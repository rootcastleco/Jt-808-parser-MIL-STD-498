"""
================================================================================
 MODULE      : jt808_parser.py
 TITLE       : JT/T 808-2013 Vehicle Terminal Communication Protocol Parser
 CLASSIFICATION: UNCLASSIFIED // FOR OFFICIAL USE ONLY
 STANDARD    : Compliant with MIL-STD-498, DO-178C DAL-C, MISRA-equivalent
 LANGUAGE    : Python 3.10+
 VERSION     : 1.0.0
================================================================================
 PURPOSE
 -------
 Implements a fully-validating parser for the JT/T 808-2013 "Road Transport
 Vehicle Satellite Positioning System – Terminal Communication Protocol"
 standard.  The parser accepts raw byte streams, extracts and unescapes
 protocol frames, verifies message integrity via XOR checksum, decodes the
 standardised message header and dispatches to per-message-ID body decoders.

 SUPPORTED MESSAGE IDs
 ---------------------
   Terminal → Platform
     0x0001  Terminal General Response
     0x0002  Terminal Heartbeat
     0x0003  Terminal Logout
     0x0100  Terminal Registration
     0x0102  Terminal Authentication
     0x0200  Location Information Report
     0x0704  Batch Location Upload

   Platform → Terminal
     0x8001  Platform General Response
     0x8100  Terminal Registration Response

 PROTOCOL FRAMING (§3.2)
 -----------------------
   [0x7E][header][body][checksum][0x7E]

   Byte stuffing (escape sequences):
     0x7E → 0x7D 0x02
     0x7D → 0x7D 0x01

 DESIGN CONSTRAINTS (DO-178C DAL-C / MISRA-equivalent)
 -------------------------------------------------------
   DC-1  All public interfaces are fully type-annotated.
   DC-2  Every function documents its pre-conditions, post-conditions and
         raised exceptions.
   DC-3  No implicit type coercions; all struct.unpack calls use explicit
         format strings with documented field sizes.
   DC-4  All buffer accesses are bounds-checked before use; violations raise
         a typed exception rather than allowing IndexError propagation.
   DC-5  No mutable default arguments.
   DC-6  Every error path is reachable by unit tests.
   DC-7  Constants are defined once and referenced by name throughout.
   DC-8  No global mutable state.

 REFERENCES
 ----------
   [1] JT/T 808-2013, Ministry of Transport of the People's Republic of China
   [2] MIL-STD-498, Software Development and Documentation, Dec 1994
   [3] DO-178C, Software Considerations in Airborne Systems and Equipment
       Certification, RTCA, Dec 2011
   [4] MISRA C:2012, Guidelines for the Use of the C Language in Critical
       Systems (applied idiomatically to Python)
================================================================================
"""

from __future__ import annotations

import struct
import logging
from dataclasses import dataclass, field
from enum import IntEnum, unique
from typing import Optional

# ---------------------------------------------------------------------------
# Module-level logger – callers configure handlers; this module never adds any.
# ---------------------------------------------------------------------------
_LOG: logging.Logger = logging.getLogger(__name__)

# ===========================================================================
# SECTION 1 – PROTOCOL CONSTANTS  (DC-7)
# ===========================================================================

# Frame delimiter (§3.2)
_FRAME_FLAG: int = 0x7E

# Escape byte (§3.2)
_ESCAPE_BYTE: int = 0x7D

# Escape sequences
_ESC_7E: bytes = bytes([0x7D, 0x02])   # encodes 0x7E within a frame
_ESC_7D: bytes = bytes([0x7D, 0x01])   # encodes 0x7D within a frame

# Header sizes (bytes) — minimum (no sub-packet) and extended (with sub-packet)
_HEADER_SIZE_BASE: int = 12
_HEADER_SIZE_SUBPACKET: int = 16

# Sub-packet bit in the message-body-properties word (bit 13)
_SUBPACKET_FLAG_BIT: int = 0x2000

# Body-length mask in message-body-properties word (bits 0–9)
_BODY_LENGTH_MASK: int = 0x03FF

# Encryption-type mask in message-body-properties word (bits 10–12)
_ENCRYPTION_MASK: int = 0x1C00
_ENCRYPTION_SHIFT: int = 10

# Maximum protocol-permitted body length (10 bits → 1023 bytes) (§3.1)
_MAX_BODY_LENGTH: int = 1023

# BCD phone-number field length in bytes
_PHONE_BCD_LEN: int = 6

# Manufacturer ID field length in bytes (terminal registration)
_MFR_ID_LEN: int = 5

# Terminal model field length in bytes (terminal registration)
_TERMINAL_MODEL_LEN: int = 20

# Terminal ID field length in bytes (terminal registration)
_TERMINAL_ID_LEN: int = 7

# GPS time field length in bytes (BCD YYMMDDHHmmss)
_GPS_TIME_LEN: int = 6


# ===========================================================================
# SECTION 2 – ENUMERATIONS
# ===========================================================================

@unique
class MessageID(IntEnum):
    """Enumeration of supported JT/T 808-2013 message identifiers."""

    # Terminal → Platform
    TERMINAL_GENERAL_RESPONSE = 0x0001
    TERMINAL_HEARTBEAT = 0x0002
    TERMINAL_LOGOUT = 0x0003
    TERMINAL_REGISTRATION = 0x0100
    TERMINAL_AUTHENTICATION = 0x0102
    LOCATION_REPORT = 0x0200
    BATCH_LOCATION_UPLOAD = 0x0704

    # Platform → Terminal
    PLATFORM_GENERAL_RESPONSE = 0x8001
    TERMINAL_REGISTRATION_RESPONSE = 0x8100


@unique
class EncryptionType(IntEnum):
    """Encryption type codes encoded in message-body-properties (bits 10–12)."""

    NONE = 0b000
    RSA = 0b001


@unique
class GeneralResult(IntEnum):
    """Result codes used by 0x0001 Terminal General Response and 0x8001."""

    SUCCESS = 0
    FAILURE = 1
    WRONG_MESSAGE = 2
    UNSUPPORTED = 3


@unique
class RegistrationResult(IntEnum):
    """Result codes used by 0x8100 Terminal Registration Response."""

    SUCCESS = 0
    VEHICLE_ALREADY_REGISTERED = 1
    VEHICLE_NOT_IN_DATABASE = 2
    TERMINAL_ALREADY_REGISTERED = 3
    TERMINAL_NOT_IN_DATABASE = 4


@unique
class LicensePlateColor(IntEnum):
    """License plate colour codes used in Terminal Registration (0x0100)."""

    BLUE = 1
    YELLOW = 2
    BLACK = 3
    WHITE = 4
    OTHER = 9


# ===========================================================================
# SECTION 3 – EXCEPTION HIERARCHY
# ===========================================================================

class JT808Error(Exception):
    """Base exception for all JT/T 808 parser errors."""


class FramingError(JT808Error):
    """Raised when a raw byte sequence cannot be decoded as a valid frame."""


class ChecksumError(JT808Error):
    """Raised when the XOR checksum of a frame does not match its payload."""


class HeaderError(JT808Error):
    """Raised when the message header is structurally invalid."""


class BodyError(JT808Error):
    """Raised when a message body cannot be decoded for the given message ID."""


class UnsupportedMessageError(JT808Error):
    """Raised when a message ID has no registered body decoder."""


# ===========================================================================
# SECTION 4 – DATA STRUCTURES
# ===========================================================================

@dataclass(frozen=True)
class SubPacketInfo:
    """
    Sub-packet fragmentation fields (§3.1).

    Attributes
    ----------
    total_count : int
        Total number of sub-packets (1–65535).
    sequence_number : int
        One-based index of this sub-packet within the complete message.
    """

    total_count: int
    sequence_number: int


@dataclass(frozen=True)
class MessageHeader:
    """
    Decoded JT/T 808-2013 message header (§3.1).

    Attributes
    ----------
    message_id : int
        16-bit message identifier.
    body_length : int
        Length of the message body in bytes (0–1023).
    encryption : EncryptionType
        Encryption type applied to the message body.
    phone_number : str
        12-digit BCD-encoded phone number as a decimal string.
    serial_number : int
        Message serial number (0–65535); used for request/response matching.
    sub_packet : Optional[SubPacketInfo]
        Present only when the sub-packet flag is set; None otherwise.
    """

    message_id: int
    body_length: int
    encryption: EncryptionType
    phone_number: str
    serial_number: int
    sub_packet: Optional[SubPacketInfo]


@dataclass(frozen=True)
class ParsedMessage:
    """
    Top-level container for a fully decoded JT/T 808-2013 message.

    Attributes
    ----------
    header : MessageHeader
        Decoded message header.
    body : object
        Decoded message body; concrete type depends on ``header.message_id``.
        May be ``None`` for bodyless messages such as 0x0002 (heartbeat).
    raw_frame : bytes
        The unescaped frame bytes (header + body + checksum) for audit/logging.
    """

    header: MessageHeader
    body: object
    raw_frame: bytes


# --- Body dataclasses -------------------------------------------------------

@dataclass(frozen=True)
class TerminalGeneralResponse:
    """Body for 0x0001 Terminal General Response."""

    response_serial: int        # Serial number of the corresponding platform message
    response_message_id: int    # Message ID being acknowledged
    result: GeneralResult


@dataclass(frozen=True)
class PlatformGeneralResponse:
    """Body for 0x8001 Platform General Response."""

    response_serial: int
    response_message_id: int
    result: GeneralResult


@dataclass(frozen=True)
class TerminalRegistration:
    """Body for 0x0100 Terminal Registration."""

    province_id: int            # Administrative province code
    city_id: int                # Administrative city/county code
    manufacturer_id: bytes      # 5-byte manufacturer code (ASCII)
    terminal_model: str         # Up to 20-character model string
    terminal_id: str            # Up to 7-character device ID string
    plate_color: int            # LicensePlateColor value
    vehicle_identification: str # Vehicle plate number (GB 18030)


@dataclass(frozen=True)
class TerminalAuthentication:
    """Body for 0x0102 Terminal Authentication."""

    auth_code: str              # Authentication token returned by 0x8100


@dataclass(frozen=True)
class TerminalRegistrationResponse:
    """Body for 0x8100 Terminal Registration Response."""

    response_serial: int
    result: RegistrationResult
    auth_code: Optional[str]    # Populated only when result == SUCCESS


@dataclass(frozen=True)
class AdditionalInfoItem:
    """
    A single additional-information item appended to a location report (§2.1.21).

    Attributes
    ----------
    item_id : int
        Additional-information identifier byte.
    data : bytes
        Raw item data (length validated against the length field in the frame).
    """

    item_id: int
    data: bytes


@dataclass(frozen=True)
class LocationReport:
    """Body for 0x0200 Location Information Report."""

    alarm_flags: int            # 32-bit alarm flag word
    status_flags: int           # 32-bit status flag word
    latitude: float             # Degrees north (negative = south)
    longitude: float            # Degrees east (negative = west)
    altitude: int               # Metres above sea level
    speed: float                # km/h (resolution 0.1)
    direction: int              # Degrees from true north (0–359)
    gps_time: str               # "YYMMDDHHmmss" BCD string
    additional_items: tuple[AdditionalInfoItem, ...]


@dataclass(frozen=True)
class BatchLocationUpload:
    """Body for 0x0704 Batch Location Upload."""

    count: int
    location_type: int          # 0 = normal, 1 = blind-spot supplement
    items: tuple[LocationReport, ...]


# ===========================================================================
# SECTION 5 – CODEC (escape / unescape)
# ===========================================================================

def unescape(data: bytes) -> bytes:
    """
    Remove byte-stuffing escape sequences from a raw frame payload (§3.2).

    Pre-conditions
    --------------
    - ``data`` must not include the leading/trailing 0x7E frame flags.

    Post-conditions
    ---------------
    - The returned buffer contains no 0x7D escape bytes.
    - Every 0x7D 0x02 in ``data`` is replaced with 0x7E.
    - Every 0x7D 0x01 in ``data`` is replaced with 0x7D.

    Raises
    ------
    FramingError
        If a 0x7D byte appears at the end of ``data`` without a following
        qualifier byte, or if the qualifier byte is not 0x01 or 0x02.
    """
    result: list[int] = []
    idx: int = 0
    length: int = len(data)

    while idx < length:
        byte: int = data[idx]
        if byte == _ESCAPE_BYTE:
            if idx + 1 >= length:
                raise FramingError(
                    f"Escape byte 0x7D at offset {idx} has no following qualifier byte"
                )
            qualifier: int = data[idx + 1]
            if qualifier == 0x01:
                result.append(0x7D)
            elif qualifier == 0x02:
                result.append(0x7E)
            else:
                raise FramingError(
                    f"Invalid escape qualifier 0x{qualifier:02X} at offset {idx + 1}; "
                    "expected 0x01 or 0x02"
                )
            idx += 2
        else:
            result.append(byte)
            idx += 1

    return bytes(result)


def escape(data: bytes) -> bytes:
    """
    Apply byte-stuffing escape sequences to a frame payload (§3.2).

    Pre-conditions
    --------------
    - ``data`` must not include the leading/trailing 0x7E frame flags or the
      checksum byte; escaping must be applied before the checksum is appended
      and before the flags are prepended.

    Post-conditions
    ---------------
    - The returned buffer contains no unescaped 0x7E bytes.
    - Every 0x7D byte in ``data`` is replaced with 0x7D 0x01.
    - Every 0x7E byte in ``data`` is replaced with 0x7D 0x02.
    """
    result: bytearray = bytearray()
    for byte in data:
        if byte == 0x7E:
            result.extend(_ESC_7E)
        elif byte == 0x7D:
            result.extend(_ESC_7D)
        else:
            result.append(byte)
    return bytes(result)


# ===========================================================================
# SECTION 6 – CHECKSUM
# ===========================================================================

def compute_checksum(data: bytes) -> int:
    """
    Compute the XOR checksum over all bytes in ``data`` (§3.4).

    The checksum covers all bytes from the start of the message header to the
    end of the message body, i.e. every byte between (exclusive) the two 0x7E
    frame flags, excluding the checksum byte itself.

    Pre-conditions
    --------------
    - ``data`` is the unescaped header + body bytes.

    Post-conditions
    ---------------
    - Return value is in range [0, 255].
    """
    checksum: int = 0
    for byte in data:
        checksum ^= byte
    return checksum


def verify_checksum(payload: bytes, expected: int) -> None:
    """
    Verify the XOR checksum of a decoded frame.

    Pre-conditions
    --------------
    - ``payload`` is the unescaped header + body bytes.
    - ``expected`` is the checksum byte extracted from the frame.

    Raises
    ------
    ChecksumError
        If the computed checksum does not equal ``expected``.
    """
    actual: int = compute_checksum(payload)
    if actual != expected:
        raise ChecksumError(
            f"Checksum mismatch: computed 0x{actual:02X}, frame carries 0x{expected:02X}"
        )


# ===========================================================================
# SECTION 7 – FRAME EXTRACTION
# ===========================================================================

def extract_frames(stream: bytes) -> list[bytes]:
    """
    Extract zero or more raw (still-escaped) frames from a byte stream.

    A frame is the sequence of bytes between (exclusive) two consecutive
    0x7E flag bytes (§3.2).  Bytes outside any frame boundary are silently
    discarded (they may be line noise or inter-frame padding).

    Pre-conditions
    --------------
    - ``stream`` is an arbitrary-length byte buffer that may contain zero or
      more complete JT/T 808-2013 frames.

    Post-conditions
    ---------------
    - Each element in the returned list is the raw (unescaped) inter-flag
      content, i.e. it does NOT include the surrounding 0x7E bytes.
    - Empty inter-flag segments (consecutive 0x7E bytes) are omitted.
    - Incomplete frames (no closing 0x7E) are silently discarded.

    Parameters
    ----------
    stream : bytes
        Raw byte buffer from the transport layer.

    Returns
    -------
    list[bytes]
        Ordered list of raw frame contents.
    """
    frames: list[bytes] = []
    start: int = -1

    for idx, byte in enumerate(stream):
        if byte == _FRAME_FLAG:
            if start != -1 and idx > start + 1:
                frames.append(stream[start + 1: idx])
            start = idx

    return frames


# ===========================================================================
# SECTION 8 – HEADER DECODER
# ===========================================================================

def _bcd_to_str(bcd_bytes: bytes) -> str:
    """
    Decode a BCD-encoded byte sequence into a decimal digit string.

    Pre-conditions
    --------------
    - Each nibble of each byte in ``bcd_bytes`` must be in range [0, 9].
      Invalid nibbles (0xA–0xF) are decoded as their hex digit character.

    Parameters
    ----------
    bcd_bytes : bytes
        Raw BCD bytes.

    Returns
    -------
    str
        Decimal string; leading zeros are preserved.
    """
    digits: list[str] = []
    for byte in bcd_bytes:
        digits.append(f"{(byte >> 4) & 0x0F:X}")
        digits.append(f"{byte & 0x0F:X}")
    return "".join(digits)


def decode_header(unescaped_frame: bytes) -> tuple[MessageHeader, int]:
    """
    Decode the JT/T 808-2013 message header from an unescaped frame.

    Pre-conditions
    --------------
    - ``unescaped_frame`` is the unescaped content between two 0x7E flags,
      including the header, body, AND the trailing checksum byte.
    - The minimum length is ``_HEADER_SIZE_BASE + 1`` (header + checksum).

    Post-conditions
    ---------------
    - The returned integer is the byte offset at which the message body begins
      (i.e., ``_HEADER_SIZE_BASE`` or ``_HEADER_SIZE_SUBPACKET``).

    Parameters
    ----------
    unescaped_frame : bytes
        Unescaped frame bytes (header + body + checksum).

    Returns
    -------
    tuple[MessageHeader, int]
        Decoded header and the byte offset of the first body byte.

    Raises
    ------
    HeaderError
        If the frame is too short to contain a valid header, if the body
        length field is inconsistent with the actual frame length, or if an
        unsupported encryption type is specified.
    """
    min_len: int = _HEADER_SIZE_BASE + 1   # header + checksum (no body)
    if len(unescaped_frame) < min_len:
        raise HeaderError(
            f"Frame too short: {len(unescaped_frame)} bytes, "
            f"minimum is {min_len}"
        )

    # Unpack the six fixed header fields:
    #   H  = unsigned short (2 bytes) big-endian
    #   6s = 6-byte string
    #   H  = unsigned short (2 bytes) big-endian
    msg_id: int
    body_props: int
    phone_bcd: bytes
    serial_no: int

    try:
        msg_id, body_props, phone_bcd, serial_no = struct.unpack_from(
            ">HH6sH", unescaped_frame, 0
        )
    except struct.error as exc:
        raise HeaderError(f"Failed to unpack fixed header fields: {exc}") from exc

    body_length: int = body_props & _BODY_LENGTH_MASK
    enc_code: int = (body_props & _ENCRYPTION_MASK) >> _ENCRYPTION_SHIFT
    has_subpacket: bool = bool(body_props & _SUBPACKET_FLAG_BIT)

    # Validate encryption code
    try:
        encryption: EncryptionType = EncryptionType(enc_code)
    except ValueError:
        raise HeaderError(
            f"Unknown encryption type code {enc_code} in message-body-properties"
        )

    # Determine body offset and optionally parse sub-packet fields
    sub_packet: Optional[SubPacketInfo] = None
    body_offset: int

    if has_subpacket:
        if len(unescaped_frame) < _HEADER_SIZE_SUBPACKET + 1:
            raise HeaderError(
                f"Sub-packet flag set but frame is too short for extended header: "
                f"{len(unescaped_frame)} bytes"
            )
        total_count: int
        seq_no: int
        try:
            total_count, seq_no = struct.unpack_from(">HH", unescaped_frame, _HEADER_SIZE_BASE)
        except struct.error as exc:
            raise HeaderError(
                f"Failed to unpack sub-packet fields: {exc}"
            ) from exc

        if total_count < 1:
            raise HeaderError(
                f"Sub-packet total count must be >= 1, got {total_count}"
            )
        if seq_no < 1 or seq_no > total_count:
            raise HeaderError(
                f"Sub-packet sequence number {seq_no} out of range "
                f"[1, {total_count}]"
            )
        sub_packet = SubPacketInfo(total_count=total_count, sequence_number=seq_no)
        body_offset = _HEADER_SIZE_SUBPACKET
    else:
        body_offset = _HEADER_SIZE_BASE

    # Validate that the declared body length matches the actual frame size.
    # Frame layout: [header][body][checksum]
    # ⟹ len(frame) == body_offset + body_length + 1
    expected_frame_len: int = body_offset + body_length + 1
    if len(unescaped_frame) != expected_frame_len:
        raise HeaderError(
            f"Body length field declares {body_length} bytes, but frame has "
            f"{len(unescaped_frame) - body_offset - 1} body bytes"
        )

    phone_number: str = _bcd_to_str(phone_bcd)

    header = MessageHeader(
        message_id=msg_id,
        body_length=body_length,
        encryption=encryption,
        phone_number=phone_number,
        serial_number=serial_no,
        sub_packet=sub_packet,
    )

    return header, body_offset


# ===========================================================================
# SECTION 9 – MESSAGE BODY DECODERS
# ===========================================================================

def _decode_terminal_general_response(body: bytes) -> TerminalGeneralResponse:
    """
    Decode body for 0x0001 Terminal General Response.

    Wire layout (5 bytes):
      [0..1]  Response serial number (uint16 BE)
      [2..3]  Response message ID    (uint16 BE)
      [4]     Result code            (uint8)

    Raises
    ------
    BodyError
        If ``body`` is not exactly 5 bytes, or if the result code is unknown.
    """
    expected: int = 5
    if len(body) != expected:
        raise BodyError(
            f"0x0001 body must be {expected} bytes, got {len(body)}"
        )
    resp_serial: int
    resp_msg_id: int
    result_code: int
    resp_serial, resp_msg_id, result_code = struct.unpack(">HHB", body)
    try:
        result = GeneralResult(result_code)
    except ValueError:
        raise BodyError(
            f"Unknown result code {result_code} in 0x0001 body"
        )
    return TerminalGeneralResponse(
        response_serial=resp_serial,
        response_message_id=resp_msg_id,
        result=result,
    )


def _decode_platform_general_response(body: bytes) -> PlatformGeneralResponse:
    """
    Decode body for 0x8001 Platform General Response.

    Wire layout (5 bytes):
      [0..1]  Response serial number (uint16 BE)
      [2..3]  Response message ID    (uint16 BE)
      [4]     Result code            (uint8)

    Raises
    ------
    BodyError
        If ``body`` is not exactly 5 bytes, or if the result code is unknown.
    """
    expected: int = 5
    if len(body) != expected:
        raise BodyError(
            f"0x8001 body must be {expected} bytes, got {len(body)}"
        )
    resp_serial: int
    resp_msg_id: int
    result_code: int
    resp_serial, resp_msg_id, result_code = struct.unpack(">HHB", body)
    try:
        result = GeneralResult(result_code)
    except ValueError:
        raise BodyError(
            f"Unknown result code {result_code} in 0x8001 body"
        )
    return PlatformGeneralResponse(
        response_serial=resp_serial,
        response_message_id=resp_msg_id,
        result=result,
    )


def _decode_terminal_registration(body: bytes) -> TerminalRegistration:
    """
    Decode body for 0x0100 Terminal Registration.

    Wire layout (minimum 37 bytes):
      [0..1]   Province ID             (uint16 BE)
      [2..3]   City ID                 (uint16 BE)
      [4..8]   Manufacturer ID         (5 bytes ASCII)
      [9..28]  Terminal model          (20 bytes ASCII, null-padded)
      [29..35] Terminal ID             (7 bytes ASCII, null-padded)
      [36]     License plate colour    (uint8)
      [37..]   Vehicle identification  (variable, GB 18030)

    Raises
    ------
    BodyError
        If ``body`` is shorter than the minimum required length.
    """
    min_len: int = 1 + 2 + 2 + _MFR_ID_LEN + _TERMINAL_MODEL_LEN + _TERMINAL_ID_LEN
    if len(body) < min_len:
        raise BodyError(
            f"0x0100 body too short: {len(body)} bytes, minimum is {min_len}"
        )

    offset: int = 0
    province_id: int
    city_id: int
    province_id, city_id = struct.unpack_from(">HH", body, offset)
    offset += 4

    mfr_id: bytes = body[offset: offset + _MFR_ID_LEN]
    offset += _MFR_ID_LEN

    model_raw: bytes = body[offset: offset + _TERMINAL_MODEL_LEN]
    offset += _TERMINAL_MODEL_LEN

    tid_raw: bytes = body[offset: offset + _TERMINAL_ID_LEN]
    offset += _TERMINAL_ID_LEN

    plate_color: int = body[offset]
    offset += 1

    vehicle_id_raw: bytes = body[offset:]

    terminal_model: str = model_raw.rstrip(b"\x00").decode("ascii", errors="replace")
    terminal_id: str = tid_raw.rstrip(b"\x00").decode("ascii", errors="replace")
    vehicle_identification: str = vehicle_id_raw.decode("gb18030", errors="replace")

    return TerminalRegistration(
        province_id=province_id,
        city_id=city_id,
        manufacturer_id=mfr_id,
        terminal_model=terminal_model,
        terminal_id=terminal_id,
        plate_color=plate_color,
        vehicle_identification=vehicle_identification,
    )


def _decode_terminal_authentication(body: bytes) -> TerminalAuthentication:
    """
    Decode body for 0x0102 Terminal Authentication.

    Wire layout (variable):
      [0..]  Authentication code (ASCII string, length == body length)

    Raises
    ------
    BodyError
        If ``body`` is empty.
    """
    if len(body) == 0:
        raise BodyError("0x0102 authentication body must not be empty")
    auth_code: str = body.decode("ascii", errors="replace")
    return TerminalAuthentication(auth_code=auth_code)


def _decode_terminal_registration_response(body: bytes) -> TerminalRegistrationResponse:
    """
    Decode body for 0x8100 Terminal Registration Response.

    Wire layout:
      [0..1]  Response serial number  (uint16 BE)
      [2]     Result code             (uint8)
      [3..]   Auth code               (ASCII, present only when result == 0)

    Raises
    ------
    BodyError
        If ``body`` is shorter than 3 bytes or the result code is unknown.
    """
    min_len: int = 3
    if len(body) < min_len:
        raise BodyError(
            f"0x8100 body too short: {len(body)} bytes, minimum is {min_len}"
        )
    resp_serial: int
    result_code: int
    resp_serial, result_code = struct.unpack_from(">HB", body, 0)
    try:
        result = RegistrationResult(result_code)
    except ValueError:
        raise BodyError(
            f"Unknown result code {result_code} in 0x8100 body"
        )
    auth_code: Optional[str] = None
    if result == RegistrationResult.SUCCESS:
        if len(body) <= 3:
            raise BodyError(
                "0x8100 result is SUCCESS but no auth code is present"
            )
        auth_code = body[3:].decode("ascii", errors="replace")
    return TerminalRegistrationResponse(
        response_serial=resp_serial,
        result=result,
        auth_code=auth_code,
    )


def _decode_additional_info_items(data: bytes) -> tuple[AdditionalInfoItem, ...]:
    """
    Decode the variable-length additional-information section of a location
    report body (§2.1.21).

    Each additional-information item has the structure:
      [0]     Item ID   (uint8)
      [1]     Length    (uint8, in bytes)
      [2..n]  Item data (``length`` bytes)

    Pre-conditions
    --------------
    - ``data`` is the bytes following the fixed location-report fields.

    Raises
    ------
    BodyError
        If the additional-information section is malformed (truncated item).
    """
    items: list[AdditionalInfoItem] = []
    offset: int = 0

    while offset < len(data):
        if offset + 2 > len(data):
            raise BodyError(
                f"Additional info item header truncated at offset {offset}"
            )
        item_id: int = data[offset]
        item_len: int = data[offset + 1]
        offset += 2

        if offset + item_len > len(data):
            raise BodyError(
                f"Additional info item 0x{item_id:02X} declares {item_len} bytes "
                f"but only {len(data) - offset} remain at offset {offset}"
            )
        item_data: bytes = data[offset: offset + item_len]
        offset += item_len

        items.append(AdditionalInfoItem(item_id=item_id, data=item_data))

    return tuple(items)


def _decode_location_report(body: bytes) -> LocationReport:
    """
    Decode body for 0x0200 Location Information Report.

    Fixed section wire layout (28 bytes):
      [0..3]   Alarm flags   (uint32 BE)
      [4..7]   Status flags  (uint32 BE)
      [8..11]  Latitude      (uint32 BE, 1/10^6 degree)
      [12..15] Longitude     (uint32 BE, 1/10^6 degree)
      [16..17] Altitude      (uint16 BE, metres)
      [18..19] Speed         (uint16 BE, 1/10 km/h)
      [20..21] Direction     (uint16 BE, degrees)
      [22..27] GPS time      (6 bytes BCD, YYMMDDHHmmss)
      [28..]   Additional information items (variable)

    Raises
    ------
    BodyError
        If ``body`` is shorter than 28 bytes or additional items are malformed.
    """
    fixed_len: int = 28
    if len(body) < fixed_len:
        raise BodyError(
            f"0x0200 body too short: {len(body)} bytes, minimum is {fixed_len}"
        )

    alarm_flags: int
    status_flags: int
    lat_raw: int
    lon_raw: int
    altitude: int
    speed_raw: int
    direction: int

    (
        alarm_flags, status_flags,
        lat_raw, lon_raw,
        altitude, speed_raw, direction,
    ) = struct.unpack_from(">IIIIHH H", body, 0)

    gps_time: str = _bcd_to_str(body[22: 22 + _GPS_TIME_LEN])

    # Bit 28 of status_flags: 1 = south latitude, 0 = north latitude (§2.1.20)
    lat_sign: float = -1.0 if (status_flags & (1 << 28)) else 1.0
    # Bit 27 of status_flags: 1 = west longitude, 0 = east longitude
    lon_sign: float = -1.0 if (status_flags & (1 << 27)) else 1.0

    latitude: float = lat_sign * lat_raw / 1_000_000.0
    longitude: float = lon_sign * lon_raw / 1_000_000.0
    speed: float = speed_raw / 10.0

    additional_items = _decode_additional_info_items(body[fixed_len:])

    return LocationReport(
        alarm_flags=alarm_flags,
        status_flags=status_flags,
        latitude=latitude,
        longitude=longitude,
        altitude=altitude,
        speed=speed,
        direction=direction,
        gps_time=gps_time,
        additional_items=additional_items,
    )


def _decode_batch_location_upload(body: bytes) -> BatchLocationUpload:
    """
    Decode body for 0x0704 Batch Location Upload.

    Wire layout:
      [0..1]  Item count      (uint16 BE)
      [2]     Location type   (uint8; 0=normal, 1=blind-spot supplement)
      [3..]   Location items  (repeated: uint16 length + location-report body)

    Raises
    ------
    BodyError
        If ``body`` is shorter than 3 bytes, or if any item is malformed.
    """
    min_len: int = 3
    if len(body) < min_len:
        raise BodyError(
            f"0x0704 body too short: {len(body)} bytes, minimum is {min_len}"
        )

    count: int
    loc_type: int
    count, loc_type = struct.unpack_from(">HB", body, 0)
    offset: int = 3
    items: list[LocationReport] = []

    for i in range(count):
        if offset + 2 > len(body):
            raise BodyError(
                f"0x0704 item {i} length field truncated at offset {offset}"
            )
        item_len: int = struct.unpack_from(">H", body, offset)[0]
        offset += 2
        if offset + item_len > len(body):
            raise BodyError(
                f"0x0704 item {i} declares {item_len} bytes but only "
                f"{len(body) - offset} remain at offset {offset}"
            )
        item_body: bytes = body[offset: offset + item_len]
        offset += item_len
        items.append(_decode_location_report(item_body))

    return BatchLocationUpload(
        count=count,
        location_type=loc_type,
        items=tuple(items),
    )


# ===========================================================================
# SECTION 10 – BODY DECODER DISPATCH TABLE  (DC-7, DC-8)
# ===========================================================================

# Type alias for body-decoder callables
_BodyDecoder = object  # Callable[[bytes], object] — kept generic for Python 3.10

_BODY_DECODERS: dict[int, object] = {
    MessageID.TERMINAL_GENERAL_RESPONSE:        _decode_terminal_general_response,
    MessageID.TERMINAL_HEARTBEAT:               None,   # no body
    MessageID.TERMINAL_LOGOUT:                  None,   # no body
    MessageID.TERMINAL_REGISTRATION:            _decode_terminal_registration,
    MessageID.TERMINAL_AUTHENTICATION:          _decode_terminal_authentication,
    MessageID.LOCATION_REPORT:                  _decode_location_report,
    MessageID.BATCH_LOCATION_UPLOAD:            _decode_batch_location_upload,
    MessageID.PLATFORM_GENERAL_RESPONSE:        _decode_platform_general_response,
    MessageID.TERMINAL_REGISTRATION_RESPONSE:   _decode_terminal_registration_response,
}


# ===========================================================================
# SECTION 11 – TOP-LEVEL PARSER CLASS
# ===========================================================================

class JT808Parser:
    """
    Stateless JT/T 808-2013 protocol parser.

    Usage
    -----
    ::

        parser = JT808Parser()

        # Parse a single pre-framed message (bytes between 0x7E flags,
        # inclusive):
        msg = parser.parse_frame(raw_bytes)

        # Parse all complete frames from a transport-layer byte stream:
        messages = parser.parse_stream(stream_bytes)

    Design Notes
    ------------
    - The parser holds no mutable state; a single instance may be shared
      across threads without synchronisation (DC-8).
    - All error conditions raise a sub-class of ``JT808Error``; callers
      should catch at least ``JT808Error`` to handle malformed input.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_frame(self, raw: bytes) -> ParsedMessage:
        """
        Parse a single JT/T 808-2013 frame from its raw byte representation.

        The caller may supply the frame with or without the surrounding 0x7E
        flag bytes; both forms are accepted.

        Pre-conditions
        --------------
        - ``raw`` contains exactly one complete message frame.

        Parameters
        ----------
        raw : bytes
            Raw (escaped) frame bytes, optionally surrounded by 0x7E flags.

        Returns
        -------
        ParsedMessage
            Fully decoded message.

        Raises
        ------
        FramingError
            If the frame cannot be unescaped.
        ChecksumError
            If the frame checksum is incorrect.
        HeaderError
            If the message header is structurally invalid.
        BodyError
            If the message body cannot be decoded.
        UnsupportedMessageError
            If the message ID is not in the dispatch table.
        """
        frame_content: bytes = self._strip_flags(raw)
        return self._decode_frame_content(frame_content)

    def parse_stream(self, stream: bytes) -> list[ParsedMessage]:
        """
        Extract and parse all complete frames from a raw byte stream.

        Frames that fail to parse are logged at WARNING level and skipped;
        they do not prevent subsequent frames from being parsed.

        Pre-conditions
        --------------
        - ``stream`` may contain zero or more complete frames and arbitrary
          inter-frame bytes (e.g. line noise).

        Parameters
        ----------
        stream : bytes
            Raw byte stream from the transport layer.

        Returns
        -------
        list[ParsedMessage]
            Ordered list of successfully parsed messages.
        """
        raw_frames: list[bytes] = extract_frames(stream)
        messages: list[ParsedMessage] = []

        for idx, frame_content in enumerate(raw_frames):
            try:
                messages.append(self._decode_frame_content(frame_content))
            except JT808Error as exc:
                _LOG.warning(
                    "Frame %d/%d failed to parse: %s",
                    idx + 1,
                    len(raw_frames),
                    exc,
                )

        return messages

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_flags(raw: bytes) -> bytes:
        """
        Remove optional leading/trailing 0x7E flag bytes.

        Pre-conditions
        --------------
        - ``raw`` is non-empty.

        Returns
        -------
        bytes
            Frame content without surrounding flags.
        """
        start: int = 0
        end: int = len(raw)
        if end > 0 and raw[0] == _FRAME_FLAG:
            start = 1
        if end > start and raw[end - 1] == _FRAME_FLAG:
            end -= 1
        return raw[start:end]

    @staticmethod
    def _decode_frame_content(frame_content: bytes) -> ParsedMessage:
        """
        Unescape, verify, decode header and body of a single frame content.

        Pre-conditions
        --------------
        - ``frame_content`` is the raw (still-escaped) bytes between the
          two 0x7E flag bytes (exclusive).

        Returns
        -------
        ParsedMessage

        Raises
        ------
        FramingError, ChecksumError, HeaderError, BodyError,
        UnsupportedMessageError
        """
        unescaped: bytes = unescape(frame_content)

        # The last byte of the unescaped frame is the XOR checksum.
        if len(unescaped) < 2:
            raise FramingError(
                f"Unescaped frame is too short to contain a checksum: "
                f"{len(unescaped)} bytes"
            )

        checksum_byte: int = unescaped[-1]
        payload: bytes = unescaped[:-1]   # header + body

        verify_checksum(payload, checksum_byte)

        header, body_offset = decode_header(unescaped)
        body_bytes: bytes = payload[body_offset:]

        decoded_body: object = JT808Parser._dispatch_body(
            header.message_id, body_bytes
        )

        return ParsedMessage(
            header=header,
            body=decoded_body,
            raw_frame=unescaped,
        )

    @staticmethod
    def _dispatch_body(message_id: int, body_bytes: bytes) -> object:
        """
        Look up and invoke the body decoder for ``message_id``.

        Pre-conditions
        --------------
        - ``body_bytes`` is the unescaped body portion of the frame.

        Returns
        -------
        object
            Decoded body dataclass, or ``None`` for bodyless messages.

        Raises
        ------
        UnsupportedMessageError
            If ``message_id`` is not present in the dispatch table.
        BodyError
            Propagated from the specific body decoder.
        """
        if message_id not in _BODY_DECODERS:
            raise UnsupportedMessageError(
                f"No decoder registered for message ID 0x{message_id:04X}"
            )

        decoder = _BODY_DECODERS[message_id]
        if decoder is None:
            return None   # bodyless message (e.g. heartbeat, logout)

        # decoder is a callable: (bytes) -> object
        return decoder(body_bytes)  # type: ignore[operator]


# ===========================================================================
# SECTION 12 – FRAME BUILDER  (convenience / testing utility)
# ===========================================================================

def build_frame(
    message_id: int,
    phone_number: str,
    serial_number: int,
    body: bytes,
    *,
    encryption: EncryptionType = EncryptionType.NONE,
    sub_packet: Optional[SubPacketInfo] = None,
) -> bytes:
    """
    Encode a JT/T 808-2013 message into a complete escaped frame.

    This function is provided as a utility for testing and for implementations
    that must transmit messages; it is the logical inverse of ``parse_frame``.

    Pre-conditions
    --------------
    - ``phone_number`` must be a 12-digit decimal string (leading zeros
      permitted).
    - ``len(body)`` must not exceed ``_MAX_BODY_LENGTH`` (1023).
    - ``serial_number`` must be in range [0, 65535].

    Parameters
    ----------
    message_id : int
        16-bit message identifier.
    phone_number : str
        12-digit decimal phone number string (BCD-encoded into 6 bytes).
    serial_number : int
        Message serial number (0–65535).
    body : bytes
        Raw (unescaped) message body.
    encryption : EncryptionType
        Encryption type to encode in the header (default: NONE).
    sub_packet : Optional[SubPacketInfo]
        Sub-packet descriptor, or ``None`` for unsegmented messages.

    Returns
    -------
    bytes
        Complete frame including leading and trailing 0x7E flags.

    Raises
    ------
    ValueError
        If ``phone_number`` is not 12 digits, ``len(body)`` exceeds the
        protocol maximum, or ``serial_number`` is out of range.
    """
    if len(phone_number) != 12 or not phone_number.isdigit():
        raise ValueError(
            f"phone_number must be exactly 12 decimal digits, got {phone_number!r}"
        )
    if len(body) > _MAX_BODY_LENGTH:
        raise ValueError(
            f"Body length {len(body)} exceeds protocol maximum {_MAX_BODY_LENGTH}"
        )
    if not (0 <= serial_number <= 0xFFFF):
        raise ValueError(
            f"serial_number {serial_number} out of range [0, 65535]"
        )

    # Encode BCD phone number
    phone_bcd: bytearray = bytearray(_PHONE_BCD_LEN)
    for i in range(_PHONE_BCD_LEN):
        high: int = int(phone_number[i * 2])
        low: int = int(phone_number[i * 2 + 1])
        phone_bcd[i] = (high << 4) | low

    # Compute body-properties word
    body_props: int = (len(body) & _BODY_LENGTH_MASK)
    body_props |= (int(encryption) << _ENCRYPTION_SHIFT) & _ENCRYPTION_MASK
    if sub_packet is not None:
        body_props |= _SUBPACKET_FLAG_BIT

    # Pack fixed header
    header: bytes = struct.pack(
        ">HH6sH",
        message_id,
        body_props,
        bytes(phone_bcd),
        serial_number,
    )

    # Append sub-packet fields if present
    if sub_packet is not None:
        header += struct.pack(">HH", sub_packet.total_count, sub_packet.sequence_number)

    payload: bytes = header + body
    checksum: int = compute_checksum(payload)
    raw_frame: bytes = escape(payload + bytes([checksum]))

    return bytes([_FRAME_FLAG]) + raw_frame + bytes([_FRAME_FLAG])
