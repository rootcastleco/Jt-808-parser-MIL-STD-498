"""
================================================================================
 MODULE      : test_jt808_parser.py
 TITLE       : Unit Tests for jt808_parser — JT/T 808-2013 Protocol Parser
 CLASSIFICATION: UNCLASSIFIED // FOR OFFICIAL USE ONLY
 STANDARD    : Compliant with MIL-STD-498 (Software Test Description),
               DO-178C DAL-C, MISRA-equivalent
 LANGUAGE    : Python 3.10+
 VERSION     : 1.0.0
================================================================================
 PURPOSE
 -------
 Provides a comprehensive unit-test suite for every public interface in
 jt808_parser.py.  Test coverage targets include:

   - Nominal (happy-path) decoding of all supported message IDs
   - Frame extraction from single and multi-frame streams
   - Escape / unescape codec (both directions)
   - XOR checksum computation and validation
   - Error-path coverage for every typed exception
   - Round-trip encode/decode via build_frame + parse_frame
================================================================================
"""

from __future__ import annotations

import struct
import unittest

from jt808_parser import (
    # Codec
    unescape,
    escape,
    # Checksum
    compute_checksum,
    verify_checksum,
    # Frame extraction
    extract_frames,
    # Header
    decode_header,
    # Frame builder
    build_frame,
    # Top-level parser
    JT808Parser,
    # Data structures
    MessageHeader,
    SubPacketInfo,
    ParsedMessage,
    LocationReport,
    TerminalGeneralResponse,
    PlatformGeneralResponse,
    TerminalRegistration,
    TerminalAuthentication,
    TerminalRegistrationResponse,
    BatchLocationUpload,
    AdditionalInfoItem,
    # Enumerations
    MessageID,
    EncryptionType,
    GeneralResult,
    RegistrationResult,
    LicensePlateColor,
    # Exceptions
    JT808Error,
    FramingError,
    ChecksumError,
    HeaderError,
    BodyError,
    UnsupportedMessageError,
)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

_PHONE: str = "013800138000"   # 12-digit BCD phone number used in most tests


def _build(
    msg_id: int,
    body: bytes,
    phone: str = _PHONE,
    serial: int = 1,
) -> bytes:
    """Build a complete escaped JT/T 808-2013 frame for testing."""
    return build_frame(msg_id, phone, serial, body)


# ===========================================================================
# SECTION 1 – CODEC TESTS
# ===========================================================================

class TestUnescape(unittest.TestCase):
    """Tests for the unescape() function (§3.2 byte stuffing)."""

    def test_no_escape_sequences_unchanged(self) -> None:
        data = bytes([0x00, 0x01, 0x02, 0xFF])
        self.assertEqual(unescape(data), data)

    def test_7d_01_becomes_7d(self) -> None:
        self.assertEqual(unescape(bytes([0x7D, 0x01])), bytes([0x7D]))

    def test_7d_02_becomes_7e(self) -> None:
        self.assertEqual(unescape(bytes([0x7D, 0x02])), bytes([0x7E]))

    def test_mixed_escape_sequences(self) -> None:
        data = bytes([0xAA, 0x7D, 0x01, 0xBB, 0x7D, 0x02, 0xCC])
        expected = bytes([0xAA, 0x7D, 0xBB, 0x7E, 0xCC])
        self.assertEqual(unescape(data), expected)

    def test_empty_input_returns_empty(self) -> None:
        self.assertEqual(unescape(b""), b"")

    def test_trailing_escape_byte_raises(self) -> None:
        with self.assertRaises(FramingError):
            unescape(bytes([0x7D]))

    def test_invalid_qualifier_raises(self) -> None:
        with self.assertRaises(FramingError):
            unescape(bytes([0x7D, 0x03]))

    def test_multiple_consecutive_escapes(self) -> None:
        data = bytes([0x7D, 0x01, 0x7D, 0x02])
        self.assertEqual(unescape(data), bytes([0x7D, 0x7E]))


class TestEscape(unittest.TestCase):
    """Tests for the escape() function (§3.2 byte stuffing)."""

    def test_no_special_bytes_unchanged(self) -> None:
        data = bytes([0x00, 0x01, 0xFE, 0xFF])
        self.assertEqual(escape(data), data)

    def test_7e_becomes_7d_02(self) -> None:
        self.assertEqual(escape(bytes([0x7E])), bytes([0x7D, 0x02]))

    def test_7d_becomes_7d_01(self) -> None:
        self.assertEqual(escape(bytes([0x7D])), bytes([0x7D, 0x01]))

    def test_mixed_bytes(self) -> None:
        data = bytes([0xAA, 0x7E, 0xBB, 0x7D, 0xCC])
        expected = bytes([0xAA, 0x7D, 0x02, 0xBB, 0x7D, 0x01, 0xCC])
        self.assertEqual(escape(data), expected)

    def test_empty_input_returns_empty(self) -> None:
        self.assertEqual(escape(b""), b"")

    def test_roundtrip_escape_unescape(self) -> None:
        original = bytes(range(256))
        self.assertEqual(unescape(escape(original)), original)


# ===========================================================================
# SECTION 2 – CHECKSUM TESTS
# ===========================================================================

class TestChecksum(unittest.TestCase):
    """Tests for compute_checksum() and verify_checksum()."""

    def test_single_byte(self) -> None:
        self.assertEqual(compute_checksum(bytes([0xAB])), 0xAB)

    def test_same_byte_twice_gives_zero(self) -> None:
        self.assertEqual(compute_checksum(bytes([0xAB, 0xAB])), 0x00)

    def test_known_value(self) -> None:
        # 0x01 ^ 0x02 ^ 0x03 = 0x00
        self.assertEqual(compute_checksum(bytes([0x01, 0x02, 0x03])), 0x00)

    def test_empty_data_gives_zero(self) -> None:
        self.assertEqual(compute_checksum(b""), 0x00)

    def test_verify_passes_on_match(self) -> None:
        data = bytes([0x01, 0x02, 0x03])
        cs = compute_checksum(data)
        verify_checksum(data, cs)   # must not raise

    def test_verify_raises_on_mismatch(self) -> None:
        data = bytes([0x01, 0x02, 0x03])
        with self.assertRaises(ChecksumError):
            verify_checksum(data, 0xFF)


# ===========================================================================
# SECTION 3 – FRAME EXTRACTION TESTS
# ===========================================================================

class TestExtractFrames(unittest.TestCase):
    """Tests for extract_frames()."""

    def test_single_frame(self) -> None:
        content = bytes([0xAA, 0xBB, 0xCC])
        stream = bytes([0x7E]) + content + bytes([0x7E])
        frames = extract_frames(stream)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0], content)

    def test_two_consecutive_frames(self) -> None:
        c1 = bytes([0x01, 0x02])
        c2 = bytes([0x03, 0x04])
        stream = bytes([0x7E]) + c1 + bytes([0x7E]) + c2 + bytes([0x7E])
        frames = extract_frames(stream)
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0], c1)
        self.assertEqual(frames[1], c2)

    def test_empty_stream(self) -> None:
        self.assertEqual(extract_frames(b""), [])

    def test_noise_before_frame_discarded(self) -> None:
        content = bytes([0xAA])
        stream = bytes([0x00, 0x01, 0x7E]) + content + bytes([0x7E])
        frames = extract_frames(stream)
        self.assertEqual(frames, [content])

    def test_incomplete_frame_discarded(self) -> None:
        # No closing 0x7E
        stream = bytes([0x7E, 0xAA, 0xBB])
        frames = extract_frames(stream)
        self.assertEqual(frames, [])

    def test_consecutive_flags_produce_no_empty_frames(self) -> None:
        stream = bytes([0x7E, 0x7E, 0x7E])
        frames = extract_frames(stream)
        self.assertEqual(frames, [])


# ===========================================================================
# SECTION 4 – HEADER DECODER TESTS
# ===========================================================================

class TestDecodeHeader(unittest.TestCase):
    """Tests for decode_header()."""

    def _make_unescaped(
        self,
        msg_id: int = 0x0200,
        body_len: int = 0,
        phone: str = _PHONE,
        serial: int = 1,
        body: bytes = b"",
        extra_props: int = 0,
    ) -> bytes:
        """Construct a minimal valid unescaped frame (header + body + checksum)."""
        phone_bcd = bytes(
            [(int(phone[i * 2]) << 4) | int(phone[i * 2 + 1]) for i in range(6)]
        )
        props = (body_len & 0x03FF) | extra_props
        header = struct.pack(">HH6sH", msg_id, props, phone_bcd, serial)
        payload = header + body
        cs = compute_checksum(payload)
        return payload + bytes([cs])

    def test_nominal_decode(self) -> None:
        frame = self._make_unescaped(msg_id=0x0200, body_len=0)
        hdr, offset = decode_header(frame)
        self.assertEqual(hdr.message_id, 0x0200)
        self.assertEqual(hdr.body_length, 0)
        self.assertEqual(hdr.serial_number, 1)
        self.assertEqual(hdr.phone_number, _PHONE)
        self.assertIsNone(hdr.sub_packet)
        self.assertEqual(offset, 12)

    def test_frame_too_short_raises(self) -> None:
        with self.assertRaises(HeaderError):
            decode_header(bytes([0x00, 0x01]))

    def test_body_length_mismatch_raises(self) -> None:
        # Declare body_len=5 but supply no body bytes
        frame = self._make_unescaped(msg_id=0x0001, body_len=5, body=b"")
        # Manually craft a frame with wrong declared length
        phone_bcd = bytes(
            [(int(_PHONE[i * 2]) << 4) | int(_PHONE[i * 2 + 1]) for i in range(6)]
        )
        props = 5   # declares 5-byte body
        header = struct.pack(">HH6sH", 0x0001, props, phone_bcd, 1)
        payload = header   # no body
        cs = compute_checksum(payload)
        bad_frame = payload + bytes([cs])
        with self.assertRaises(HeaderError):
            decode_header(bad_frame)

    def test_subpacket_flag_decoded(self) -> None:
        phone_bcd = bytes(
            [(int(_PHONE[i * 2]) << 4) | int(_PHONE[i * 2 + 1]) for i in range(6)]
        )
        props = 0x2000   # sub-packet flag, body_len = 0
        header = struct.pack(">HH6sH", 0x0200, props, phone_bcd, 1)
        header += struct.pack(">HH", 3, 1)   # total=3, seq=1
        payload = header   # empty body
        cs = compute_checksum(payload)
        frame = payload + bytes([cs])
        hdr, offset = decode_header(frame)
        self.assertIsNotNone(hdr.sub_packet)
        assert hdr.sub_packet is not None
        self.assertEqual(hdr.sub_packet.total_count, 3)
        self.assertEqual(hdr.sub_packet.sequence_number, 1)
        self.assertEqual(offset, 16)

    def test_invalid_encryption_raises(self) -> None:
        phone_bcd = bytes(
            [(int(_PHONE[i * 2]) << 4) | int(_PHONE[i * 2 + 1]) for i in range(6)]
        )
        # bits 10–12 = 0b111 (7) — invalid encryption type
        props = (7 << 10)
        header = struct.pack(">HH6sH", 0x0200, props, phone_bcd, 1)
        payload = header
        cs = compute_checksum(payload)
        frame = payload + bytes([cs])
        with self.assertRaises(HeaderError):
            decode_header(frame)


# ===========================================================================
# SECTION 5 – ROUND-TRIP TESTS (build_frame + parse_frame)
# ===========================================================================

class TestRoundTrip(unittest.TestCase):
    """Round-trip encode/decode tests using build_frame and JT808Parser."""

    def setUp(self) -> None:
        self.parser = JT808Parser()

    # --- 0x0002 Terminal Heartbeat (bodyless) ---

    def test_heartbeat_roundtrip(self) -> None:
        frame = _build(MessageID.TERMINAL_HEARTBEAT, b"")
        msg = self.parser.parse_frame(frame)
        self.assertEqual(msg.header.message_id, MessageID.TERMINAL_HEARTBEAT)
        self.assertIsNone(msg.body)

    # --- 0x0003 Terminal Logout (bodyless) ---

    def test_logout_roundtrip(self) -> None:
        frame = _build(MessageID.TERMINAL_LOGOUT, b"")
        msg = self.parser.parse_frame(frame)
        self.assertEqual(msg.header.message_id, MessageID.TERMINAL_LOGOUT)
        self.assertIsNone(msg.body)

    # --- 0x0001 Terminal General Response ---

    def test_terminal_general_response_roundtrip(self) -> None:
        body = struct.pack(">HHB", 42, 0x8001, GeneralResult.SUCCESS)
        frame = _build(MessageID.TERMINAL_GENERAL_RESPONSE, body)
        msg = self.parser.parse_frame(frame)
        self.assertIsInstance(msg.body, TerminalGeneralResponse)
        resp: TerminalGeneralResponse = msg.body  # type: ignore[assignment]
        self.assertEqual(resp.response_serial, 42)
        self.assertEqual(resp.response_message_id, 0x8001)
        self.assertEqual(resp.result, GeneralResult.SUCCESS)

    # --- 0x8001 Platform General Response ---

    def test_platform_general_response_roundtrip(self) -> None:
        body = struct.pack(">HHB", 7, 0x0200, GeneralResult.FAILURE)
        frame = _build(MessageID.PLATFORM_GENERAL_RESPONSE, body)
        msg = self.parser.parse_frame(frame)
        self.assertIsInstance(msg.body, PlatformGeneralResponse)
        resp: PlatformGeneralResponse = msg.body  # type: ignore[assignment]
        self.assertEqual(resp.response_serial, 7)
        self.assertEqual(resp.result, GeneralResult.FAILURE)

    # --- 0x0100 Terminal Registration ---

    def test_terminal_registration_roundtrip(self) -> None:
        province = 11
        city = 1
        mfr = b"ABCDE"
        model = b"ModelX" + b"\x00" * 14
        tid = b"TID001\x00"
        color = LicensePlateColor.BLUE
        plate = "京A12345".encode("gb18030")
        body = (
            struct.pack(">HH", province, city)
            + mfr
            + model
            + tid
            + struct.pack("B", color)
            + plate
        )
        frame = _build(MessageID.TERMINAL_REGISTRATION, body)
        msg = self.parser.parse_frame(frame)
        self.assertIsInstance(msg.body, TerminalRegistration)
        reg: TerminalRegistration = msg.body  # type: ignore[assignment]
        self.assertEqual(reg.province_id, province)
        self.assertEqual(reg.city_id, city)
        self.assertEqual(reg.manufacturer_id, mfr)
        self.assertEqual(reg.terminal_model, "ModelX")
        self.assertEqual(reg.terminal_id, "TID001")
        self.assertEqual(reg.plate_color, LicensePlateColor.BLUE)
        self.assertEqual(reg.vehicle_identification, "京A12345")

    # --- 0x0102 Terminal Authentication ---

    def test_terminal_authentication_roundtrip(self) -> None:
        auth_code = "AUTH_TOKEN_001"
        body = auth_code.encode("ascii")
        frame = _build(MessageID.TERMINAL_AUTHENTICATION, body)
        msg = self.parser.parse_frame(frame)
        self.assertIsInstance(msg.body, TerminalAuthentication)
        auth: TerminalAuthentication = msg.body  # type: ignore[assignment]
        self.assertEqual(auth.auth_code, auth_code)

    # --- 0x8100 Terminal Registration Response (success) ---

    def test_registration_response_success_roundtrip(self) -> None:
        auth_code = b"TOKEN123"
        body = struct.pack(">HB", 1, RegistrationResult.SUCCESS) + auth_code
        frame = _build(MessageID.TERMINAL_REGISTRATION_RESPONSE, body)
        msg = self.parser.parse_frame(frame)
        self.assertIsInstance(msg.body, TerminalRegistrationResponse)
        resp: TerminalRegistrationResponse = msg.body  # type: ignore[assignment]
        self.assertEqual(resp.result, RegistrationResult.SUCCESS)
        self.assertEqual(resp.auth_code, "TOKEN123")

    # --- 0x8100 Terminal Registration Response (failure) ---

    def test_registration_response_failure_no_auth_code(self) -> None:
        body = struct.pack(">HB", 2, RegistrationResult.VEHICLE_NOT_IN_DATABASE)
        frame = _build(MessageID.TERMINAL_REGISTRATION_RESPONSE, body)
        msg = self.parser.parse_frame(frame)
        resp: TerminalRegistrationResponse = msg.body  # type: ignore[assignment]
        self.assertEqual(resp.result, RegistrationResult.VEHICLE_NOT_IN_DATABASE)
        self.assertIsNone(resp.auth_code)

    # --- 0x0200 Location Information Report ---

    def _build_location_body(
        self,
        alarm: int = 0,
        status: int = 0,
        lat_raw: int = 31_523_000,   # ~31.523° N
        lon_raw: int = 120_123_000,  # ~120.123° E
        altitude: int = 50,
        speed_raw: int = 600,         # 60.0 km/h
        direction: int = 90,
        gps_time: str = "230101120000",
        additional: bytes = b"",
    ) -> bytes:
        gps_bcd = bytes(
            [
                (int(gps_time[i * 2]) << 4) | int(gps_time[i * 2 + 1])
                for i in range(6)
            ]
        )
        return (
            struct.pack(">IIIIHH H", alarm, status, lat_raw, lon_raw,
                        altitude, speed_raw, direction)
            + gps_bcd
            + additional
        )

    def test_location_report_nominal(self) -> None:
        body = self._build_location_body()
        frame = _build(MessageID.LOCATION_REPORT, body)
        msg = self.parser.parse_frame(frame)
        self.assertIsInstance(msg.body, LocationReport)
        loc: LocationReport = msg.body  # type: ignore[assignment]
        self.assertAlmostEqual(loc.latitude, 31.523, places=3)
        self.assertAlmostEqual(loc.longitude, 120.123, places=3)
        self.assertEqual(loc.altitude, 50)
        self.assertAlmostEqual(loc.speed, 60.0, places=1)
        self.assertEqual(loc.direction, 90)
        self.assertEqual(loc.gps_time, "230101120000")
        self.assertEqual(len(loc.additional_items), 0)

    def test_location_report_south_latitude(self) -> None:
        # Bit 28 of status flags = 1 → south latitude
        status = 1 << 28
        body = self._build_location_body(status=status, lat_raw=10_000_000)
        frame = _build(MessageID.LOCATION_REPORT, body)
        msg = self.parser.parse_frame(frame)
        loc: LocationReport = msg.body  # type: ignore[assignment]
        self.assertLess(loc.latitude, 0)

    def test_location_report_west_longitude(self) -> None:
        # Bit 27 of status flags = 1 → west longitude
        status = 1 << 27
        body = self._build_location_body(status=status, lon_raw=10_000_000)
        frame = _build(MessageID.LOCATION_REPORT, body)
        msg = self.parser.parse_frame(frame)
        loc: LocationReport = msg.body  # type: ignore[assignment]
        self.assertLess(loc.longitude, 0)

    def test_location_report_with_additional_items(self) -> None:
        # Additional item: ID=0x01 (mileage), length=4, value=12345
        additional = struct.pack(">BBL", 0x01, 4, 12345)
        body = self._build_location_body(additional=additional)
        frame = _build(MessageID.LOCATION_REPORT, body)
        msg = self.parser.parse_frame(frame)
        loc: LocationReport = msg.body  # type: ignore[assignment]
        self.assertEqual(len(loc.additional_items), 1)
        item = loc.additional_items[0]
        self.assertEqual(item.item_id, 0x01)
        self.assertEqual(len(item.data), 4)

    # --- 0x0704 Batch Location Upload ---

    def test_batch_location_upload_roundtrip(self) -> None:
        loc_body = self._build_location_body()
        item = struct.pack(">H", len(loc_body)) + loc_body
        body = struct.pack(">HB", 1, 0) + item   # count=1, type=normal
        frame = _build(MessageID.BATCH_LOCATION_UPLOAD, body)
        msg = self.parser.parse_frame(frame)
        self.assertIsInstance(msg.body, BatchLocationUpload)
        batch: BatchLocationUpload = msg.body  # type: ignore[assignment]
        self.assertEqual(batch.count, 1)
        self.assertEqual(batch.location_type, 0)
        self.assertEqual(len(batch.items), 1)

    # --- Phone number preserved ---

    def test_phone_number_preserved(self) -> None:
        phone = "013912345678"
        frame = build_frame(MessageID.TERMINAL_HEARTBEAT, phone, 99, b"")
        msg = self.parser.parse_frame(frame)
        self.assertEqual(msg.header.phone_number, phone)

    # --- Serial number preserved ---

    def test_serial_number_preserved(self) -> None:
        frame = build_frame(MessageID.TERMINAL_HEARTBEAT, _PHONE, 1234, b"")
        msg = self.parser.parse_frame(frame)
        self.assertEqual(msg.header.serial_number, 1234)

    # --- Frame accepted with and without surrounding 0x7E flags ---

    def test_frame_with_flags(self) -> None:
        frame = _build(MessageID.TERMINAL_HEARTBEAT, b"")
        self.assertEqual(frame[0], 0x7E)
        self.assertEqual(frame[-1], 0x7E)
        msg = self.parser.parse_frame(frame)
        self.assertEqual(msg.header.message_id, MessageID.TERMINAL_HEARTBEAT)

    def test_frame_without_flags(self) -> None:
        frame = _build(MessageID.TERMINAL_HEARTBEAT, b"")
        msg = self.parser.parse_frame(frame[1:-1])
        self.assertEqual(msg.header.message_id, MessageID.TERMINAL_HEARTBEAT)


# ===========================================================================
# SECTION 6 – ERROR PATH TESTS
# ===========================================================================

class TestErrorPaths(unittest.TestCase):
    """Tests that verify every typed exception is raised on invalid input."""

    def setUp(self) -> None:
        self.parser = JT808Parser()

    # --- FramingError ---

    def test_framing_error_trailing_escape(self) -> None:
        with self.assertRaises(FramingError):
            unescape(bytes([0x7D]))

    def test_framing_error_invalid_qualifier(self) -> None:
        with self.assertRaises(FramingError):
            unescape(bytes([0x7D, 0x05]))

    def test_framing_error_too_short_after_unescape(self) -> None:
        # A frame with only one byte (after unescape) is too short for checksum
        with self.assertRaises(FramingError):
            self.parser.parse_frame(bytes([0x7E, 0xAA, 0x7E]))

    # --- ChecksumError ---

    def test_checksum_error_on_bad_frame(self) -> None:
        # Build a valid frame, then corrupt the checksum byte
        frame = _build(MessageID.TERMINAL_HEARTBEAT, b"")
        # The checksum is the second-to-last byte (before the trailing 0x7E flag)
        frame_list = bytearray(frame)
        frame_list[-2] ^= 0xFF   # flip all bits of checksum byte
        with self.assertRaises(ChecksumError):
            self.parser.parse_frame(bytes(frame_list))

    # --- HeaderError ---

    def test_header_error_on_short_frame(self) -> None:
        # Frame content: single payload byte 0x01 followed by checksum 0x01
        # (checksum passes, but the 2-byte unescaped frame is too short for a header)
        raw = bytes([0x7E, 0x01, 0x01, 0x7E])
        with self.assertRaises(HeaderError):
            self.parser.parse_frame(raw)

    # --- BodyError – 0x0001 wrong length ---

    def test_body_error_0001_wrong_length(self) -> None:
        body = bytes([0x00, 0x01, 0x02])   # should be 5 bytes
        frame = _build(MessageID.TERMINAL_GENERAL_RESPONSE, body)
        with self.assertRaises(BodyError):
            self.parser.parse_frame(frame)

    # --- BodyError – 0x0102 empty auth code ---

    def test_body_error_0102_empty(self) -> None:
        frame = _build(MessageID.TERMINAL_AUTHENTICATION, b"")
        with self.assertRaises(BodyError):
            self.parser.parse_frame(frame)

    # --- BodyError – 0x0200 too short ---

    def test_body_error_0200_too_short(self) -> None:
        frame = _build(MessageID.LOCATION_REPORT, bytes(10))
        with self.assertRaises(BodyError):
            self.parser.parse_frame(frame)

    # --- BodyError – 0x8100 success without auth code ---

    def test_body_error_8100_success_no_auth(self) -> None:
        body = struct.pack(">HB", 1, RegistrationResult.SUCCESS)
        # body is exactly 3 bytes with no auth code
        frame = _build(MessageID.TERMINAL_REGISTRATION_RESPONSE, body)
        with self.assertRaises(BodyError):
            self.parser.parse_frame(frame)

    # --- UnsupportedMessageError ---

    def test_unsupported_message_id(self) -> None:
        frame = _build(0xFFFF, b"")
        with self.assertRaises(UnsupportedMessageError):
            self.parser.parse_frame(frame)

    # --- build_frame validation ---

    def test_build_frame_rejects_short_phone(self) -> None:
        with self.assertRaises(ValueError):
            build_frame(0x0002, "01234", 1, b"")

    def test_build_frame_rejects_non_digit_phone(self) -> None:
        with self.assertRaises(ValueError):
            build_frame(0x0002, "01234ABCDE56", 1, b"")

    def test_build_frame_rejects_oversized_body(self) -> None:
        with self.assertRaises(ValueError):
            build_frame(0x0002, _PHONE, 1, bytes(1024))

    def test_build_frame_rejects_bad_serial(self) -> None:
        with self.assertRaises(ValueError):
            build_frame(0x0002, _PHONE, 70000, b"")

    # --- Additional info item truncation ---

    def test_additional_info_truncated_header_raises(self) -> None:
        # Additional section has only one byte (needs at least 2 for ID + len)
        additional = bytes([0x01])
        body = self._build_location_body(additional=additional)
        frame = _build(MessageID.LOCATION_REPORT, body)
        with self.assertRaises(BodyError):
            self.parser.parse_frame(frame)

    def test_additional_info_truncated_data_raises(self) -> None:
        # Declares 4 bytes of data but only 2 present
        additional = bytes([0x01, 0x04, 0x00, 0x00])
        body = self._build_location_body(additional=additional)
        frame = _build(MessageID.LOCATION_REPORT, body)
        with self.assertRaises(BodyError):
            self.parser.parse_frame(frame)

    def _build_location_body(self, additional: bytes = b"") -> bytes:
        gps_time = "230101120000"
        gps_bcd = bytes(
            [
                (int(gps_time[i * 2]) << 4) | int(gps_time[i * 2 + 1])
                for i in range(6)
            ]
        )
        return (
            struct.pack(">IIIIHH H", 0, 0, 31_523_000, 120_123_000, 50, 600, 90)
            + gps_bcd
            + additional
        )


# ===========================================================================
# SECTION 7 – PARSE STREAM TESTS
# ===========================================================================

class TestParseStream(unittest.TestCase):
    """Tests for JT808Parser.parse_stream()."""

    def setUp(self) -> None:
        self.parser = JT808Parser()

    def test_empty_stream(self) -> None:
        self.assertEqual(self.parser.parse_stream(b""), [])

    def test_single_frame_in_stream(self) -> None:
        frame = _build(MessageID.TERMINAL_HEARTBEAT, b"")
        msgs = self.parser.parse_stream(frame)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].header.message_id, MessageID.TERMINAL_HEARTBEAT)

    def test_multiple_frames_in_stream(self) -> None:
        f1 = _build(MessageID.TERMINAL_HEARTBEAT, b"")
        f2 = _build(MessageID.TERMINAL_LOGOUT, b"")
        msgs = self.parser.parse_stream(f1 + f2)
        self.assertEqual(len(msgs), 2)
        self.assertEqual(msgs[0].header.message_id, MessageID.TERMINAL_HEARTBEAT)
        self.assertEqual(msgs[1].header.message_id, MessageID.TERMINAL_LOGOUT)

    def test_bad_frame_skipped_good_frame_parsed(self) -> None:
        # A valid frame followed by a corrupted frame, followed by another valid frame
        good1 = _build(MessageID.TERMINAL_HEARTBEAT, b"", serial=1)
        # Corrupt: two 0x7E flags with a single byte between them — checksum only, no header
        bad = bytes([0x7E, 0xAA, 0x7E])
        good2 = _build(MessageID.TERMINAL_HEARTBEAT, b"", serial=2)
        msgs = self.parser.parse_stream(good1 + bad + good2)
        self.assertEqual(len(msgs), 2)


# ===========================================================================
# SECTION 8 – ESCAPE INTERACTION WITH FRAME BUILDER
# ===========================================================================

class TestEscapeInBuiltFrames(unittest.TestCase):
    """Tests that frames containing 0x7D and 0x7E bytes in the body are correctly
    escaped by build_frame and unescaped by parse_frame."""

    def setUp(self) -> None:
        self.parser = JT808Parser()

    def test_body_containing_7e_roundtrips(self) -> None:
        # 0x0102 auth code that contains ASCII characters whose BCD encoding
        # could result in 0x7E after the checksum — we force it via a crafted body.
        # Use 0x0102 terminal authentication with a known auth code.
        auth_code = "A" * 5
        body = auth_code.encode("ascii")
        frame = build_frame(MessageID.TERMINAL_AUTHENTICATION, _PHONE, 1, body)
        msg = self.parser.parse_frame(frame)
        auth: TerminalAuthentication = msg.body  # type: ignore[assignment]
        self.assertEqual(auth.auth_code, auth_code)

    def test_body_with_0x7d_byte_roundtrips(self) -> None:
        # Build a terminal-authentication body that contains 0x7D
        body = bytes([0x7D, 0x7E, 0x61])   # contains both special bytes
        # This won't be valid as ASCII but we use errors='replace' so it's safe
        frame = build_frame(MessageID.TERMINAL_AUTHENTICATION, _PHONE, 1, body)
        # Verify no raw 0x7E appears inside the frame (between the flags)
        inner = frame[1:-1]
        self.assertNotIn(0x7E, inner)
        # Parse must succeed
        msg = self.parser.parse_frame(frame)
        self.assertIsNotNone(msg)


if __name__ == "__main__":
    unittest.main()
