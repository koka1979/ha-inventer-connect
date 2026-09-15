"""Tests for the inVENTer Connect wire protocol.

These run without Home Assistant, Bluetooth or the controller:

    python3 -m pytest homeassistant/tests/test_protocol.py
"""

from __future__ import annotations

import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "custom_components" / "inventer_connect"))

import protocol as p  # noqa: E402

FIXED_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


# --- checksum ----------------------------------------------------------------

def test_crc8_is_the_firmware_variant_not_the_textbook_one():
    """The firmware tests the MSB after shifting, which changes the result."""
    def textbook(data: bytes) -> int:
        crc = 0
        for byte in data:
            crc ^= byte
            for _ in range(8):
                crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
        return crc

    sample = bytes(range(16))
    assert p.crc8(sample) != textbook(sample)


def test_crc8_of_empty_input_is_zero():
    assert p.crc8(b"") == 0


def test_crc8_stays_in_byte_range():
    for length in range(1, 40):
        assert 0 <= p.crc8(bytes(range(length))) <= 0xFF


# --- packet construction -----------------------------------------------------

def test_packet_header_fields():
    packet = p.build_packet(p.TYPE_ZONE_VIEW_HEADER, now=FIXED_TIME)

    assert len(packet) == p.PAYLOAD_OFFSET
    assert packet[p.HDR_PACKET_SIZE] == p.PAYLOAD_OFFSET
    assert packet[p.HDR_PACKET_TYPE] == p.TYPE_ZONE_VIEW_HEADER
    assert packet[p.HDR_OP_TYPE] == p.OP_TYPE_DATA_REQUEST
    assert packet[p.HDR_DESTINATION] == p.TARGET_CONTROLLER
    assert packet[p.HDR_BACKTRACKING] == 0


def test_packet_checksum_covers_everything_but_itself():
    packet = p.build_packet(p.TYPE_USER_OVERRIDE, b"\x01\x02\x03", now=FIXED_TIME)
    assert packet[p.HDR_CHECKSUM] == p.crc8(packet[1:])


def test_timestamp_is_big_endian_seconds_since_2000():
    packet = p.build_packet(p.TYPE_REAL_TIME, now=FIXED_TIME)
    seconds = struct.unpack_from(">i", packet, p.HDR_TIMESTAMP)[0]
    assert seconds == int((FIXED_TIME - p.EPOCH_2000).total_seconds())


def test_payload_is_little_endian_while_header_timestamp_is_big_endian():
    payload = p.user_settings_payload(p.COMMAND_ZONE_SPEED_MODE, 2, 1, 0, 600)
    assert payload == bytes([5, 2, 1, 0]) + struct.pack("<i", 600)


def test_oversized_payload_is_rejected():
    with pytest.raises(p.ProtocolError):
        p.build_packet(p.TYPE_USER_OVERRIDE, b"\x00" * 200, now=FIXED_TIME)


# --- DataObjectArray envelope ------------------------------------------------

def test_data_row_envelope_matches_the_sdk_layout():
    wrapped = p.wrap_data_row(b"\x01\x02\x03\x04\x05\x06\x07\x08")

    assert len(wrapped) == 12
    magic, data_type, count = struct.unpack_from("<HBB", wrapped, 0)
    assert magic == p.DATA_MAGIC
    assert data_type == p.DATA_TYPE_ROW
    assert count == 8


def test_user_override_packet_is_22_bytes():
    """10 byte header + 4 byte envelope + 8 byte UserSettings."""
    packet = p.set_zone_speed(0, 2, 1, 600, now=FIXED_TIME)
    assert len(packet) == 22
    assert p.packet_type(packet) == p.TYPE_USER_OVERRIDE


# --- the ready-made commands -------------------------------------------------

def test_global_boost_uses_speed_4_mode_1_and_scales_hours():
    packet = p.global_boost(2, now=FIXED_TIME)
    command, speed, mode, zone = packet[p.PAYLOAD_OFFSET + 4:p.PAYLOAD_OFFSET + 8]
    timeout = struct.unpack_from("<i", packet, p.PAYLOAD_OFFSET + 8)[0]

    assert command == p.COMMAND_GLOBAL_BOOST
    assert (speed, mode) == (4, 1)
    assert zone == p.ZONE_ALL
    assert timeout == 7200


def test_shutdown_uses_an_open_ended_timeout():
    packet = p.global_shutdown(now=FIXED_TIME)
    timeout = struct.unpack_from("<i", packet, p.PAYLOAD_OFFSET + 8)[0]
    assert timeout == -1


def test_zone_commands_address_a_single_zone():
    for builder, expected in ((p.zone_boost, p.COMMAND_ZONE_BOOST),
                              (p.zone_pause, p.COMMAND_ZONE_PAUSE)):
        packet = builder(3, now=FIXED_TIME)
        command = packet[p.PAYLOAD_OFFSET + 4]
        zone = packet[p.PAYLOAD_OFFSET + 7]
        assert command == expected
        assert zone == 3


def test_zone_row_request_carries_the_index_and_is_a_data_update():
    packet = p.request_zone_row(2, now=FIXED_TIME)
    assert p.packet_type(packet) == p.TYPE_ZONE_VIEW_ROW
    assert packet[p.HDR_OP_TYPE] == p.OP_TYPE_DATA_UPDATE
    assert packet[p.PAYLOAD_OFFSET] == 2


# --- framing -----------------------------------------------------------------

def test_frames_are_20_bytes_with_index_and_total_nibbles():
    packet = p.set_zone_speed(0, 2, 1, 600, now=FIXED_TIME)
    frames = p.fragment(packet)

    assert len(frames) == 2
    assert all(len(f) == p.FRAME_SIZE for f in frames)
    for index, frame in enumerate(frames, start=1):
        assert frame[0] >> 4 == index
        assert frame[0] & 0x0F == len(frames)


def test_each_frame_carries_a_crc_over_its_padded_payload():
    frames = p.fragment(p.set_zone_speed(0, 2, 1, 600, now=FIXED_TIME))
    for frame in frames:
        assert frame[1] == p.crc8(frame[p.FRAME_HEADER_SIZE:])


def test_ack_value_lands_in_byte_two():
    frames = p.fragment(p.request_zone_view_header(now=FIXED_TIME), ack=7)
    assert all(frame[2] == 7 for frame in frames)


def test_round_trip_through_fragment_and_reassembler():
    for payload_length in (0, 1, 8, 17, 34, 100):
        packet = p.build_packet(p.TYPE_USER_OVERRIDE, b"\xab" * payload_length, now=FIXED_TIME)
        reassembler = p.Reassembler()
        complete = False
        for frame in p.fragment(packet):
            complete = reassembler.push(frame)
        assert complete, payload_length
        assert reassembler.packet() == packet, payload_length


def test_reassembler_reports_completion_only_on_the_last_frame():
    packet = p.build_packet(p.TYPE_USER_OVERRIDE, b"\xcd" * 40, now=FIXED_TIME)
    frames = p.fragment(packet)
    reassembler = p.Reassembler()

    results = [reassembler.push(frame) for frame in frames]
    assert results[:-1] == [False] * (len(frames) - 1)
    assert results[-1] is True


def test_reassembler_rejects_an_error_frame():
    reassembler = p.Reassembler()
    with pytest.raises(p.ProtocolError):
        reassembler.push(bytes(20))


def test_reassembler_rejects_a_truncated_frame():
    reassembler = p.Reassembler()
    with pytest.raises(p.ProtocolError):
        reassembler.push(b"\x11")


def test_ack_and_cancel_frames():
    assert p.ack_frame(3)[2] == 3
    assert p.cancel_frame()[2] == 0xFF
    assert len(p.cancel_frame()) == p.FRAME_SIZE


# --- zone status parsing -----------------------------------------------------

def _zone_row(**overrides) -> bytes:
    """Build a synthetic ZONE_VIEW_ROW packet with known field values."""
    values = {
        "fan_speed": 2, "play_mode": p.PLAY_MODE_NORMAL, "timer": 900, "flags": 0b11011,
        "ventilation_mode": 1, "ventilation_profile": 3, "comfort_room_temp": 21.5,
        "humidity_threshold": 60.0, "co2_threshold": 1000.0, "voc_threshold": 250.0,
        "ext_temperature": 8.25, "ext_humidity": 71.0, "int_temperature": 22.5,
        "int_humidity": 55.5, "int_co2": 620.0, "int_voc": 120.0,
        "system_status_flag": 0.0, "ventilation_time": 70,
    }
    values.update(overrides)

    row = bytearray(p.ZONE_ROW_MIN_LENGTH)
    row[p.HDR_PACKET_SIZE] = p.ZONE_ROW_MIN_LENGTH
    row[p.HDR_PACKET_TYPE] = p.TYPE_ZONE_VIEW_ROW
    row[17] = values["fan_speed"]
    row[18] = values["play_mode"]
    struct.pack_into("<i", row, 19, values["timer"])
    row[23] = values["flags"]
    row[24] = values["ventilation_mode"]
    row[25] = values["ventilation_profile"]
    for offset, key in ((30, "comfort_room_temp"), (34, "humidity_threshold"),
                        (38, "co2_threshold"), (42, "voc_threshold"),
                        (46, "ext_temperature"), (50, "ext_humidity"),
                        (54, "int_temperature"), (58, "int_humidity"),
                        (62, "int_co2"), (66, "int_voc"), (70, "system_status_flag")):
        struct.pack_into("<f", row, offset, values[key])
    struct.pack_into("<i", row, 78, values["ventilation_time"])
    return bytes(row)


def test_zone_row_scalar_fields():
    status = p.parse_zone_row(_zone_row())

    assert status.fan_speed == 2
    assert status.timer == 900
    assert status.ventilation_mode == 1
    assert status.ventilation_profile == 3
    assert status.ventilation_time == 70


def test_zone_row_sensor_values():
    status = p.parse_zone_row(_zone_row())

    assert status.int_temperature == pytest.approx(22.5)
    assert status.int_humidity == pytest.approx(55.5)
    assert status.int_co2 == pytest.approx(620.0)
    assert status.ext_temperature == pytest.approx(8.25)


def test_zone_row_flag_bits():
    status = p.parse_zone_row(_zone_row(flags=0b11011))

    assert status.timer_active is True
    assert status.co2_sensor_present is True
    assert status.ext_sensor_present is False
    assert status.fcu_present is True
    assert status.global_command is True


def test_zone_row_play_modes():
    assert p.parse_zone_row(_zone_row(play_mode=p.PLAY_MODE_PAUSE)).paused is True
    assert p.parse_zone_row(_zone_row(play_mode=p.PLAY_MODE_BOOST)).boosting is True

    normal = p.parse_zone_row(_zone_row(play_mode=p.PLAY_MODE_NORMAL))
    assert (normal.paused, normal.boosting) == (False, False)


def test_zone_is_off_when_paused_or_at_zero_speed():
    assert p.parse_zone_row(_zone_row(fan_speed=0)).is_on is False
    assert p.parse_zone_row(_zone_row(play_mode=p.PLAY_MODE_PAUSE)).is_on is False
    assert p.parse_zone_row(_zone_row(fan_speed=1)).is_on is True


def test_infinite_sensor_readings_become_zero():
    """The firmware uses infinity for absent sensors; the app maps that to 0."""
    status = p.parse_zone_row(_zone_row(int_co2=float("inf")))
    assert status.int_co2 == 0.0


def test_short_zone_row_is_rejected_rather_than_read_past_the_end():
    with pytest.raises(p.ProtocolError):
        p.parse_zone_row(_zone_row()[:40])


# --- a full transaction, as the client drives it -----------------------------

class FakeController:
    """Minimal stand-in that answers a zone-row request.

    Mirrors the client's transaction: frames are written, then the client reads
    one fragment at a time, acknowledging each by writing back its index.
    """

    def __init__(self, response: bytes) -> None:
        self.response_frames = p.fragment(response)
        self.written: list[bytes] = []
        self._cursor = 0

    def write(self, frame: bytes) -> None:
        self.written.append(frame)

    def read(self) -> bytes:
        frame = self.response_frames[self._cursor]
        self._cursor += 1
        return frame


def test_client_transaction_sequence_reassembles_a_zone_row():
    controller = FakeController(_zone_row(fan_speed=3, int_temperature=21.0))
    request = p.request_zone_row(0, now=FIXED_TIME)

    for frame in p.fragment(request):
        controller.write(frame)

    reassembler = p.Reassembler()
    acks: list[int] = []
    while True:
        complete = reassembler.push(controller.read())
        ack = p.ack_frame(reassembler.received)
        controller.write(ack)
        acks.append(ack[2])
        if complete:
            break

    status = p.parse_zone_row(reassembler.packet())
    assert status.fan_speed == 3
    assert status.int_temperature == pytest.approx(21.0)
    assert acks == list(range(1, len(controller.response_frames) + 1))


def test_zone_row_needs_several_frames():
    """Confirms the poll loop is not a single round trip."""
    assert len(p.fragment(_zone_row())) >= 5
