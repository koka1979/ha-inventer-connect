"""Wire protocol for inVENTer Connect controllers.

Pure functions and dataclasses, no Home Assistant or Bluetooth imports, so the
whole protocol layer is testable without hardware. Derived from the Volution
device SDK shipped inside the inVENTer Mobile app; see
docs/research/inventer-connect-reverse-engineering.md for the analysis.

Layering, outermost first:

    BLE frames (20 bytes each)  ->  packet  ->  DataObjectArray  ->  payload

The controller is the only peer we talk to; it relays to the ventilation units
over its own 868 MHz network.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone

# --- packet types (ProtocolPacket.STD_TYPE ordinals) -------------------------

TYPE_DEV_RSSI = 9
TYPE_REAL_TIME = 36
TYPE_USER_OVERRIDE = 56
TYPE_DEVICE_VIEW_HEADER = 141
TYPE_DEVICE_VIEW_ROW = 142
TYPE_REQUEST_ZONE_VIEW = 144
TYPE_ZONE_VIEW_HEADER = 145
TYPE_ZONE_VIEW_ROW = 146

OP_TYPE_DATA_UPDATE = 1
OP_TYPE_DATA_REQUEST = 2

TARGET_CONTROLLER = 0
TARGET_ESP32 = 159

# --- user override command types --------------------------------------------

COMMAND_NONE = 0
COMMAND_GLOBAL_BOOST = 1
COMMAND_GLOBAL_PAUSE = 2
COMMAND_ZONE_BOOST = 3
COMMAND_ZONE_PAUSE = 4
COMMAND_ZONE_SPEED_MODE = 5
COMMAND_ZONE_VENT_PROFILE = 6
COMMAND_CANCEL = 7

ZONE_ALL = 0xFF

#: The app writes speed 4 for boost, so 4 is the top of the range.
MAX_FAN_SPEED = 4

#: playMode values observed in a zone row.
PLAY_MODE_NORMAL = 0
PLAY_MODE_PAUSE = 1
PLAY_MODE_BOOST = 2

# --- packet layout -----------------------------------------------------------

HDR_CHECKSUM = 0
HDR_PACKET_SIZE = 1
HDR_BACKTRACKING = 2
HDR_PACKET_TYPE = 3
HDR_OP_TYPE = 4
HDR_DESTINATION = 5
HDR_TIMESTAMP = 6
PAYLOAD_OFFSET = 10
MAX_PACKET_SIZE = 128

FRAME_SIZE = 20
FRAME_HEADER_SIZE = 3
FRAME_PAYLOAD_SIZE = FRAME_SIZE - FRAME_HEADER_SIZE  # 17
REASSEMBLY_LIMIT = 256

#: DataObjectArray magic, little-endian int16.
DATA_MAGIC = 2746
DATA_TYPE_ROW = 0

EPOCH_2000 = datetime(2000, 1, 1, tzinfo=timezone.utc)


class ProtocolError(Exception):
    """Raised when a buffer cannot be interpreted as a valid packet."""


def crc8(data: bytes) -> int:
    """Checksum as the controller firmware computes it.

    Polynomial 0x07, init 0x00, no reflection -- but the MSB is tested *after*
    the shift rather than before. That deviates from the textbook routine, and
    the firmware rejects packets whose checksum was computed the usual way.
    """
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc << 1) & 0xFF
            if crc & 0x80:
                crc ^= 0x07
    return crc


def timestamp_bytes(now: datetime | None = None) -> bytes:
    """Seconds since 2000-01-01, big-endian.

    Note the split: this header field is big-endian while every payload field
    is little-endian.
    """
    now = now or datetime.now(timezone.utc)
    return struct.pack(">i", int((now - EPOCH_2000).total_seconds()))


def wrap_data_row(payload: bytes) -> bytes:
    """Wrap a payload in the DataObjectArray envelope the controller expects.

    Mirrors DataObjectArray.setRawData(payload, len) followed by
    setPayload(buffer, getBufferLength() - 3), which yields magic, type, count
    and then the payload itself.
    """
    return struct.pack("<HBB", DATA_MAGIC, DATA_TYPE_ROW, len(payload)) + payload


def build_packet(packet_type: int, payload: bytes = b"", *,
                 op_type: int = OP_TYPE_DATA_REQUEST,
                 target: int = TARGET_CONTROLLER,
                 now: datetime | None = None) -> bytes:
    """Assemble one application packet."""
    packet_size = len(payload) + PAYLOAD_OFFSET
    if packet_size > MAX_PACKET_SIZE:
        raise ProtocolError(
            f"packet of {packet_size} bytes exceeds the {MAX_PACKET_SIZE} byte limit")

    packet = bytearray(packet_size)
    packet[HDR_PACKET_SIZE] = packet_size
    packet[HDR_BACKTRACKING] = 0
    packet[HDR_PACKET_TYPE] = packet_type
    packet[HDR_OP_TYPE] = op_type
    packet[HDR_DESTINATION] = target
    packet[HDR_TIMESTAMP:HDR_TIMESTAMP + 4] = timestamp_bytes(now)
    packet[PAYLOAD_OFFSET:] = payload
    packet[HDR_CHECKSUM] = crc8(bytes(packet[1:]))
    return bytes(packet)


def user_settings_payload(command_type: int, fan_speed: int, fan_mode: int,
                          zone_id: int, timeout_sec: int) -> bytes:
    """The 8-byte UserSettings struct, little-endian.

    zone_id 0xFF addresses every zone; timeout_sec -1 means "until cancelled".
    """
    return struct.pack("<BBBBi", command_type, fan_speed & 0xFF, fan_mode & 0xFF,
                       zone_id & 0xFF, timeout_sec)


def user_override(command_type: int, *, fan_speed: int = 0, fan_mode: int = 0,
                  zone_id: int = ZONE_ALL, timeout_sec: int = 3600,
                  now: datetime | None = None) -> bytes:
    """Build a complete USER_OVERRIDE packet."""
    payload = user_settings_payload(command_type, fan_speed, fan_mode, zone_id, timeout_sec)
    return build_packet(TYPE_USER_OVERRIDE, wrap_data_row(payload),
                        op_type=OP_TYPE_DATA_REQUEST, now=now)


# --- ready-made commands, mirroring the app's request classes ----------------

def set_zone_speed(zone_id: int, fan_speed: int, fan_mode: int,
                   timeout_sec: int, now: datetime | None = None) -> bytes:
    return user_override(COMMAND_ZONE_SPEED_MODE, fan_speed=fan_speed,
                         fan_mode=fan_mode, zone_id=zone_id,
                         timeout_sec=timeout_sec, now=now)


def global_boost(hours: int, now: datetime | None = None) -> bytes:
    """The app fixes speed 4 and mode 1 for boost and scales hours to seconds."""
    return user_override(COMMAND_GLOBAL_BOOST, fan_speed=4, fan_mode=1,
                         zone_id=ZONE_ALL, timeout_sec=hours * 3600, now=now)


def global_pause(hours: int, now: datetime | None = None) -> bytes:
    return user_override(COMMAND_GLOBAL_PAUSE, zone_id=ZONE_ALL,
                         timeout_sec=hours * 3600, now=now)


def global_shutdown(now: datetime | None = None) -> bytes:
    """Pause with timeout -1, i.e. until something cancels it."""
    return user_override(COMMAND_GLOBAL_PAUSE, zone_id=ZONE_ALL,
                         timeout_sec=-1, now=now)


def zone_boost(zone_id: int, now: datetime | None = None) -> bytes:
    return user_override(COMMAND_ZONE_BOOST, zone_id=zone_id, timeout_sec=3600, now=now)


def zone_pause(zone_id: int, now: datetime | None = None) -> bytes:
    return user_override(COMMAND_ZONE_PAUSE, zone_id=zone_id, timeout_sec=3600, now=now)


def cancel(zone_id: int = ZONE_ALL, now: datetime | None = None) -> bytes:
    """Drop any override and return the zone to its programmed profile."""
    return user_override(COMMAND_CANCEL, zone_id=zone_id, timeout_sec=3600, now=now)


def request_zone_view_header(now: datetime | None = None) -> bytes:
    return build_packet(TYPE_ZONE_VIEW_HEADER, op_type=OP_TYPE_DATA_REQUEST, now=now)


def request_zone_row(zone_index: int, now: datetime | None = None) -> bytes:
    return build_packet(TYPE_ZONE_VIEW_ROW, bytes([zone_index & 0xFF]),
                        op_type=OP_TYPE_DATA_UPDATE, now=now)


def request_device_view_header(now: datetime | None = None) -> bytes:
    return build_packet(TYPE_DEVICE_VIEW_HEADER, op_type=OP_TYPE_DATA_REQUEST, now=now)


# --- BLE framing -------------------------------------------------------------

def fragment(packet: bytes, ack: int = 0) -> list[bytes]:
    """Split a packet into the 20-byte frames the controller expects.

    Byte 0 packs the 1-based index into the high nibble and the total count
    into the low nibble, byte 1 is a CRC-8 over this frame's 17 payload bytes,
    byte 2 carries the ack value. Short final fragments are zero-padded to 17
    bytes before the CRC is taken, as the app does.
    """
    chunks = [packet[i:i + FRAME_PAYLOAD_SIZE]
              for i in range(0, len(packet), FRAME_PAYLOAD_SIZE)] or [b""]
    total = len(chunks)
    if total > 15:
        raise ProtocolError(
            "packet needs more than 15 frames, which the nibble counter cannot express")

    frames = []
    for index, body in enumerate(chunks, start=1):
        padded = body.ljust(FRAME_PAYLOAD_SIZE, b"\x00")
        frame = bytearray(FRAME_SIZE)
        frame[0] = (index << 4) | total
        frame[1] = crc8(padded)
        frame[2] = ack & 0xFF
        frame[3:] = padded
        frames.append(bytes(frame))
    return frames


def ack_frame(index: int) -> bytes:
    """Frame that acknowledges a received fragment and asks for the next."""
    frame = bytearray(FRAME_SIZE)
    frame[2] = index & 0xFF
    return bytes(frame)


def cancel_frame() -> bytes:
    """Frame that aborts an in-flight transfer."""
    return ack_frame(0xFF)


@dataclass
class Reassembler:
    """Collects read frames into one packet.

    The read path ignores the per-frame CRC and acknowledges each fragment by
    writing back its index, which is what push() reports through `complete`.
    """

    buffer: bytearray = None  # type: ignore[assignment]
    expected: int = 0
    received: int = 0

    def __post_init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.buffer = bytearray(REASSEMBLY_LIMIT)
        self.expected = 0
        self.received = 0

    def push(self, frame: bytes) -> bool:
        """Absorb one frame; returns True once the packet is complete."""
        if len(frame) < FRAME_HEADER_SIZE:
            raise ProtocolError(f"frame of {len(frame)} bytes is too short")

        index = frame[0] >> 4
        total = frame[0] & 0x0F
        if index == 0:
            raise ProtocolError("controller signalled an error frame")

        body = frame[FRAME_HEADER_SIZE:]
        start = (index - 1) * len(body)
        end = start + len(body)
        if end > REASSEMBLY_LIMIT:
            raise ProtocolError("fragment runs past the reassembly buffer")

        self.buffer[start:end] = body
        self.expected = total
        self.received = index
        return index == total

    def packet(self) -> bytes:
        """The reassembled packet, trimmed to its declared size."""
        size = self.buffer[HDR_PACKET_SIZE]
        if not PAYLOAD_OFFSET <= size <= REASSEMBLY_LIMIT:
            raise ProtocolError(f"reassembled packet declares an implausible size of {size}")
        return bytes(self.buffer[:size])


def packet_type(packet: bytes) -> int:
    if len(packet) <= HDR_PACKET_TYPE:
        raise ProtocolError("packet too short to carry a type")
    return packet[HDR_PACKET_TYPE]


# --- zone status -------------------------------------------------------------

FLAG_TIMER_ACTIVE = 1
FLAG_CO2_SENSOR = 2
FLAG_EXT_SENSOR = 4
FLAG_FCU_PRESENT = 8
FLAG_GLOBAL_COMMAND = 16

#: Smallest buffer ZoneInfoHelper.getZoneInfo() can read without overrunning.
ZONE_ROW_MIN_LENGTH = 82


@dataclass
class ZoneStatus:
    """One zone as reported by a ZONE_VIEW_ROW response."""

    fan_speed: int
    play_mode: int
    timer: int
    timer_active: bool
    co2_sensor_present: bool
    ext_sensor_present: bool
    fcu_present: bool
    global_command: bool
    ventilation_mode: int
    ventilation_profile: int
    comfort_room_temp: float
    humidity_threshold: float
    co2_threshold: float
    voc_threshold: float
    ext_temperature: float
    ext_humidity: float
    int_temperature: float
    int_humidity: float
    int_co2: float
    int_voc: float
    system_status_flag: float
    ventilation_time: int

    @property
    def paused(self) -> bool:
        return self.play_mode == PLAY_MODE_PAUSE

    @property
    def boosting(self) -> bool:
        return self.play_mode == PLAY_MODE_BOOST

    @property
    def is_on(self) -> bool:
        return self.fan_speed > 0 and not self.paused


def _float_at(buffer: bytes, offset: int) -> float:
    """Read a little-endian float, mapping the firmware's infinities to zero."""
    value = struct.unpack_from("<f", buffer, offset)[0]
    if value != value or value in (float("inf"), float("-inf")):
        return 0.0
    return value


def parse_zone_row(packet: bytes) -> ZoneStatus:
    """Decode a ZONE_VIEW_ROW packet.

    Offsets are those of ZoneInfoHelper.getZoneInfo() and are taken against the
    whole reassembled packet, header included.
    """
    if len(packet) < ZONE_ROW_MIN_LENGTH:
        raise ProtocolError(
            f"zone row of {len(packet)} bytes is shorter than the {ZONE_ROW_MIN_LENGTH} "
            "bytes the layout requires")

    flags = packet[23]
    return ZoneStatus(
        fan_speed=packet[17],
        play_mode=packet[18],
        timer=struct.unpack_from("<i", packet, 19)[0],
        timer_active=bool(flags & FLAG_TIMER_ACTIVE),
        co2_sensor_present=bool(flags & FLAG_CO2_SENSOR),
        ext_sensor_present=bool(flags & FLAG_EXT_SENSOR),
        fcu_present=bool(flags & FLAG_FCU_PRESENT),
        global_command=bool(flags & FLAG_GLOBAL_COMMAND),
        ventilation_mode=packet[24],
        ventilation_profile=packet[25],
        comfort_room_temp=_float_at(packet, 30),
        humidity_threshold=_float_at(packet, 34),
        co2_threshold=_float_at(packet, 38),
        voc_threshold=_float_at(packet, 42),
        ext_temperature=_float_at(packet, 46),
        ext_humidity=_float_at(packet, 50),
        int_temperature=_float_at(packet, 54),
        int_humidity=_float_at(packet, 58),
        int_co2=_float_at(packet, 62),
        int_voc=_float_at(packet, 66),
        system_status_flag=_float_at(packet, 70),
        ventilation_time=struct.unpack_from("<i", packet, 78)[0],
    )
