#!/usr/bin/env python3
"""Read-only BLE probe for an inVENTer Connect controller.

Scans for BLE devices, connects to the one you name, and dumps its GATT table.
It reports whether the Zirconia packet-transport characteristic is present,
which is what an eventual Home Assistant integration would speak.

The probe never writes to the controller and never sends a PIN, so it cannot
change any ventilation setting.

Usage:
    python3 inventer-ble-probe.py --scan
    python3 inventer-ble-probe.py --address AA:BB:CC:DD:EE:FF
    python3 inventer-ble-probe.py --selftest      # no hardware needed

Requires: pip install bleak

See inventer-connect-reverse-engineering.md for the protocol notes.
"""

from __future__ import annotations

import argparse
import asyncio
import struct
import sys
from datetime import datetime, timezone

# --- Zirconia transport ------------------------------------------------------

TRANSPORT_CHARACTERISTIC = "e6ec2fd8-e888-4eb2-9681-e78ed6ea89e1"

CONNECTION_SERVICE = "e6834e4b-7b3a-48e6-91e4-f1d005f564d3"
PIN_CODE_CHARACTERISTIC = "4cad343a-209a-40b7-b911-4d9b3df569b2"
PIN_CONFIRMATION_CHARACTERISTIC = "d1ae6b70-ee12-4f6d-b166-d2063dcaffe1"
PSK_CHARACTERISTIC = "638ff62c-3823-4e0f-8179-1695c46ee8ad"
DEVICE_UUID_CHARACTERISTIC = "98faf8a5-1ee6-4b0c-911e-dc37bff5206f"

DEVICE_INFO_CHARACTERISTICS = {
    "00002a00-0000-1000-8000-00805f9b34fb": "device name",
    "00002a24-0000-1000-8000-00805f9b34fb": "model number",
    "00002a25-0000-1000-8000-00805f9b34fb": "serial number",
    "00002a26-0000-1000-8000-00805f9b34fb": "firmware revision",
    "00002a27-0000-1000-8000-00805f9b34fb": "hardware revision",
    "00002a28-0000-1000-8000-00805f9b34fb": "software revision",
    "00002a29-0000-1000-8000-00805f9b34fb": "manufacturer name",
}

# Packet header layout, see ProtocolPacket.preparePacket().
HDR_CHECKSUM = 0
HDR_PACKET_SIZE = 1
HDR_BACKTRACKING = 2
HDR_PACKET_TYPE = 3
HDR_OP_TYPE = 4
HDR_DESTINATION = 5
HDR_TIMESTAMP = 6
PAYLOAD_OFFSET = 10
MAX_PACKET_SIZE = 128

OP_TYPE_DATA_UPDATE = 1
OP_TYPE_DATA_REQUEST = 2

TARGET_CONTROLLER = 0
TARGET_ESP32 = 159

COMMAND_NONE = 0
COMMAND_GLOBAL_BOOST = 1
COMMAND_GLOBAL_PAUSE = 2
COMMAND_ZONE_BOOST = 3
COMMAND_ZONE_PAUSE = 4
COMMAND_ZONE_SPEED_MODE = 5
COMMAND_ZONE_VENT_PROFILE = 6
COMMAND_CANCEL = 7

EPOCH_2000 = datetime(2000, 1, 1, tzinfo=timezone.utc)


def checksum(data: bytes) -> int:
    """CRC-8 as the controller firmware expects it.

    Polynomial 0x07, init 0x00, no reflection -- but the MSB is tested *after*
    the shift, not before. That deviates from the textbook routine and the
    firmware rejects packets computed the usual way.
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
    """Seconds since 2000-01-01, big-endian -- note the payload is little-endian."""
    now = now or datetime.now(timezone.utc)
    return struct.pack(">i", int((now - EPOCH_2000).total_seconds()))


def build_packet(packet_type: int, payload: bytes, *, op_type: int = OP_TYPE_DATA_REQUEST,
                 target: int = TARGET_CONTROLLER, now: datetime | None = None) -> bytes:
    """Assemble a Zirconia application packet."""
    packet_size = len(payload) + PAYLOAD_OFFSET
    if packet_size > MAX_PACKET_SIZE:
        raise ValueError(f"packet of {packet_size} bytes exceeds the {MAX_PACKET_SIZE} byte limit")

    packet = bytearray(packet_size)
    packet[HDR_PACKET_SIZE] = packet_size
    packet[HDR_BACKTRACKING] = 0
    packet[HDR_PACKET_TYPE] = packet_type
    packet[HDR_OP_TYPE] = op_type
    packet[HDR_DESTINATION] = target
    packet[HDR_TIMESTAMP:HDR_TIMESTAMP + 4] = timestamp_bytes(now)
    packet[PAYLOAD_OFFSET:] = payload
    packet[HDR_CHECKSUM] = checksum(bytes(packet[1:]))
    return bytes(packet)


def user_override_payload(command_type: int, fan_speed: int, fan_mode: int,
                          zone_id: int, timeout_sec: int) -> bytes:
    """The 8-byte UserSettings payload, little-endian."""
    return struct.pack("<BBBBi", command_type, fan_speed, fan_mode, zone_id, timeout_sec)


def fragment(packet: bytes, ack: int = 0) -> list[bytes]:
    """Split a packet into the 20-byte BLE frames the controller expects.

    Per Utils.prepareProtocolData(): byte 0 packs the 1-based index into the
    high nibble and the total count into the low nibble, byte 1 is a CRC-8 over
    this frame's 17 payload bytes, byte 2 carries the ack value, and the payload
    occupies bytes 3..19. Short final fragments are zero-padded to 17 bytes
    before the CRC is taken, which is what the app does too.
    """
    chunk = 17
    chunks = [packet[i:i + chunk] for i in range(0, len(packet), chunk)] or [b""]
    total = len(chunks)
    if total > 15:
        raise ValueError("packet needs more than 15 frames, which the nibble counter cannot express")

    frames = []
    for index, body in enumerate(chunks, start=1):
        padded = body.ljust(chunk, b"\x00")
        frame = bytearray(20)
        frame[0] = (index << 4) | total
        frame[1] = checksum(padded)
        frame[2] = ack & 0xFF
        frame[3:] = padded
        frames.append(bytes(frame))
    return frames


def reassemble(frames: list[bytes]) -> bytes:
    """Inverse of fragment(), mirroring the app's read path.

    The read path ignores the per-frame CRC in byte 1 and instead acknowledges
    each fragment by writing a frame whose byte 2 holds the index just received.
    """
    buffer = bytearray(256)
    seen = 0
    for frame in frames:
        index = frame[0] >> 4
        total = frame[0] & 0x0F
        if index == 0:
            raise ValueError("controller signalled an error frame")
        body = frame[3:]
        buffer[(index - 1) * len(body):index * len(body)] = body
        seen = max(seen, index)
        if index == total:
            break
    size = buffer[HDR_PACKET_SIZE]
    return bytes(buffer[:size])


# --- Probe -------------------------------------------------------------------

async def scan(timeout: float) -> int:
    from bleak import BleakScanner

    print(f"Scanning for {timeout:.0f}s ...\n")
    devices = await BleakScanner.discover(timeout=timeout)
    if not devices:
        print("No BLE devices found. Is Bluetooth enabled and the controller in range?")
        return 1

    for device in sorted(devices, key=lambda d: d.address):
        name = device.name or "(no name)"
        print(f"  {device.address}  {name}")
    print("\nRun again with --address <addr> for the controller.")
    return 0


async def probe(address: str, timeout: float) -> int:
    from bleak import BleakClient

    print(f"Connecting to {address} ...")
    async with BleakClient(address, timeout=timeout) as client:
        print("Connected.\n")

        transport_found = False
        for service in client.services:
            print(f"service {service.uuid}  {service.description}")
            for char in service.characteristics:
                props = ",".join(char.properties)
                marker = ""
                if char.uuid.lower() == TRANSPORT_CHARACTERISTIC:
                    marker = "   <-- Zirconia packet transport"
                    transport_found = True
                elif char.uuid.lower() == PSK_CHARACTERISTIC:
                    marker = "   <-- TLS-PSK (WiFi path)"
                elif char.uuid.lower() == PIN_CODE_CHARACTERISTIC:
                    marker = "   <-- PIN"
                print(f"  char {char.uuid}  [{props}]{marker}")
            print()

        print("Device information:")
        for uuid, label in DEVICE_INFO_CHARACTERISTICS.items():
            try:
                raw = await client.read_gatt_char(uuid)
            except Exception:
                continue
            print(f"  {label}: {raw.decode('utf-8', 'replace').strip()}")

        print()
        if transport_found:
            print("Zirconia transport characteristic present -- this controller speaks the")
            print("packet protocol an integration would use. Next: establish the PIN.")
            return 0

        print("Zirconia transport characteristic NOT found.")
        print("Either this is not the Connect controller, or it uses a different family.")
        return 1


def selftest() -> int:
    """Verify the packet maths without hardware."""
    fixed = datetime(2026, 1, 1, tzinfo=timezone.utc)

    payload = user_override_payload(COMMAND_ZONE_SPEED_MODE, fan_speed=2, fan_mode=1,
                                    zone_id=0, timeout_sec=600)
    assert len(payload) == 8, payload
    assert payload == bytes([5, 2, 1, 0]) + struct.pack("<i", 600), payload.hex()

    packet = build_packet(110, payload, op_type=OP_TYPE_DATA_REQUEST, now=fixed)
    assert len(packet) == 18, len(packet)
    assert packet[HDR_PACKET_SIZE] == 18
    assert packet[HDR_PACKET_TYPE] == 110
    assert packet[HDR_OP_TYPE] == OP_TYPE_DATA_REQUEST
    assert packet[HDR_DESTINATION] == TARGET_CONTROLLER
    assert packet[HDR_CHECKSUM] == checksum(packet[1:])

    seconds = struct.unpack(">i", packet[HDR_TIMESTAMP:HDR_TIMESTAMP + 4])[0]
    assert seconds == int((fixed - EPOCH_2000).total_seconds()), seconds

    frames = fragment(packet)
    assert all(len(f) == 20 for f in frames), [len(f) for f in frames]
    assert frames[0][0] >> 4 == 1
    assert frames[-1][0] & 0x0F == len(frames)
    for frame in frames:
        assert frame[1] == checksum(frame[3:]), frame.hex()
    assert reassemble(frames) == packet

    big = build_packet(110, b"\x00" * 100, now=fixed)
    assert reassemble(fragment(big)) == big

    try:
        build_packet(110, b"\x00" * 200, now=fixed)
    except ValueError:
        pass
    else:
        raise AssertionError("oversized packet should have been rejected")

    print("selftest: packet build, checksum, fragmentation and reassembly OK")
    print(f"  sample USER_OVERRIDE packet: {packet.hex()}")
    for i, frame in enumerate(frames, start=1):
        print(f"  frame {i}/{len(frames)}: {frame.hex()}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scan", action="store_true", help="list nearby BLE devices")
    group.add_argument("--address", help="BLE address of the controller to probe")
    group.add_argument("--selftest", action="store_true",
                       help="verify the packet maths offline, no hardware needed")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="scan/connect timeout in seconds (default: 10)")
    args = parser.parse_args()

    if args.selftest:
        return selftest()

    try:
        if args.scan:
            return asyncio.run(scan(args.timeout))
        return asyncio.run(probe(args.address, args.timeout))
    except ImportError:
        print("bleak is not installed. Run: pip install bleak", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
