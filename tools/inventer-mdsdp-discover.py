#!/usr/bin/env python3
"""MDSDP discovery probe for inVENTer Connect / Volution WiFi controllers.

Sends the 8-byte MDSDP search message the inVENTer Mobile app broadcasts and
prints any announce replies. This is the fastest way to confirm that a WiFi
capable controller is reachable, before investing in the TLS-PSK work.

Usage:
    python3 inventer-mdsdp-discover.py [--broadcast 192.168.1.255] [--timeout 5]

See inventer-connect-reverse-engineering.md for the protocol notes this
implements.
"""

import argparse
import socket
import struct
import sys
import uuid

PORT = 47818
PROTO_ID = b"MDSDP"
MSG_SEARCH = 0x03
ANNOUNCE_V4_LEN = 94

DN_LEN = 64
DDN_LEN = 32
LOC_LEN = 32


def search_message(transaction_id: int) -> bytes:
    return PROTO_ID + struct.pack("<BH", MSG_SEARCH, transaction_id & 0xFFFF)


def decode_string(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()


def parse_announce(payload: bytes, sender: str) -> dict | None:
    """Best-effort parse of an announce reply.

    The field order follows the app's AnnounceV4 struct: protocol id, message
    type, transaction id, then the addressing and naming fields. Offsets are
    derived from decompiled code, not from a published spec, so unknown
    trailing bytes are reported rather than silently dropped.
    """
    if len(payload) < len(PROTO_ID) + 3 or not payload.startswith(PROTO_ID):
        return None

    body = payload[len(PROTO_ID) + 3:]
    if len(body) < 36:
        return None

    device_uuid = uuid.UUID(bytes=body[0:16])
    st_uuid = uuid.UUID(bytes=body[16:32])
    ipv4 = socket.inet_ntoa(body[32:36])

    rest = body[36:]
    names = {}
    for label, length in (("device_name", DN_LEN), ("domain", DDN_LEN), ("location", LOC_LEN)):
        if len(rest) >= length:
            names[label] = decode_string(rest[:length])
            rest = rest[length:]

    return {
        "sender": sender,
        "uuid": str(device_uuid),
        "service_type_uuid": str(st_uuid),
        "ipv4": ipv4,
        **names,
        "trailing_bytes": rest.hex() or None,
    }


def discover(broadcast: str, timeout: float) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)

    message = search_message(transaction_id=1)
    print(f"-> {broadcast}:{PORT}  {message.hex()}")
    sock.sendto(message, (broadcast, PORT))

    found = 0
    while True:
        try:
            payload, addr = sock.recvfrom(512)
        except socket.timeout:
            break

        print(f"\n<- {addr[0]}:{addr[1]}  {len(payload)} bytes")
        parsed = parse_announce(payload, addr[0])
        if parsed is None:
            print(f"   unrecognised payload: {payload.hex()}")
            continue

        found += 1
        for key, value in parsed.items():
            if value:
                print(f"   {key}: {value}")
        print(f"   next step: TLS-PSK to {parsed['ipv4']}:47820, identity '12345'")

    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--broadcast", default="255.255.255.255",
                        help="broadcast address to probe (default: 255.255.255.255)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="seconds to listen for replies (default: 5)")
    args = parser.parse_args()

    found = discover(args.broadcast, args.timeout)
    print(f"\n{found} controller(s) answered.")
    if not found:
        print("Try the subnet-specific broadcast address, e.g. --broadcast 192.168.1.255.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
