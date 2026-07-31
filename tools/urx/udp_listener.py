#!/usr/bin/env python3
"""UDP listener — prints packet length and hex dump of every received datagram.

Each received UDP payload is assumed to be an encapsulated IPv4 datagram.
parse_packet() decodes and displays the inner IP header and transport layer.
"""

import argparse
import socket
import struct
import sys


def parse_args() -> int:
    parser = argparse.ArgumentParser(
        description="Listen on a UDP port and hex-dump received datagrams."
    )
    parser.add_argument("port", type=int, help="UDP port to listen on (1-65535)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error(f"port must be between 1 and 65535, got {args.port}")
    return args.port


def hex_dump(data: bytes) -> str:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        left = chunk[:8]
        right = chunk[8:]
        hex_left = " ".join(f"{b:02x}" for b in left).ljust(23)
        hex_right = " ".join(f"{b:02x}" for b in right).ljust(23)
        ascii_col = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_left}  {hex_right}  {ascii_col}")
    return "\n".join(lines)


# Symbolic names for well-known IP protocols
_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

# TCP flag bit masks and their display labels (checked high-to-low)
_TCP_FLAGS = [
    (0x100, "NS"),
    (0x080, "CWR"),
    (0x040, "ECE"),
    (0x020, "URG"),
    (0x010, "ACK"),
    (0x008, "PSH"),
    (0x004, "RST"),
    (0x002, "SYN"),
    (0x001, "FIN"),
]


def parse_packet(data: bytes) -> str:
    """Decode an IPv4 datagram carried as the UDP payload and return a summary.

    Decodes:
      - IP source and destination addresses
      - IP protocol number (with name for ICMP/TCP/UDP)
      - TCP/UDP source and destination ports
      - TCP flags (when protocol is TCP)
    """
    if len(data) < 20:
        return f"[too short for IPv4 header: {len(data)} bytes]"

    ihl = (data[0] & 0x0F) * 4   # IP header length in bytes
    proto_num = data[9]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    proto_name = _PROTO_NAMES.get(proto_num, f"proto={proto_num}")

    transport = data[ihl:]

    if proto_num == 6:  # TCP
        if len(transport) < 20:
            return f"{src_ip} -> {dst_ip}  {proto_name}  [truncated TCP header]"
        src_port, dst_port, _, _, data_off_flags = struct.unpack_from("!HHIIH", transport)
        flags = data_off_flags & 0x1FF
        flag_str = "|".join(name for mask, name in _TCP_FLAGS if flags & mask) or "none"
        return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}  {proto_name}  flags=[{flag_str}]"

    if proto_num == 17:  # UDP
        if len(transport) < 4:
            return f"{src_ip} -> {dst_ip}  {proto_name}  [truncated UDP header]"
        src_port, dst_port = struct.unpack_from("!HH", transport)
        return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}  {proto_name}"

    return f"{src_ip} -> {dst_ip}  {proto_name}"


def main() -> None:
    port = parse_args()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", port))
    except OSError as exc:
        print(f"Error: could not bind to 127.0.0.1:{port} — {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Listening on UDP 127.0.0.1:{port}")

    try:
        while True:
            data, addr = sock.recvfrom(65535)
            print(f"\nReceived {len(data)} bytes from {addr}")
            print(parse_packet(data))
#            print(hex_dump(data))
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
