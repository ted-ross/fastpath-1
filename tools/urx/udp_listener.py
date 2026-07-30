#!/usr/bin/env python3
"""UDP listener — prints packet length and hex dump of every received datagram."""

import argparse
import socket
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
            print(hex_dump(data))
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
