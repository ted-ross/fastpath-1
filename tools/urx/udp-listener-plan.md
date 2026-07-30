# UDP Listener — Plan

## Top-Level Overview

Create a single-file Python CLI program (`udp_listener.py`) that:
1. Accepts a UDP port number as a positional CLI argument.
2. Binds a UDP (datagram) socket to that port on localhost.
3. Loops forever, receiving datagrams and printing the packet length and a formatted hex dump of each packet's contents.

No external dependencies — standard library only (`socket`, `argparse`).

---

## Sub-Tasks

### Sub-Task 1 — CLI argument parsing

**Intent**
Accept a single positional argument `port` from the command line and validate it is a valid port number (1–65535). Exit with a helpful message on bad input.

**Expected Outcomes**
- Running `python udp_listener.py 9000` yields a parsed integer port `9000`.
- Running with no argument or an invalid value prints a usage error and exits non-zero.

**Todo List**
1. Use `argparse.ArgumentParser` with a positional `port` argument typed as `int`.
2. After parsing, validate `1 <= port <= 65535`; if not, call `parser.error()`.

**Relevant Context**
- Standard library: `argparse`

**Status** — `[ ] pending`

---

### Sub-Task 2 — UDP socket setup

**Intent**
Open a UDP socket bound to `127.0.0.1` on the parsed port. Per security policy the socket must bind to `localhost` (127.0.0.1), not `0.0.0.0`.

**Expected Outcomes**
- Socket is created with `SOCK_DGRAM` and bound to `('127.0.0.1', port)`.
- A startup message is printed: `Listening on UDP 127.0.0.1:<port>`.
- If the bind fails (e.g. port in use), the OS exception is printed and the program exits with a non-zero code.

**Todo List**
1. Create `socket.socket(socket.AF_INET, socket.SOCK_DGRAM)`.
2. Wrap bind in a `try/except OSError` to print a clear error and `sys.exit(1)`.
3. Print the listening message after a successful bind.

**Relevant Context**
- Standard library: `socket`, `sys`
- Security rule: bind to `127.0.0.1`, not `0.0.0.0`

**Status** — `[ ] pending`

---

### Sub-Task 3 — Receive loop and hex dump formatter

**Intent**
Loop forever calling `recvfrom` on the socket. For each received datagram, print:
- The sender address and packet length.
- A canonical hex dump (offset | hex bytes | ASCII representation), matching the style of tools like `xxd` or Wireshark's hex view.

**Expected Outcomes**
- Each received datagram produces output like:
  ```
  Received 14 bytes from ('127.0.0.1', 52301)
  0000  48 65 6c 6c 6f 2c 20 57  6f 72 6c 64 21 0a        Hello, World!.
  ```
- Non-printable bytes in the ASCII column are shown as `.`.
- The loop handles `KeyboardInterrupt` gracefully (prints a short message and exits cleanly).

**Todo List**
1. Set a reasonable `recvfrom` buffer size (e.g. 65535 bytes to accommodate the largest valid UDP payload).
2. Implement `hex_dump(data: bytes) -> str` that formats 16-byte rows with:
   - 4-digit hex offset
   - Two groups of 8 hex bytes separated by two spaces
   - ASCII column with `.` for non-printable characters
3. Print length + sender info, then call `hex_dump` and print the result.
4. Wrap the loop in `try/except KeyboardInterrupt`.

**Relevant Context**
- Standard library: `socket`

**Status** — `[ ] pending`

---

## Non-Goals

- No TLS/encryption (this is a local debugging tool, bound to loopback).
- No IPv6 support in this iteration.
- No output to file — stdout only.
