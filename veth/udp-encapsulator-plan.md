# UDP Encapsulator — Implementation Plan

## Top-Level Overview

Build a C++ command-line program (`udp-encap`) that tunnels raw IPv4 traffic between two
hosts over UDP.  The program opens an `AF_PACKET` raw socket bound to the fixed interface
`veth1` and a standard UDP socket on a configurable local port.  A single-threaded
`epoll` event loop multiplexes both sockets.

**Outbound path:** IP frames arriving on `veth1` (with their Ethernet MAC header) are
stripped of the MAC header and the raw IP payload is encapsulated in a UDP datagram that
is forwarded to the configured remote peer.

**Inbound path:** UDP datagrams arriving on the local UDP socket are treated as raw IP
payloads.  A synthetic Ethernet MAC header is prepended (source MAC = veth1 MAC,
destination MAC = veth1 MAC, EtherType = 0x0800) and the resulting frame is injected into
`veth1` via the `AF_PACKET` socket.

**Constraints / non-goals:**
- The program does not create or configure network interfaces.
- Only IPv4 traffic (EtherType 0x0800) is forwarded; other EtherTypes are silently dropped.
- No encryption or authentication of the UDP tunnel (DTLS to be added in a future iteration).
- The program installs SIGINT / SIGTERM handlers and shuts down cleanly.

---

## CLI Interface

```
udp-encap --peer-ip <IP> --peer-port <PORT> --local-port <PORT>
```

| Argument | Description |
|---|---|
| `--peer-ip` | IPv4 address of the remote peer |
| `--peer-port` | UDP port on the remote peer |
| `--local-port` | UDP port this instance listens on |

---

## Sub-Tasks

---

### Sub-Task 1 — Project Scaffolding

**Intent:** Create the CMake project structure and build system so that all subsequent
sub-tasks have a working compile/link environment.

**Expected Outcomes:**
- `CMakeLists.txt` at the project root targeting C++17.
- A single `src/main.cpp` stub that compiles and links cleanly.
- `cmake -B build && cmake --build build` produces the `udp-encap` binary.

**Todo List:**
1. Create `CMakeLists.txt` with `project(udp-encap CXX)`, `set(CMAKE_CXX_STANDARD 17)`,
   and an `add_executable` for `udp-encap` pointing at `src/main.cpp`.
2. Create `src/main.cpp` with a minimal `main()` that prints a startup message and
   returns 0.
3. Create a `.gitignore` that excludes the `build/` directory and editor artifacts.

**Relevant Context:** No existing code — greenfield project.

**Status:** [x] done

---

### Sub-Task 2 — CLI Argument Parsing

**Intent:** Parse and validate the three required command-line arguments so the rest of
the program can rely on typed, validated configuration values.

**Expected Outcomes:**
- A `Config` struct holding `peer_ip` (string), `peer_port` (uint16_t), and
  `local_port` (uint16_t).
- A `parse_args(int argc, char* argv[]) -> Config` function (or equivalent) that prints
  usage and exits with a non-zero code if arguments are missing or invalid.
- Unit-testable without any socket code.

**Todo List:**
1. Add a `Config` struct in `src/config.hpp`.
2. Implement `parse_args` in `src/config.cpp` using standard `getopt_long` or manual
   argv scanning (no third-party libraries).
3. Validate that `peer_port` and `local_port` are in the range 1–65535 and that
   `peer_ip` is a non-empty string (full IP validation happens implicitly when the
   socket is created).
4. Call `parse_args` from `main()` and print the resolved config at startup.

**Relevant Context:** Standard POSIX `getopt_long` from `<getopt.h>`.

**Status:** [x] done

---

### Sub-Task 3 — Raw AF_PACKET Socket (veth1)

**Intent:** Open and configure the `AF_PACKET` raw socket bound to `veth1` so that the
program can send and receive full Ethernet frames on that interface.

**Expected Outcomes:**
- A helper `open_raw_socket(const std::string& iface) -> int` that returns a file
  descriptor ready for `recvfrom` / `sendto` using `struct sockaddr_ll`.
- The socket captures all Ethernet frames (not just IP) — EtherType filtering is done
  in application code.
- The interface index and MAC address of `veth1` are resolved at startup via `SIOCGIFINDEX`
  and `SIOCGIFHWADDR` ioctls and stored for later use.

**Todo List:**
1. Create `src/raw_socket.hpp` / `src/raw_socket.cpp`.
2. In `open_raw_socket`: call `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`.
3. Use `ioctl(fd, SIOCGIFINDEX, &ifr)` to get the interface index for `veth1`.
4. `bind` the socket to a `sockaddr_ll` using the interface index and `ETH_P_ALL`.
5. Use `ioctl(fd, SIOCGIFHWADDR, &ifr)` to read and store the 6-byte MAC address of
   `veth1`.
6. Return the open fd; store the interface index and MAC in a shared context struct.

**Relevant Context:** `<linux/if_packet.h>`, `<net/ethernet.h>`, `<sys/ioctl.h>`,
`<net/if.h>`.

**Status:** [x] done

---

### Sub-Task 4 — UDP Socket

**Intent:** Open the local UDP socket that receives encapsulated IP payloads from the
remote peer and is also used to send encapsulated payloads to the peer.

**Expected Outcomes:**
- A helper `open_udp_socket(uint16_t local_port) -> int` that returns a bound,
  non-blocking UDP file descriptor.
- The peer address (`peer_ip`, `peer_port`) is resolved into a `sockaddr_in` at startup
  and stored for use by the send path.

**Todo List:**
1. Create `src/udp_socket.hpp` / `src/udp_socket.cpp`.
2. In `open_udp_socket`: call `socket(AF_INET, SOCK_DGRAM, 0)`, bind to
   `0.0.0.0:<local_port>`.
3. Set the socket non-blocking with `fcntl(fd, F_SETFL, O_NONBLOCK)`.
4. Resolve the peer address using `inet_pton` and store as a `sockaddr_in`.
5. Return the open fd.

**Relevant Context:** `<arpa/inet.h>`, `<sys/socket.h>`, `<fcntl.h>`.

**Status:** [x] done

---

### Sub-Task 5 — Outbound Path (veth1 → UDP peer)

**Intent:** Implement the logic that reads an Ethernet frame from `veth1`, validates it
is IPv4, strips the 14-byte MAC header, and sends the raw IP payload to the remote peer
via UDP.

**Expected Outcomes:**
- A function `handle_raw_input(int raw_fd, int udp_fd, const sockaddr_in& peer)` that
  performs one read/send cycle.
- Frames with EtherType != 0x0800 are silently discarded.
- Frames shorter than 14 bytes (Ethernet header) + 1 byte (minimum IP) are discarded.
- The IP payload (everything after the 14-byte Ethernet header) is sent as a single UDP
  datagram to the peer.

**Todo List:**
1. In `handle_raw_input`, call `recvfrom` on the raw fd into a buffer sized for the MTU
   (MTU-sized, 1500 bytes).
2. Check `ntohs(eth_header->ether_type) == ETH_P_IP`; drop if not.
3. Compute `ip_payload = buffer + sizeof(ethhdr)` and
   `ip_len = received_bytes - sizeof(ethhdr)`.
4. Call `sendto` on the UDP fd with `ip_payload` / `ip_len` targeting the peer
   `sockaddr_in`.

**Relevant Context:** `struct ethhdr` from `<linux/if_ether.h>`.

**Status:** [x] done

---

### Sub-Task 6 — Inbound Path (UDP peer → veth1)

**Intent:** Implement the logic that reads a UDP datagram (raw IP payload) from the UDP
socket, prepends a synthetic Ethernet MAC header, and injects the resulting frame into
`veth1` via the raw socket.

**Expected Outcomes:**
- A function `handle_udp_input(int udp_fd, int raw_fd, int iface_index, const uint8_t mac[6])`
  that performs one read/send cycle.
- The MAC header uses the veth1 MAC as both source and destination, and EtherType
  0x0800.
- The assembled frame is sent via `sendto` on the raw fd using `sockaddr_ll` addressing.

**Todo List:**
1. In `handle_udp_input`, call `recvfrom` on the UDP fd into a buffer offset by
   `sizeof(ethhdr)` bytes so there is room for the header in-place.
2. Build an `ethhdr` at the start of the buffer: copy veth1 MAC into both
   `h_dest` and `h_source`, set `h_proto = htons(ETH_P_IP)`.
3. Construct a `sockaddr_ll` with `sll_ifindex = iface_index`,
   `sll_halen = ETH_ALEN`, and `sll_addr` set to the veth1 MAC.
4. Call `sendto` on the raw fd with the full frame (header + IP payload).

**Relevant Context:** `struct ethhdr` from `<linux/if_ether.h>`,
`struct sockaddr_ll` from `<linux/if_packet.h>`.

**Status:** [x] done

---

### Sub-Task 7 — epoll Event Loop and Signal Handling

**Intent:** Wire both sockets into a single-threaded `epoll` event loop and install
SIGINT / SIGTERM handlers so the program runs indefinitely and shuts down cleanly.

**Expected Outcomes:**
- Both the raw fd and the UDP fd are registered with `EPOLLIN` in an `epoll` instance.
- The loop calls the correct handler function depending on which fd is readable.
- A `volatile sig_atomic_t g_running` flag is set to 0 by the signal handler; the loop
  exits when the flag is cleared.
- Both sockets are closed before `main` returns.

**Todo List:**
1. Install signal handlers for `SIGINT` and `SIGTERM` using `sigaction` that set
   `g_running = 0`.
2. Create an `epoll` fd with `epoll_create1(0)`.
3. Register the raw fd and UDP fd with `EPOLL_CTL_ADD` / `EPOLLIN`.
4. Loop: call `epoll_wait` with a short timeout (e.g. 500 ms) so the `g_running` check
   fires promptly.
5. On each ready event dispatch to `handle_raw_input` or `handle_udp_input`.
6. On loop exit, call `close` on both socket fds and the epoll fd.

**Relevant Context:** `<sys/epoll.h>`, `<signal.h>`.

**Status:** [x] done

---

## File Layout

```
udp-encap/
├── CMakeLists.txt
├── .gitignore
└── src/
    ├── main.cpp
    ├── config.hpp
    ├── config.cpp
    ├── raw_socket.hpp
    ├── raw_socket.cpp
    ├── udp_socket.hpp
    ├── udp_socket.cpp
    └── handlers.cpp      (outbound + inbound path functions)
```
