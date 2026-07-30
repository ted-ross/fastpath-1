# Dataplane Tunnel Application — Plan

## Top-Level Overview

Build a C++ userspace application that bridges a raw network interface to a UDP tunnel using
XDP and AF_XDP zero-copy sockets. Ingress IP packets on a named interface are captured via an
XDP eBPF program that redirects frames into an AF_XDP socket. The userspace application reads
those frames from the AF_XDP RX ring and wraps each one in a UDP datagram sent to a configured
remote host:port. In the other direction, UDP datagrams arriving on a configured local receive
port are unwrapped and the raw IP payload is injected back into the interface via the AF_XDP TX
ring, which the XDP program forwards to the wire.

All memory between the kernel and userspace is shared via a UMEM region (zero-copy). No kernel
packet copies occur on the data path.

---

## Architecture Summary

```
NIC (ingress) --> XDP eBPF (XDP_REDIRECT) --> AF_XDP RX ring
                                                     |
                                              C++ poll loop
                                                     |
                                           UDP Send Socket --> remote host:port

remote host:port --> UDP Recv Socket
                           |
                      C++ poll loop
                           |
                   AF_XDP TX ring --> NIC (egress)
```

---

## Sub-Tasks

---

### Sub-Task 1 — Project Scaffolding and Build System

**Status:** [ ] pending

**Intent:**
Set up the CMake-based project structure, directory layout, and toolchain configuration so that
both the C++ userspace binary and the eBPF kernel program can be compiled from a single build
invocation.

**Expected Outcomes:**
- `CMakeLists.txt` at the project root builds the userspace binary and compiles the eBPF `.bpf.c`
  file to a `.o` object using clang BPF target.
- `libbpf` is located and linked (via pkg-config or a vendored submodule).
- A `cmake --build` produces both artifacts without errors on a modern Linux host with clang and
  libbpf-dev installed.

**Todo List:**
1. Create the top-level directory layout:
   - `src/` — C++ userspace sources
   - `bpf/` — eBPF kernel program sources
   - `include/` — shared headers (e.g. UMEM layout constants)
2. Write `CMakeLists.txt`:
   - Set `CMAKE_CXX_STANDARD 20`.
   - Add a custom command to compile `bpf/xdp_prog.bpf.c` with `clang -target bpf -O2 -g`
     producing `xdp_prog.bpf.o`.
   - Find `libbpf` via `pkg_check_modules` or `find_library`.
   - Define the userspace executable target, link against `libbpf`, `libelf`, `libz`.
3. Add a minimal placeholder `src/main.cpp` and `bpf/xdp_prog.bpf.c` so the build resolves.
4. Verify `cmake -S . -B build && cmake --build build` succeeds.

**Relevant Context:**
- eBPF object compilation requires `clang` with BPF target support (`clang -target bpf`).
- `libbpf` provides `bpf/libbpf.h`, `bpf/xsk.h` (AF_XDP helpers), and `bpf/bpf.h`.
- The eBPF `.o` file path must be known at runtime; embed it as a compile-time define or place
  it alongside the binary.

---

### Sub-Task 2 — CLI Argument Parsing

**Status:** [ ] pending

**Intent:**
Parse the four required CLI arguments and expose them as a typed configuration struct used by
the rest of the application.

**Expected Outcomes:**
- Running `./dataplane --help` prints usage with all four flags.
- All four arguments are required; missing any one exits with a clear error message.
- A `Config` struct is populated and accessible from `main`.

**Arguments:**
| Flag | Type | Description |
|---|---|---|
| `--iface` | string | Name of the network interface to attach XDP to |
| `--dest-host` | string | Remote tunnel endpoint IP address |
| `--dest-port` | uint16 | Remote tunnel endpoint UDP port |
| `--recv-port` | uint16 | Local UDP port to receive tunnel traffic on |

**Todo List:**
1. Add a lightweight CLI parsing approach using `getopt_long` (no external library needed).
2. Define `struct Config` in `include/config.h`.
3. Implement `Config parse_args(int argc, char** argv)` in `src/config.cpp`.
4. Call `parse_args` early in `main` and validate all fields are non-empty/non-zero.

**Relevant Context:**
- No third-party CLI library is required; `getopt_long` from `<getopt.h>` is standard on Linux.

---

### Sub-Task 3 — eBPF XDP Program

**Status:** [ ] pending

**Intent:**
Write the XDP kernel program that runs at the NIC driver level and redirects all ingress IP
frames into an AF_XDP socket using `bpf_redirect_map`. This is the zero-copy ingress path.

**Expected Outcomes:**
- `bpf/xdp_prog.bpf.c` compiles cleanly to `xdp_prog.bpf.o`.
- The program redirects every ingress frame to the AF_XDP socket map entry for queue 0.
- Frames that cannot be redirected (map lookup miss) are passed through normally (`XDP_PASS`).
- The program exports one BPF map: an `XSKMAP` named `xsk_map` with one entry (queue index 0).

**Todo List:**
1. Write `bpf/xdp_prog.bpf.c`:
   - Include `<linux/bpf.h>` and `<bpf/bpf_helpers.h>`.
   - Define an `XSKMAP` named `xsk_map` with `max_entries = 1`.
   - Implement `SEC("xdp") int xdp_prog(struct xdp_md *ctx)` that calls
     `bpf_redirect_map(&xsk_map, 0, XDP_PASS)` and returns the result.
   - Add `char _license[] SEC("license") = "GPL";`.
2. Verify the `.bpf.c` compiles with `clang -target bpf -O2 -g` without warnings.

**Relevant Context:**
- `bpf_redirect_map` with `XDP_PASS` as the fallback flag means frames pass through normally if
  the AF_XDP socket is not yet registered in the map, which is safe during startup.
- Queue index is hardcoded to 0; this application uses a single queue.

---

### Sub-Task 4 — AF_XDP Socket and UMEM Setup

**Status:** [ ] pending

**Intent:**
Implement the AF_XDP socket layer in C++: allocate the UMEM region, create the XDP socket,
configure the fill/completion/rx/tx rings, load and attach the XDP program, and insert the
socket file descriptor into the `xsk_map`.

**Expected Outcomes:**
- A C++ class or struct `XskSocket` encapsulates the UMEM and socket lifecycle.
- On construction it loads `xdp_prog.bpf.o`, attaches it to the named interface, and registers
  the AF_XDP socket fd in the `xsk_map` at index 0.
- On destruction it detaches the XDP program and closes all file descriptors.
- The RX ring can be polled; frames read from it contain raw Ethernet frames as received.
- The TX ring can be submitted with raw Ethernet frames to transmit.

**Todo List:**
1. Create `include/xsk_socket.h` and `src/xsk_socket.cpp`.
2. Define constants: `UMEM_SIZE` (e.g. 4096 frames × 2048 bytes/frame = 8 MiB), `FRAME_SIZE`
   (2048), `NUM_FRAMES` (4096), `RING_SIZE` (2048).
3. Implement UMEM allocation:
   - `mmap` anonymous memory of `UMEM_SIZE`.
   - Call `xsk_umem__create` to register the memory region with the kernel.
4. Implement socket creation:
   - Call `xsk_socket__create` with interface name, queue 0, and the UMEM handle.
   - Retrieve the fill ring, completion ring, RX ring, and TX ring handles.
5. Populate the fill ring with all free UMEM frame addresses on startup.
6. Load the BPF object file using `bpf_object__open_file` / `bpf_object__load`.
7. Attach the XDP program to the interface using `bpf_xdp_attach` (flag `XDP_FLAGS_SKB_MODE`
   as fallback if the driver does not support native XDP).
8. Find the `xsk_map` via `bpf_object__find_map_by_name` and insert the AF_XDP socket fd with
   `bpf_map_update_elem`.
9. Expose `receive_batch` and `send_batch` methods for the main poll loop.

**Relevant Context:**
- `xsk_socket__create`, `xsk_umem__create` and ring accessor macros are in `<bpf/xsk.h>`.
- `bpf_xdp_attach` / `bpf_xdp_detach` are in `<bpf/bpf.h>` (libbpf ≥ 0.7).
- The fill ring must be pre-populated or the kernel will have no frames to fill RX with.
- `XDP_FLAGS_SKB_MODE` ensures compatibility on virtual/veth interfaces (e.g. for testing).

---

### Sub-Task 5 — UDP Send and Receive Sockets

**Status:** [ ] pending

**Intent:**
Create the two UDP sockets: one to send tunnel datagrams to the remote endpoint, and one to
receive tunnel datagrams on the local configured port.

**Expected Outcomes:**
- A `UdpSender` object wraps a `SOCK_DGRAM` socket pre-configured with the remote address.
- A `UdpReceiver` object wraps a `SOCK_DGRAM` socket bound to `0.0.0.0:<recv-port>`.
- Both are non-blocking.
- `UdpSender::send(const uint8_t* data, size_t len)` sends a UDP datagram.
- `UdpReceiver::fd()` returns the socket fd for use in `poll`/`epoll`.
- `UdpReceiver::recv(uint8_t* buf, size_t buflen)` returns the number of bytes read.

**Todo List:**
1. Create `include/udp_socket.h` and `src/udp_socket.cpp`.
2. Implement `UdpSender`:
   - `socket(AF_INET, SOCK_DGRAM, 0)`.
   - `connect` to the remote host:port (resolves hostname via `getaddrinfo`).
   - `fcntl` to set `O_NONBLOCK`.
3. Implement `UdpReceiver`:
   - `socket(AF_INET, SOCK_DGRAM, 0)`.
   - `bind` to `0.0.0.0:<recv-port>`.
   - `fcntl` to set `O_NONBLOCK`.

**Relevant Context:**
- Using `connect` on a UDP socket allows `send()` / `write()` without specifying the address
  each time, which is idiomatic and avoids per-call `sendto` overhead.
- Binding to `127.0.0.1` is not used here because the tunnel receive port may receive from a
  remote host; `0.0.0.0` is required.

---

### Sub-Task 6 — Main Poll Loop

**Status:** [ ] pending

**Intent:**
Implement the central event loop in `main` that ties the AF_XDP socket and UDP sockets together,
forwarding traffic in both directions.

**Expected Outcomes:**
- The loop uses `poll(2)` (or `epoll`) on the AF_XDP socket fd and the UDP receive socket fd.
- When the AF_XDP RX ring has frames, each frame's raw bytes are sent as a UDP datagram via
  `UdpSender`.
- When the UDP receive socket has data, the raw payload bytes are injected into the AF_XDP TX
  ring to be transmitted on the interface.
- The loop runs until `SIGINT` or `SIGTERM` is received.
- Frame buffers are recycled: RX frames are returned to the fill ring after being sent; TX
  completion ring entries are returned to the free pool.

**Todo List:**
1. In `src/main.cpp`, after parsing config and constructing `XskSocket`, `UdpSender`, and
   `UdpReceiver`, enter the poll loop.
2. Build a `pollfd` array: `[xsk_fd, udp_recv_fd]` both with `POLLIN`.
3. On `xsk_fd` readable:
   a. Call `receive_batch` to get a list of `(addr, len)` pairs from the RX ring.
   b. For each frame, call `UdpSender::send(umem_base + addr, len)`.
   c. Return all consumed addresses back to the fill ring.
4. On `udp_recv_fd` readable:
   a. Call `UdpReceiver::recv` into a temporary buffer.
   b. Copy the raw bytes into an available UMEM TX frame slot.
   c. Submit the frame to the TX ring via the XDP socket's `sendmsg`/`kick` mechanism.
   d. Drain the TX completion ring to reclaim used frame addresses.
5. Install `SIGINT`/`SIGTERM` handlers that set an `std::atomic<bool> running = false`.
6. On loop exit, call destructors to detach XDP and close sockets.

**Relevant Context:**
- AF_XDP sockets require a "kick" (`sendmsg` with no data, or `xsk_ring_prod__needs_wakeup`)
  to wake the kernel TX path on some drivers.
- The fill ring must be kept populated; if it runs empty the kernel drops incoming packets.
- The completion ring must be drained regularly to return TX frame slots to userspace.

---

### Sub-Task 7 — Integration Testing and README

**Status:** [ ] pending

**Intent:**
Verify the application builds and runs correctly in a loopback test environment, and document
how to build and use it.

**Expected Outcomes:**
- `README.md` explains prerequisites, build steps, and a sample invocation.
- A manual test procedure using a `veth` pair or loopback is documented.
- The binary accepts `--help` and prints usage cleanly.

**Todo List:**
1. Write `README.md` covering:
   - Prerequisites: Linux kernel ≥ 5.10, clang ≥ 12, libbpf-dev, cmake ≥ 3.16.
   - Build instructions: `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build`.
   - Usage example with all four CLI flags.
   - Note that the binary requires `CAP_NET_ADMIN` / running as root to attach XDP programs.
   - Simple loopback test using a `veth` pair.
2. Confirm the binary links and launches without crashing on `--help`.
