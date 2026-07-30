# FastPath-1 Prototype

A raw-IP-over-UDP tunnel that uses a TC egress BPF program and a BPF ring
buffer to forward traffic between a named network interface and a remote UDP
endpoint.

```
local process → interface (egress) → TC BPF → BPF ring buffer
                                                      │
                                               C++ poll loop
                                                      │
                                           UDP send socket → remote host:port

remote host:port → UDP recv socket
                          │
                    C++ poll loop
                          │
              AF_PACKET SOCK_RAW sendto() → interface (layer-2 inject)
```

## How it works

1. A TC egress BPF program is attached to the named interface at startup using
   `bpf_tc_attach()` on the `BPF_TC_EGRESS` hook (clsact qdisc).
2. Every frame leaving the interface is copied into a `BPF_MAP_TYPE_RINGBUF`.
   The original packet continues normally (`TC_ACT_OK`).
3. The userspace poll loop reads frames from the ring buffer via
   `ring_buffer__consume()` and wraps each one in a UDP datagram sent to the
   configured remote endpoint.
4. UDP datagrams arriving on the configured receive port are injected back into
   the interface as raw layer-2 frames via an `AF_PACKET SOCK_RAW` socket.

## Prerequisites

| Requirement | Minimum version |
|---|---|
| Linux kernel | 5.15 |
| clang | 12 |
| libbpf-devel | 1.0 |
| cmake | 3.16 |
| g++ | 10 (C++20) |

On Fedora / RHEL:
```bash
sudo dnf install clang libbpf-devel cmake gcc-c++ elfutils-libelf-devel zlib-devel
```

On Debian / Ubuntu:
```bash
sudo apt install clang libbpf-dev cmake g++ libelf-dev zlib1g-dev
```

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The build produces:
- `build/dataplane`      — userspace binary
- `build/xdp_prog.bpf.o` — eBPF object (path is compiled into the binary via
  `BPF_OBJ_PATH`; must exist at that path when the binary runs)

## Usage

```
./build/dataplane \
    --iface    <interface>   \   # e.g. eth0, ens3
    --dest-host <ip-or-host> \   # remote tunnel endpoint IP
    --dest-port <port>       \   # remote tunnel endpoint UDP port
    --recv-port <port>           # local UDP port to receive tunnel traffic
```

The binary must be run as **root** (or with `CAP_NET_ADMIN` + `CAP_BPF` +
`CAP_NET_RAW`) to attach a TC BPF program and use `AF_PACKET`.

### Example

**Node A** (192.168.1.10) — sends interface traffic to Node B:
```bash
sudo ./build/dataplane \
    --iface eth0 \
    --dest-host 192.168.1.20 \
    --dest-port 4789 \
    --recv-port 4789
```

**Node B** (192.168.1.20) — mirrors the setup back to Node A:
```bash
sudo ./build/dataplane \
    --iface eth0 \
    --dest-host 192.168.1.10 \
    --dest-port 4789 \
    --recv-port 4789
```

## Local test

The TC egress hook fires on any traffic *sent out through* the interface,
including traffic from local processes.

```bash
# Bring up a loopback-style interface (or use an existing one)
sudo ip link set lo up

# Run dataplane on lo — captures all egress traffic on loopback
sudo ./build/dataplane \
    --iface lo \
    --dest-host 127.0.0.1 \
    --dest-port 5000 \
    --recv-port 5001 &

# In another terminal: generate some egress traffic
ping -I lo 127.0.0.1 -c 3

# Inspect UDP tunnel traffic with tcpdump
sudo tcpdump -i lo udp port 5000 -v

# Tear down: Ctrl+C on the dataplane process detaches the TC filter cleanly
```

## Architecture notes

- **TC egress hook**: the BPF program runs on every frame leaving the interface,
  regardless of whether it originated from a local process or was forwarded.
  The original packet always continues (`TC_ACT_OK`) — the program is observe-
  only.
- **Ring buffer**: `BPF_MAP_TYPE_RINGBUF` (1 MiB). If the ring fills faster
  than userspace drains it, frames are silently dropped on the BPF side. The
  ring size can be increased in `bpf/xdp_prog.bpf.c` (`max_entries`).
- **TX injection**: outbound frames from the UDP tunnel are injected via
  `AF_PACKET SOCK_RAW sendto()` with a `sockaddr_ll`. The full Ethernet frame
  (including the destination MAC) must be present in the UDP payload.
- **No feedback filter**: egress frames from the injected AF_PACKET traffic will
  also be captured by the TC hook. Avoid routing the tunnel traffic back through
  the same interface to prevent loops.
- **TC attachment**: `BPF_TC_F_REPLACE` is used so restarting the process
  replaces any previously attached filter cleanly.

## Security

The application requires elevated privileges to:
- Attach an eBPF XDP program to a network interface (`CAP_NET_ADMIN`).
- Load a BPF program into the kernel (`CAP_BPF`, kernel ≥ 5.8; root on older).
- Set `RLIMIT_MEMLOCK` to unlimited for the UMEM `mmap`.

Run in a dedicated network namespace or container where possible.
