// SPDX-License-Identifier: GPL-2.0
//
// TC egress program: copy every outgoing frame into a BPF ring buffer so
// userspace can read it, then let the frame continue normally (TC_ACT_OK).
//
// Attached with bpf_tc_attach() to the egress hook of the named interface.

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

// Maximum frame size we will copy.  Frames larger than this are truncated.
#define MAX_FRAME 2048

// SKB mark used by the userspace AF_PACKET injection socket.  Frames carrying
// this mark were injected by us and must not be re-forwarded into the tunnel.
// Must match INJECTED_MARK in include/iface_capture.h.
#define INJECTED_MARK 0xFB01

// Per-CPU scratch buffer.  The BPF stack is limited to 512 bytes so we cannot
// keep a 2048-byte frame buffer there.  A per-CPU array gives us one slot per
// CPU with no lock contention.
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       __u8[MAX_FRAME]);
} scratch SEC(".maps");

// Ring buffer shared with userspace.  Sized at 2 MiB.
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21);   // 2 MiB
} ringbuf SEC(".maps");

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    // Skip frames injected by our AF_PACKET socket to prevent a loop.
    if (skb->mark == INJECTED_MARK)
        return TC_ACT_OK;

    __u32 key = 0;
    __u8 *buf = bpf_map_lookup_elem(&scratch, &key);
    if (!buf)
        goto out;

    __u32 len = skb->len;
    if (len > MAX_FRAME)
        len = MAX_FRAME;
    if (len == 0)
        goto out;

    if (bpf_skb_load_bytes(skb, 0, buf, len) != 0)
        goto out;

    // bpf_ringbuf_output copies buf[0..len-1] into the ring buffer.
    // The size argument may be a runtime value because the verifier can
    // confirm it is bounded by the MAX_FRAME clamp above.
    bpf_ringbuf_output(&ringbuf, buf, len, 0);

out:
    return TC_ACT_OK;   // always let the original packet through
}

char _license[] SEC("license") = "GPL";
