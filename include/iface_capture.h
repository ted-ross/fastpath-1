#pragma once

#include <bpf/libbpf.h>

#include <cstdint>
#include <functional>
#include <string>

// ── IfaceCapture ──────────────────────────────────────────────────────────────
//
// Attaches a TC egress BPF program to a named TUN interface that copies every
// outgoing IP packet into a BPF ring buffer.  Userspace reads frames via the
// ring_buffer consumer callback.  Packets are injected into the kernel IP
// stack by writing to the TUN fd (ingress path — no copy overhead on egress).
//
class IfaceCapture {
public:
    // frame_cb is called for every captured egress frame.
    using FrameCallback = std::function<void(const uint8_t* data, uint32_t len)>;

    IfaceCapture(const std::string& iface,
                 const std::string& bpf_obj_path,
                 FrameCallback      frame_cb);
    ~IfaceCapture();

    // epoll-compatible fd that becomes readable when the ring buffer has data.
    int epoll_fd() const;

    // Consume all available ring-buffer entries, invoking frame_cb for each.
    // Returns the number of frames consumed, or a negative libbpf error code.
    int consume();

    // Inject a raw Ethernet frame into the interface (layer-2 TX).
    // Returns true on success.
    bool send_frame(const uint8_t* data, uint32_t len);

private:
    std::string    iface_;
    int            ifindex_  = -1;
    int            tun_fd_   = -1;   // /dev/net/tun fd for ingress injection

    struct bpf_object*   obj_      = nullptr;
    struct ring_buffer*  ringbuf_  = nullptr;

    // TC hook tracking (for cleanup)
    bool           tc_hook_created_ = false;

    static int ringbuf_cb(void* ctx, void* data, size_t size);
    FrameCallback  frame_cb_;
};
