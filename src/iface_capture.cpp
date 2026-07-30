#include "iface_capture.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>

static void ic_throw(const std::string& msg, int err = errno)
{
    throw std::runtime_error(msg + ": " + std::strerror(err));
}

// ── Constructor ──────────────────────────────────────────────────────────────

IfaceCapture::IfaceCapture(const std::string& iface,
                           const std::string& bpf_obj_path,
                           FrameCallback      frame_cb)
    : iface_(iface), frame_cb_(std::move(frame_cb))
{
    ifindex_ = static_cast<int>(if_nametoindex(iface.c_str()));
    if (ifindex_ == 0)
        ic_throw("if_nametoindex(" + iface + ")");

    // ── Load BPF object ───────────────────────────────────────────────────────
    obj_ = bpf_object__open_file(bpf_obj_path.c_str(), nullptr);
    if (!obj_)
        ic_throw("bpf_object__open_file(" + bpf_obj_path + ")");

    if (bpf_object__load(obj_) != 0) {
        bpf_object__close(obj_);
        obj_ = nullptr;
        ic_throw("bpf_object__load");
    }

    // ── Find the tc_egress program ─────────────────────────────────────────────
    struct bpf_program* prog =
        bpf_object__find_program_by_name(obj_, "tc_egress");
    if (!prog)
        throw std::runtime_error(
            "BPF program 'tc_egress' not found in " + bpf_obj_path);

    int prog_fd = bpf_program__fd(prog);

    // ── Create TC clsact qdisc and attach egress filter ────────────────────────
    LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex      = ifindex_,
        .attach_point = BPF_TC_EGRESS,
    );

    // bpf_tc_hook_create returns -EEXIST if clsact is already present — that
    // is fine, we just reuse the existing one.
    int ret = bpf_tc_hook_create(&hook);
    if (ret != 0 && ret != -EEXIST)
        ic_throw("bpf_tc_hook_create", -ret);
    tc_hook_created_ = (ret == 0);

    LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = prog_fd,
        .flags   = BPF_TC_F_REPLACE,
    );
    ret = bpf_tc_attach(&hook, &opts);
    if (ret != 0)
        ic_throw("bpf_tc_attach", -ret);

    // ── Set up ring buffer consumer ────────────────────────────────────────────
    struct bpf_map* map = bpf_object__find_map_by_name(obj_, "ringbuf");
    if (!map)
        throw std::runtime_error("BPF map 'ringbuf' not found in " + bpf_obj_path);

    ringbuf_ = ring_buffer__new(bpf_map__fd(map), ringbuf_cb, this, nullptr);
    if (!ringbuf_)
        ic_throw("ring_buffer__new");

    // ── AF_PACKET raw socket for layer-2 TX injection ─────────────────────────
    raw_fd_ = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
    if (raw_fd_ < 0)
        ic_throw("socket(AF_PACKET)");

    // Bind to the named interface so sendto() with a null address works via
    // send() after binding.  We use sendto with a sockaddr_ll instead.
    // (No bind needed for TX-only use with sendto.)
}

// ── Destructor ───────────────────────────────────────────────────────────────

IfaceCapture::~IfaceCapture()
{
    if (raw_fd_ >= 0) close(raw_fd_);

    if (ringbuf_) ring_buffer__free(ringbuf_);

    // Detach the TC filter and optionally destroy the clsact qdisc.
    if (obj_) {
        LIBBPF_OPTS(bpf_tc_hook, hook,
            .ifindex      = ifindex_,
            .attach_point = BPF_TC_EGRESS,
        );
        LIBBPF_OPTS(bpf_tc_opts, opts);
        bpf_tc_detach(&hook, &opts);

        if (tc_hook_created_) {
            // Only destroy the qdisc if we created it, to avoid removing one
            // that pre-existed (e.g. from another program).
            hook.attach_point =
                static_cast<bpf_tc_attach_point>(BPF_TC_INGRESS | BPF_TC_EGRESS);
            bpf_tc_hook_destroy(&hook);
        }

        bpf_object__close(obj_);
    }
}

// ── Ring buffer glue ──────────────────────────────────────────────────────────

// Static trampoline: libbpf calls this; we forward to the instance callback.
int IfaceCapture::ringbuf_cb(void* ctx, void* data, size_t size)
{
    auto* self = static_cast<IfaceCapture*>(ctx);
    self->frame_cb_(static_cast<const uint8_t*>(data),
                    static_cast<uint32_t>(size));
    return 0;
}

int IfaceCapture::epoll_fd() const
{
    return ring_buffer__epoll_fd(ringbuf_);
}

int IfaceCapture::consume()
{
    return ring_buffer__consume(ringbuf_);
}

// ── TX injection ─────────────────────────────────────────────────────────────

bool IfaceCapture::send_frame(const uint8_t* data, uint32_t len)
{
    struct sockaddr_ll addr{};
    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = ifindex_;
    addr.sll_protocol = 0;   // ignored on TX; protocol comes from the frame itself
    addr.sll_halen    = ETH_ALEN;
    // Destination MAC is embedded in the frame — copy first 6 bytes.
    if (len >= ETH_ALEN)
        std::memcpy(addr.sll_addr, data, ETH_ALEN);

    ssize_t n = sendto(raw_fd_, data, len, 0,
                       reinterpret_cast<struct sockaddr*>(&addr),
                       sizeof(addr));
    return n == static_cast<ssize_t>(len);
}
