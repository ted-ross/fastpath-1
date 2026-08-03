#include "iface_capture.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <cstdio>

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

    // Destroy any pre-existing clsact qdisc on this interface (e.g. left behind
    // by a previous crashed run) before creating a fresh one.  We must use the
    // combined INGRESS|EGRESS attach_point for the destroy call, then restore
    // EGRESS for the create/attach calls that follow.
    {
        LIBBPF_OPTS(bpf_tc_hook, destroy_hook,
            .ifindex      = ifindex_,
            .attach_point = static_cast<bpf_tc_attach_point>(BPF_TC_INGRESS | BPF_TC_EGRESS),
        );
        bpf_tc_hook_destroy(&destroy_hook);   // ignore error — may not exist
    }

    int ret = bpf_tc_hook_create(&hook);
    if (ret != 0 && ret != -EEXIST)
        ic_throw("bpf_tc_hook_create", -ret);
    tc_hook_created_ = true;   // we always own the hook now

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

    // ── TUN fd for ingress injection ──────────────────────────────────────────
    // Opening /dev/net/tun and attaching to the named TUN interface gives a fd
    // where write() delivers an IP packet directly into the kernel IP stack —
    // the same interface the TC egress hook is watching.  IFF_NO_PI suppresses
    // the 4-byte packet-info header so we can write raw IP PDUs directly.
    tun_fd_ = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (tun_fd_ < 0)
        ic_throw("open(/dev/net/tun)");

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(tun_fd_, TUNSETIFF, &ifr) < 0) {
        close(tun_fd_);
        tun_fd_ = -1;
        ic_throw("ioctl(TUNSETIFF, " + iface + ")");
    }
}

// ── Destructor ───────────────────────────────────────────────────────────────

IfaceCapture::~IfaceCapture()
{
    if (tun_fd_ >= 0) close(tun_fd_);

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

// ── Helpers ───────────────────────────────────────────────────────────────────

// Log a one-line summary of an IP packet (IPv4 only) for debugging.
static void log_packet(const char* direction, const uint8_t* data, uint32_t len)
{
    if (len < 20) {
        fprintf(stderr, "dbg: %s  [%u bytes, too short for IPv4]\n", direction, len);
        return;
    }
    uint8_t  proto = data[9];
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, data + 12, src, sizeof(src));
    inet_ntop(AF_INET, data + 16, dst, sizeof(dst));

    if (proto == 6 && len >= (uint32_t)((data[0] & 0x0f) * 4) + 14u) {  // TCP
        const uint8_t* tcp = data + ((data[0] & 0x0f) * 4);
        uint16_t sport = (uint16_t)(tcp[0] << 8 | tcp[1]);
        uint16_t dport = (uint16_t)(tcp[2] << 8 | tcp[3]);
        uint8_t  flags = tcp[13];
        fprintf(stderr, "dbg: %s  TCP  %s:%u -> %s:%u  flags=0x%02x\n",
                direction, src, sport, dst, dport, flags);
    } else if (proto == 1) {                        // ICMP
        fprintf(stderr, "dbg: %s  ICMP  %s -> %s\n", direction, src, dst);
    } else {
        fprintf(stderr, "dbg: %s  proto=%u  %s -> %s  [%u bytes]\n",
                direction, proto, src, dst, len);
    }
}

// ── Ring buffer glue ──────────────────────────────────────────────────────────

// Static trampoline: libbpf calls this; we forward to the instance callback.
int IfaceCapture::ringbuf_cb(void* ctx, void* data, size_t size)
{
    auto* self = static_cast<IfaceCapture*>(ctx);
    const uint8_t* pkt = static_cast<const uint8_t*>(data);
    log_packet("TC-egress ", pkt, static_cast<uint32_t>(size));
    self->frame_cb_(pkt, static_cast<uint32_t>(size));
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

// ── Ingress injection ─────────────────────────────────────────────────────────

bool IfaceCapture::send_frame(const uint8_t* data, uint32_t len)
{
    log_packet("TUN-inject", data, len);
    ssize_t n = write(tun_fd_, data, len);
    if (n != static_cast<ssize_t>(len)) {
        fprintf(stderr, "dbg: TUN-inject write returned %zd (errno=%d %s)\n",
                n, errno, strerror(errno));
        return false;
    }
    return true;
}
