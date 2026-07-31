#include "xsk_socket.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>

// ── Internal helpers ─────────────────────────────────────────────────────────

static void xsk_throw(const std::string& msg, int err = errno)
{
    throw std::runtime_error(msg + ": " + std::strerror(err));
}

static inline uint32_t ring_mask(uint32_t idx)
{
    return idx & (RING_SIZE - 1);
}

// ── Constructor ──────────────────────────────────────────────────────────────

XskSocket::XskSocket(const std::string& iface, const std::string& bpf_obj_path)
    : iface_(iface)
{
    ifindex_ = static_cast<int>(if_nametoindex(iface.c_str()));
    if (ifindex_ == 0)
        xsk_throw("if_nametoindex(" + iface + ")");

    // Raise locked memory limit so we can mmap the UMEM region.
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0)
        xsk_throw("setrlimit(RLIMIT_MEMLOCK)");

    setup_umem();
    setup_socket();
    load_and_attach_xdp(bpf_obj_path);
}

// ── Destructor ───────────────────────────────────────────────────────────────

XskSocket::~XskSocket()
{
    if (ifindex_ > 0) {
        // Detach the XDP program; use SKB mode flag to match what was attached.
        LIBBPF_OPTS(bpf_xdp_attach_opts, detach_opts);
        bpf_xdp_detach(ifindex_, XDP_FLAGS_SKB_MODE, &detach_opts);
    }

    auto unmap = [](XskRing& r) {
        if (r.ring && r.ring != MAP_FAILED)
            munmap(r.ring, r.mmap_size);
    };
    unmap(rx_ring_);
    unmap(tx_ring_);
    unmap(fill_ring_);
    unmap(comp_ring_);

    if (xsk_fd_ >= 0) close(xsk_fd_);

    if (umem_area_ && umem_area_ != MAP_FAILED)
        munmap(umem_area_, UMEM_SIZE);
}

// ── UMEM + ring setup ────────────────────────────────────────────────────────

void XskSocket::setup_umem()
{
    // Try hugepages first; fall back to regular anonymous memory.
    umem_area_ = mmap(nullptr, UMEM_SIZE,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                      -1, 0);
    if (umem_area_ == MAP_FAILED) {
        umem_area_ = mmap(nullptr, UMEM_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);
        if (umem_area_ == MAP_FAILED)
            xsk_throw("mmap UMEM");
    }

    // Open AF_XDP socket.
    xsk_fd_ = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
    if (xsk_fd_ < 0)
        xsk_throw("socket(AF_XDP)");

    // Register UMEM with the kernel.
    struct xdp_umem_reg reg{};
    reg.addr       = reinterpret_cast<uint64_t>(umem_area_);
    reg.len        = UMEM_SIZE;
    reg.chunk_size = FRAME_SIZE;
    reg.headroom   = 0;
    reg.flags      = 0;

    if (setsockopt(xsk_fd_, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg)) != 0)
        xsk_throw("setsockopt(XDP_UMEM_REG)");

    // Configure ring sizes.
    uint32_t rsz = RING_SIZE;
    if (setsockopt(xsk_fd_, SOL_XDP, XDP_UMEM_FILL_RING,       &rsz, sizeof(rsz)) != 0)
        xsk_throw("setsockopt(XDP_UMEM_FILL_RING)");
    if (setsockopt(xsk_fd_, SOL_XDP, XDP_UMEM_COMPLETION_RING, &rsz, sizeof(rsz)) != 0)
        xsk_throw("setsockopt(XDP_UMEM_COMPLETION_RING)");
    if (setsockopt(xsk_fd_, SOL_XDP, XDP_RX_RING,              &rsz, sizeof(rsz)) != 0)
        xsk_throw("setsockopt(XDP_RX_RING)");
    if (setsockopt(xsk_fd_, SOL_XDP, XDP_TX_RING,              &rsz, sizeof(rsz)) != 0)
        xsk_throw("setsockopt(XDP_TX_RING)");

    // Query mmap offsets once — cached in the ring structs for the hot path.
    struct xdp_mmap_offsets off{};
    socklen_t optlen = sizeof(off);
    if (getsockopt(xsk_fd_, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) != 0)
        xsk_throw("getsockopt(XDP_MMAP_OFFSETS)");

    // Helper lambda: mmap a ring and cache its producer/consumer/flags/descs.
    auto map_ring = [&](XskRing& r, uint64_t pgoff,
                        uint64_t prod_off, uint64_t cons_off,
                        uint64_t flags_off, uint64_t desc_off,
                        size_t desc_entry_size) {
        r.mmap_size = desc_off + RING_SIZE * desc_entry_size;
        r.ring = mmap(nullptr, r.mmap_size,
                      PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE,
                      xsk_fd_, static_cast<off_t>(pgoff));
        if (r.ring == MAP_FAILED) xsk_throw("mmap ring");
        auto* base = static_cast<uint8_t*>(r.ring);
        r.producer = reinterpret_cast<uint32_t*>(base + prod_off);
        r.consumer = reinterpret_cast<uint32_t*>(base + cons_off);
        r.flags    = reinterpret_cast<uint32_t*>(base + flags_off);
        r.descs    = base + desc_off;
    };

    map_ring(fill_ring_, XDP_UMEM_PGOFF_FILL_RING,
             off.fr.producer, off.fr.consumer, off.fr.flags, off.fr.desc,
             sizeof(uint64_t));

    map_ring(comp_ring_, XDP_UMEM_PGOFF_COMPLETION_RING,
             off.cr.producer, off.cr.consumer, off.cr.flags, off.cr.desc,
             sizeof(uint64_t));

    map_ring(rx_ring_, XDP_PGOFF_RX_RING,
             off.rx.producer, off.rx.consumer, off.rx.flags, off.rx.desc,
             sizeof(struct xdp_desc));

    map_ring(tx_ring_, XDP_PGOFF_TX_RING,
             off.tx.producer, off.tx.consumer, off.tx.flags, off.tx.desc,
             sizeof(struct xdp_desc));

    // Offer lower half of UMEM frames to the kernel (RX fill ring).
    auto* fill_descs = reinterpret_cast<uint64_t*>(fill_ring_.descs);
    for (uint32_t i = 0; i < NUM_FRAMES / 2; ++i)
        fill_descs[ring_mask(fill_prod_idx_ + i)] =
            static_cast<uint64_t>(i) * FRAME_SIZE;
    __sync_synchronize();
    __atomic_store_n(fill_ring_.producer,
                     fill_prod_idx_ + NUM_FRAMES / 2, __ATOMIC_RELEASE);
    fill_prod_idx_ += NUM_FRAMES / 2;

    // Reserve upper half of UMEM frames as the TX free pool.
    for (uint32_t i = NUM_FRAMES / 2; i < NUM_FRAMES; ++i)
        free_frames_.push_back(static_cast<uint64_t>(i) * FRAME_SIZE);
}

// ── Socket bind ───────────────────────────────────────────────────────────────

void XskSocket::setup_socket()
{
    struct sockaddr_xdp addr{};
    addr.sxdp_family   = AF_XDP;
    addr.sxdp_ifindex  = static_cast<uint32_t>(ifindex_);
    addr.sxdp_queue_id = 0;
    addr.sxdp_flags    = 0; // try zero-copy first

    if (bind(xsk_fd_, reinterpret_cast<struct sockaddr*>(&addr),
             sizeof(addr)) == 0)
        return;

    // Driver does not support zero-copy; fall back to copy mode.
    addr.sxdp_flags = XDP_COPY;
    if (bind(xsk_fd_, reinterpret_cast<struct sockaddr*>(&addr),
             sizeof(addr)) != 0)
        xsk_throw("bind(AF_XDP)");
}

// ── XDP program load & attach ─────────────────────────────────────────────────

void XskSocket::load_and_attach_xdp(const std::string& bpf_obj_path)
{
    struct bpf_object* obj =
        bpf_object__open_file(bpf_obj_path.c_str(), nullptr);
    if (!obj)
        xsk_throw("bpf_object__open_file(" + bpf_obj_path + ")");

    if (bpf_object__load(obj) != 0) {
        bpf_object__close(obj);
        xsk_throw("bpf_object__load");
    }

    struct bpf_program* prog =
        bpf_object__find_program_by_name(obj, "xdp_ingress");
    if (!prog) {
        bpf_object__close(obj);
        throw std::runtime_error(
            "BPF program 'xdp_ingress' not found in " + bpf_obj_path);
    }

    int prog_fd = bpf_program__fd(prog);

    // Try native XDP; fall back to SKB (generic) mode for virtual interfaces.
    LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
    uint32_t flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    int ret = bpf_xdp_attach(ifindex_, prog_fd, flags, &opts);
    if (ret != 0) {
        flags |= XDP_FLAGS_SKB_MODE;
        ret = bpf_xdp_attach(ifindex_, prog_fd, flags, &opts);
        if (ret != 0) {
            bpf_object__close(obj);
            xsk_throw("bpf_xdp_attach(" + iface_ + ")", -ret);
        }
    }

    // Register this socket in the XSKMAP at queue index 0.
    struct bpf_map* xsk_map = bpf_object__find_map_by_name(obj, "xsk_map");
    if (!xsk_map) {
        bpf_object__close(obj);
        throw std::runtime_error("BPF map 'xsk_map' not found in " +
                                 bpf_obj_path);
    }

    int map_fd = bpf_map__fd(xsk_map);
    uint32_t key = 0;
    int val = xsk_fd_;
    if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0) {
        bpf_object__close(obj);
        xsk_throw("bpf_map_update_elem(xsk_map)");
    }

    // Intentionally do not close obj — closing it would unload the BPF maps
    // and detach the program from the map perspective.
}

// ── RX path ───────────────────────────────────────────────────────────────────

std::vector<XskFrame> XskSocket::receive_batch(uint32_t max_frames)
{
    std::vector<XskFrame> frames;

    uint32_t prod  = __atomic_load_n(rx_ring_.producer, __ATOMIC_ACQUIRE);
    uint32_t avail = prod - rx_cons_idx_;
    if (avail == 0) return frames;
    if (avail > max_frames) avail = max_frames;

    auto* descs = reinterpret_cast<const struct xdp_desc*>(rx_ring_.descs);
    frames.reserve(avail);
    for (uint32_t i = 0; i < avail; ++i) {
        const auto& d = descs[ring_mask(rx_cons_idx_ + i)];
        frames.push_back({ d.addr, d.len });
    }

    __atomic_store_n(rx_ring_.consumer, rx_cons_idx_ + avail, __ATOMIC_RELEASE);
    rx_cons_idx_ += avail;
    return frames;
}

void XskSocket::recycle_rx_frames(const std::vector<XskFrame>& frames)
{
    if (frames.empty()) return;

    auto* descs = reinterpret_cast<uint64_t*>(fill_ring_.descs);
    for (const auto& f : frames)
        descs[ring_mask(fill_prod_idx_++)] = f.addr;

    __sync_synchronize();
    __atomic_store_n(fill_ring_.producer, fill_prod_idx_, __ATOMIC_RELEASE);
}

// ── TX path ───────────────────────────────────────────────────────────────────

bool XskSocket::send_frame(const uint8_t* data, uint32_t len)
{
    if (free_frames_.empty()) return false;
    if (len > FRAME_SIZE) len = FRAME_SIZE;

    uint64_t addr = free_frames_.back();
    free_frames_.pop_back();

    std::memcpy(umem_base() + addr, data, len);

    auto* descs = reinterpret_cast<struct xdp_desc*>(tx_ring_.descs);
    auto& d = descs[ring_mask(tx_prod_idx_)];
    d.addr    = addr;
    d.len     = len;
    d.options = 0;

    __sync_synchronize();
    __atomic_store_n(tx_ring_.producer, tx_prod_idx_ + 1, __ATOMIC_RELEASE);
    tx_prod_idx_++;

    // Wake up the kernel TX path if needed.
    if (*tx_ring_.flags & XDP_RING_NEED_WAKEUP) {
        if (sendto(xsk_fd_, nullptr, 0, MSG_DONTWAIT, nullptr, 0) < 0
            && errno != ENOBUFS && errno != EAGAIN
            && errno != EBUSY  && errno != ENETDOWN)
            xsk_throw("sendto(kick TX)");
    }

    return true;
}

void XskSocket::drain_tx_completions()
{
    uint32_t prod  = __atomic_load_n(comp_ring_.producer, __ATOMIC_ACQUIRE);
    uint32_t avail = prod - comp_cons_idx_;
    if (avail == 0) return;

    auto* descs = reinterpret_cast<const uint64_t*>(comp_ring_.descs);
    for (uint32_t i = 0; i < avail; ++i)
        free_frames_.push_back(descs[ring_mask(comp_cons_idx_ + i)]);

    __atomic_store_n(comp_ring_.consumer,
                     comp_cons_idx_ + avail, __ATOMIC_RELEASE);
    comp_cons_idx_ += avail;
}
