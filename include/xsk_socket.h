#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <atomic>

// ── Constants ─────────────────────────────────────────────────────────────────
static constexpr uint32_t FRAME_SIZE   = 2048;      // bytes per UMEM frame
static constexpr uint32_t NUM_FRAMES   = 4096;      // total UMEM frames
static constexpr uint64_t UMEM_SIZE    = static_cast<uint64_t>(FRAME_SIZE) * NUM_FRAMES;
static constexpr uint32_t RING_SIZE    = 2048;      // entries per ring (must be power of 2)

// ── Ring descriptor from kernel ────────────────────────────────────────────────
struct XskRing {
    uint32_t*    producer  = nullptr;
    uint32_t*    consumer  = nullptr;
    uint32_t*    flags     = nullptr;
    uint8_t*     descs     = nullptr;   // pointer to descriptor array
    void*        ring      = nullptr;   // mmap base
    size_t       mmap_size = 0;
};

// ── A received frame (addr = offset into UMEM, len = byte count) ──────────────
struct XskFrame {
    uint64_t addr;
    uint32_t len;
};

// ── AF_XDP socket encapsulating one UMEM and one RX+TX socket ────────────────
class XskSocket {
public:
    XskSocket(const std::string& iface, const std::string& bpf_obj_path);
    ~XskSocket();

    // File descriptor suitable for poll(2).
    int fd() const { return xsk_fd_; }

    // Receive up to `max_frames` frames from the RX ring.
    // Returned XskFrame::addr values are offsets into umem_base().
    std::vector<XskFrame> receive_batch(uint32_t max_frames = 64);

    // Return addresses used in receive_batch back to the fill ring so the
    // kernel can reuse the UMEM slots.
    void recycle_rx_frames(const std::vector<XskFrame>& frames);

    // Copy `len` bytes from `data` into an available UMEM TX slot and submit
    // it to the TX ring. Returns false if no free slot is available.
    bool send_frame(const uint8_t* data, uint32_t len);

    // Drain the TX completion ring and return freed UMEM addresses to the pool.
    void drain_tx_completions();

    // Direct access to the UMEM base pointer (for zero-copy RX reads).
    uint8_t* umem_base() const { return static_cast<uint8_t*>(umem_area_); }

private:
    void setup_umem();
    void setup_socket();
    void load_and_attach_xdp(const std::string& bpf_obj_path);

    std::string  iface_;
    int          ifindex_  = -1;
    int          xsk_fd_   = -1;
    int          umem_fd_  = -1;   // same as xsk_fd_ for single-socket UMEM

    void*        umem_area_ = nullptr;

    // mmap'd ring pointers
    XskRing fill_ring_;
    XskRing comp_ring_;
    XskRing rx_ring_;
    XskRing tx_ring_;

    // Producer/consumer cached indices
    uint32_t fill_prod_idx_  = 0;
    uint32_t rx_cons_idx_    = 0;
    uint32_t tx_prod_idx_    = 0;
    uint32_t comp_cons_idx_  = 0;

    // Free UMEM frame address pool (TX side)
    std::vector<uint64_t> free_frames_;
};
