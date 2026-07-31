#include "config.h"
#include "iface_capture.h"
#include "udp_socket.h"

#include <poll.h>
#include <signal.h>

#include <atomic>
#include <cinttypes>
#include <cstdio>
#include <stdexcept>

// ── Signal handling ───────────────────────────────────────────────────────────

static std::atomic<bool> running{true};

static void handle_signal(int /*sig*/)
{
    running.store(false, std::memory_order_relaxed);
}

// ── Receive scratch buffer ────────────────────────────────────────────────────

static constexpr size_t UDP_RECV_BUF = 2048;

// ── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char** argv)
{
    Config cfg;
    try {
        cfg = parse_args(argc, argv);
    } catch (const std::exception& e) {
        fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }

    fprintf(stderr,
            "dataplane: iface=%s  tunnel=%s:%u  recv-port=%u\n"
            "           bpf-object=%s\n",
            cfg.iface.c_str(), cfg.dest_host.c_str(),
            cfg.dest_port, cfg.recv_port,
            BPF_OBJ_PATH);

    struct sigaction sa{};
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    // ── Counters shared with the ring-buffer callback ─────────────────────────
    uint64_t rx_packets = 0;

    // ── UDP sender (set up before capture so the lambda can capture it) ───────
    UdpSender*   sender   = nullptr;
    UdpReceiver* receiver = nullptr;
    try {
        sender   = new UdpSender(cfg.dest_host, cfg.dest_port);
        receiver = new UdpReceiver(cfg.recv_port);
    } catch (const std::exception& e) {
        fprintf(stderr, "error: UDP socket init failed: %s\n", e.what());
        return 1;
    }

    // ── TC egress capture ─────────────────────────────────────────────────────
    IfaceCapture* cap = nullptr;
    try {
        cap = new IfaceCapture(
            cfg.iface, BPF_OBJ_PATH,
            // Ring-buffer callback: forward each captured egress frame as UDP.
            [&](const uint8_t* data, uint32_t len) {
                sender->send(data, len);
                ++rx_packets;
            }
        );
    } catch (const std::exception& e) {
        fprintf(stderr, "error: TC capture init failed: %s\n", e.what());
        delete sender;
        delete receiver;
        return 1;
    }

    fprintf(stderr, "dataplane: running — press Ctrl+C to stop\n");

    // ── Poll loop ─────────────────────────────────────────────────────────────
    // epoll_fd() becomes readable when the BPF ring buffer has new entries.
    struct pollfd pfds[2];
    pfds[0].fd     = cap->epoll_fd();
    pfds[0].events = POLLIN;
    pfds[1].fd     = receiver->fd();
    pfds[1].events = POLLIN;

    uint8_t udp_buf[UDP_RECV_BUF];
    uint64_t tx_packets = 0;

    while (running.load(std::memory_order_relaxed)) {
        int nfds = poll(pfds, 2, 100);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        // ── Egress frames → UDP tunnel ────────────────────────────────────────
        if (pfds[0].revents & POLLIN)
            cap->consume();   // invokes frame_cb for each queued frame

        // ── UDP tunnel → ingress injection via TUN fd ─────────────────────────
        if (pfds[1].revents & POLLIN) {
            while (true) {
                ssize_t n = receiver->recv(udp_buf, sizeof(udp_buf));
                if (n <= 0) break;
                if (cap->send_frame(udp_buf, static_cast<uint32_t>(n)))
                    ++tx_packets;
                else
                    fprintf(stderr, "warning: TUN inject failed\n");
            }
        }
    }

    fprintf(stderr,
            "\ndataplane: shutting down  rx_packets=%" PRIu64
            "  tx_packets=%" PRIu64 "\n",
            rx_packets, tx_packets);

    delete cap;       // detaches TC filter + closes TUN fd
    delete receiver;
    delete sender;

    return 0;
}
