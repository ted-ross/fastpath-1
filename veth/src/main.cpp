#include "config.hpp"
#include "raw_socket.hpp"
#include "udp_socket.hpp"
#include "handlers.hpp"

#include <csignal>
#include <cstring>
#include <cerrno>
#include <iostream>

#include <liburing.h>
#include <poll.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------

static volatile sig_atomic_t g_running = 1;

static void on_signal(int /*sig*/)
{
    g_running = 0;
}

static void install_signal_handlers()
{
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

// ---------------------------------------------------------------------------
// io_uring helpers
// ---------------------------------------------------------------------------

/// Submit a POLL_ADD SQE that fires when `fd` becomes readable.
/// `user_data` is set to `fd` so the CQE handler can dispatch without
/// any additional lookup.
static void arm_poll(struct io_uring* ring, int fd)
{
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
    io_uring_prep_poll_add(sqe, fd, POLLIN);
    io_uring_sqe_set_data64(sqe, static_cast<uint64_t>(fd));
    io_uring_submit(ring);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    Config    cfg = parse_args(argc, argv);
    RawSocket raw = open_raw_socket("veth1");
    UdpSocket udp = open_udp_socket(cfg.local_port, cfg.peer_ip, cfg.peer_port);

    std::cout << "udp-encap ready"
              << "  peer=" << cfg.peer_ip << ":" << cfg.peer_port
              << "  local-port=" << cfg.local_port << "\n";

    install_signal_handlers();

    // Set up io_uring — queue depth of 4 is ample for two poll entries.
    struct io_uring ring{};
    if (io_uring_queue_init(4, &ring, 0) < 0) {
        std::cerr << "error: io_uring_queue_init: " << std::strerror(errno) << "\n";
        return 1;
    }

    // Arm an initial POLL_ADD for each fd.
    arm_poll(&ring, raw.fd);
    arm_poll(&ring, udp.fd);

    // Event loop — wait for a CQE, dispatch, re-arm, repeat.
    static constexpr long WAIT_NS = 500'000'000L;  // 500 ms — keeps signal check responsive

    while (g_running) {
        struct __kernel_timespec ts{ 0, WAIT_NS };
        struct io_uring_cqe* cqe = nullptr;

        int ret = io_uring_wait_cqe_timeout(&ring, &cqe, &ts);
        if (ret == -EINTR) {
            continue;  // interrupted by signal — loop will check g_running
        }
        if (ret == -ETIME) {
            continue;  // timeout — check g_running and wait again
        }
        if (ret < 0) {
            std::cerr << "error: io_uring_wait_cqe_timeout: "
                      << std::strerror(-ret) << "\n";
            break;
        }

        int fd = static_cast<int>(io_uring_cqe_get_data64(cqe));
        io_uring_cqe_seen(&ring, cqe);

        if (fd == raw.fd) {
            handle_raw_input(raw.fd, udp.fd, udp.peer_addr, cfg.debug);
        } else if (fd == udp.fd) {
            handle_udp_input(udp.fd, raw.fd, raw.iface_index, raw.mac, cfg.debug);
        }

        // Re-arm poll for the fd that just fired.
        arm_poll(&ring, fd);
    }

    std::cout << "udp-encap shutting down\n";
    io_uring_queue_exit(&ring);
    close(udp.fd);
    close(raw.fd);
    return 0;
}
