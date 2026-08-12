#include "config.hpp"
#include "raw_socket.hpp"
#include "udp_socket.hpp"
#include "handlers.hpp"

#include <csignal>
#include <cstring>
#include <cerrno>
#include <iostream>

#include <sys/epoll.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------

static volatile sig_atomic_t g_running = 1;

static unsigned long if_rx    = 0;
static unsigned long if_tx    = 0;
static unsigned long if_drop  = 0;
static unsigned long tun_rx   = 0;
static unsigned long tun_tx   = 0;
static unsigned long tun_drop = 0;

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

    // Set up epoll.
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        std::cerr << "error: epoll_create1: " << std::strerror(errno) << "\n";
        return 1;
    }

    auto add_fd = [&](int fd) {
        struct epoll_event ev{};
        ev.events  = EPOLLIN;
        ev.data.fd = fd;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            std::cerr << "error: epoll_ctl(ADD, fd=" << fd << "): "
                      << std::strerror(errno) << "\n";
            return false;
        }
        return true;
    };

    if (!add_fd(raw.fd) || !add_fd(udp.fd)) {
        close(epfd);
        close(raw.fd);
        close(udp.fd);
        return 1;
    }

    // Event loop.
    static constexpr int MAX_EVENTS    = 4;
    static constexpr int EPOLL_TIMEOUT = 500;  // ms — ensures signal check fires promptly

    struct epoll_event events[MAX_EVENTS];

    while (g_running) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, EPOLL_TIMEOUT);
        if (n < 0) {
            if (errno == EINTR) {
                continue;  // interrupted by signal — loop will check g_running
            }
            std::cerr << "error: epoll_wait: " << std::strerror(errno) << "\n";
            break;
        }

        for (int i = 0; i < n; ++i) {
            if (events[i].data.fd == raw.fd) {
                handle_raw_input(raw.fd, udp.fd, udp.peer_addr, cfg.debug,
                    &if_rx, &tun_tx, &tun_drop);
            } else if (events[i].data.fd == udp.fd) {
                handle_udp_input(udp.fd, raw.fd, raw.iface_index, raw.mac, cfg.debug,
                    &if_tx, &if_drop, &tun_rx);
            }
        }
    }

    std::cout << "udp-encap shutting down\n\n";
    std::cout << "Interface: tx = " << if_tx << "\n";
    std::cout << "           rx = " << if_rx << "\n";
    std::cout << "         drop = " << if_drop << "\n";
    std::cout << "Tunnel:    tx = " << tun_tx << "\n";
    std::cout << "           rx = " << tun_rx << "\n";
    std::cout << "         drop = " << tun_drop << "\n";
    close(epfd);
    close(udp.fd);
    close(raw.fd);
    return 0;
}
