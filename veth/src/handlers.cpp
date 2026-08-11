#include "handlers.hpp"

#include <cstring>
#include <cerrno>
#include <iostream>

#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

/// Ethernet header + maximum IPv4 payload within a 1500-byte MTU.
static constexpr int ETH_FRAME_MAX = 1514;  // 14-byte header + 1500-byte payload

// ---------------------------------------------------------------------------
// Outbound: veth1 → UDP peer
// ---------------------------------------------------------------------------

void handle_raw_input(int raw_fd, int udp_fd, const struct sockaddr_in& peer)
{
    uint8_t buf[ETH_FRAME_MAX];

    ssize_t n = recvfrom(raw_fd, buf, sizeof(buf), 0, nullptr, nullptr);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            std::cerr << "warn: recvfrom(raw): " << std::strerror(errno) << "\n";
        }
        return;
    }

    // Need at least the 14-byte Ethernet header plus 1 byte of payload.
    if (n < static_cast<ssize_t>(sizeof(struct ethhdr) + 1)) {
        return;
    }

    const auto* eth = reinterpret_cast<const struct ethhdr*>(buf);
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return;  // Not IPv4 — silently drop.
    }

    const uint8_t* ip_payload = buf + sizeof(struct ethhdr);
    ssize_t        ip_len     = n - static_cast<ssize_t>(sizeof(struct ethhdr));

    ssize_t sent = sendto(udp_fd,
                          ip_payload,
                          static_cast<size_t>(ip_len),
                          0,
                          reinterpret_cast<const struct sockaddr*>(&peer),
                          sizeof(peer));
    if (sent < 0) {
        std::cerr << "warn: sendto(udp peer): " << std::strerror(errno) << "\n";
    }
}

// ---------------------------------------------------------------------------
// Inbound: UDP peer → veth1
// ---------------------------------------------------------------------------

void handle_udp_input(int udp_fd, int raw_fd,
                      int iface_index, const uint8_t mac[6])
{
    // Reserve space at the front of the buffer for the Ethernet header.
    uint8_t buf[ETH_FRAME_MAX];
    uint8_t* ip_area  = buf + sizeof(struct ethhdr);
    size_t   ip_space = sizeof(buf) - sizeof(struct ethhdr);

    ssize_t n = recvfrom(udp_fd, ip_area, ip_space, 0, nullptr, nullptr);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            std::cerr << "warn: recvfrom(udp): " << std::strerror(errno) << "\n";
        }
        return;
    }
    if (n == 0) {
        return;
    }

    // Build the Ethernet header in-place at the start of the buffer.
    auto* eth    = reinterpret_cast<struct ethhdr*>(buf);
    std::memcpy(eth->h_dest,   mac, ETH_ALEN);
    std::memcpy(eth->h_source, mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    // Addressing for AF_PACKET sendto.
    struct sockaddr_ll sa{};
    sa.sll_family   = AF_PACKET;
    sa.sll_ifindex  = iface_index;
    sa.sll_halen    = ETH_ALEN;
    std::memcpy(sa.sll_addr, mac, ETH_ALEN);

    size_t  frame_len = sizeof(struct ethhdr) + static_cast<size_t>(n);
    ssize_t sent = sendto(raw_fd,
                          buf,
                          frame_len,
                          0,
                          reinterpret_cast<struct sockaddr*>(&sa),
                          sizeof(sa));
    if (sent < 0) {
        std::cerr << "warn: sendto(raw/veth1): " << std::strerror(errno) << "\n";
    }
}
