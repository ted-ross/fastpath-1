#include "handlers.hpp"

#include <cstring>
#include <cerrno>
#include <iostream>
#include <iomanip>
#include <sstream>

#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

/// Ethernet header + maximum IPv4 payload within a 1500-byte MTU.
static constexpr int ETH_FRAME_MAX = 1514;  // 14-byte header + 1500-byte payload

/*
/// Format a 6-byte MAC address as "xx:xx:xx:xx:xx:xx".
static std::string mac_to_str(const uint8_t m[ETH_ALEN])
{
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (int i = 0; i < ETH_ALEN; ++i) {
        if (i) os << ':';
        os << std::setw(2) << static_cast<unsigned>(m[i]);
    }
    return os.str();
}
*/

// ---------------------------------------------------------------------------
// Outbound: veth1 → UDP peer
// ---------------------------------------------------------------------------

void handle_raw_input(int raw_fd, int udp_fd, const struct sockaddr_in& peer,
                      bool debug)
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
        if (debug) {
            std::cout << "[debug] veth1 RX  dropped: runt frame (" << n << " bytes)\n";
        }
        return;
    }

    const auto* eth = reinterpret_cast<const struct ethhdr*>(buf);
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        if (debug) {
            std::cout << "[debug] veth1 RX  dropped: non-IPv4 EtherType 0x"
                      << std::hex << ntohs(eth->h_proto) << std::dec << "\n";
        }
        return;
    }

    const uint8_t* ip_payload = buf + sizeof(struct ethhdr);
    ssize_t        ip_len     = n - static_cast<ssize_t>(sizeof(struct ethhdr));

    if (debug) {
        const auto* iph = reinterpret_cast<const struct iphdr*>(ip_payload);
        char ipsrc[INET_ADDRSTRLEN], ipdst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, ipsrc, sizeof(ipsrc));
        inet_ntop(AF_INET, &iph->daddr, ipdst, sizeof(ipdst));
        std::cout << "[debug] veth1 RX  " << ip_len << " bytes"
                  //<< "  mac-src=" << mac_to_str(eth->h_source)
                  //<< " mac-dst=" << mac_to_str(eth->h_dest)
                  << "  ip-src=" << ipsrc << " ip-dst=" << ipdst << " proto=" << (int)iph->protocol << "\n";
    }

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
                      int iface_index, const uint8_t mac[6], bool debug)
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
        if (debug) {
            std::cout << "[debug] veth1 TX  dropped: zero-length UDP datagram\n";
        }
        return;
    }

    // Build the Ethernet header in-place at the start of the buffer.
    auto* eth    = reinterpret_cast<struct ethhdr*>(buf);
    std::memcpy(eth->h_dest,   mac, ETH_ALEN);
    std::memcpy(eth->h_source, mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    if (debug) {
        const auto* iph = reinterpret_cast<const struct iphdr*>(ip_area);
        char ipsrc[INET_ADDRSTRLEN], ipdst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, ipsrc, sizeof(ipsrc));
        inet_ntop(AF_INET, &iph->daddr, ipdst, sizeof(ipdst));
        std::cout << "[debug] veth1 TX  " << n << " bytes"
                  //<< "  mac-src=" << mac_to_str(eth->h_source)
                  //<< " mac-dst=" << mac_to_str(eth->h_dest)
                  << "  ip-src=" << ipsrc << " ip-dst=" << ipdst << " proto=" << (int)iph->protocol << "\n";
    }

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
