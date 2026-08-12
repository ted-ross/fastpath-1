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

/// Maximum IPv4 packet size within a 1500-byte MTU.
static constexpr int IP_FRAME_MAX = 1500;

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
                      bool debug,
                      unsigned long *if_rx, unsigned long *tun_tx, unsigned long *tun_drop)
{
    // With SOCK_DGRAM the kernel strips the Ethernet header; buf holds the IP
    // packet directly.
    uint8_t buf[IP_FRAME_MAX];

    ssize_t n = recvfrom(raw_fd, buf, sizeof(buf), 0, nullptr, nullptr);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            std::cerr << "warn: recvfrom(raw): " << std::strerror(errno) << "\n";
        }
        return;
    }
    if (n < 1) {
        if (debug) {
            std::cout << "[debug] veth1 RX  dropped: empty packet\n";
        }
        return;
    }

    (*if_rx)++;

    if (debug) {
        const auto* iph = reinterpret_cast<const struct iphdr*>(buf);
        char ipsrc[INET_ADDRSTRLEN], ipdst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, ipsrc, sizeof(ipsrc));
        inet_ntop(AF_INET, &iph->daddr, ipdst, sizeof(ipdst));
        std::cout << "[debug] veth1 RX  " << n << " bytes"
                  << "  ip-src=" << ipsrc << " ip-dst=" << ipdst << " proto=" << (int)iph->protocol << "\n";
    }

    ssize_t sent = sendto(udp_fd,
                          buf,
                          static_cast<size_t>(n),
                          0,
                          reinterpret_cast<const struct sockaddr*>(&peer),
                          sizeof(peer));
    if (sent < 0) {
        std::cerr << "warn: sendto(udp peer): " << std::strerror(errno) << "\n";
        (*tun_drop)++;
    } else {
        (*tun_tx)++;
    }
}

// ---------------------------------------------------------------------------
// Inbound: UDP peer → veth1
// ---------------------------------------------------------------------------

void handle_udp_input(int udp_fd, int raw_fd,
                      int iface_index, const uint8_t mac[6], bool debug,
                      unsigned long *if_tx, unsigned long *if_drop, unsigned long *tun_rx)
{
    // With SOCK_DGRAM the kernel prepends the Ethernet header on send; we only
    // need to supply the IP packet.
    uint8_t buf[IP_FRAME_MAX];

    ssize_t n = recvfrom(udp_fd, buf, sizeof(buf), 0, nullptr, nullptr);
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

    (*tun_rx)++;

    if (debug) {
        const auto* iph = reinterpret_cast<const struct iphdr*>(buf);
        char ipsrc[INET_ADDRSTRLEN], ipdst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, ipsrc, sizeof(ipsrc));
        inet_ntop(AF_INET, &iph->daddr, ipdst, sizeof(ipdst));
        std::cout << "[debug] veth1 TX  " << n << " bytes"
                  << "  ip-src=" << ipsrc << " ip-dst=" << ipdst << " proto=" << (int)iph->protocol << "\n";
    }

    // Addressing for AF_PACKET SOCK_DGRAM sendto — kernel fills the Ethernet
    // header using sll_addr as the destination MAC.
    struct sockaddr_ll sa{};
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_IP);
    sa.sll_ifindex  = iface_index;
    sa.sll_halen    = ETH_ALEN;
    std::memcpy(sa.sll_addr, mac, ETH_ALEN);

    ssize_t sent = sendto(raw_fd,
                          buf,
                          static_cast<size_t>(n),
                          0,
                          reinterpret_cast<struct sockaddr*>(&sa),
                          sizeof(sa));
    if (sent < 0) {
        std::cerr << "warn: sendto(raw/veth1): " << std::strerror(errno) << "\n";
        (*if_drop)++;
    } else {
        (*if_tx)++;
    }
}
