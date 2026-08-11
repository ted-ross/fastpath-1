#include "raw_socket.hpp"

#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <iostream>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Netlink helper: resolve the MAC address of veth1's peer interface.
//
// A veth pair always has a peer.  The peer's ifindex is stored as the
// IFLA_LINK attribute of the local interface's RTM_GETLINK response.
// A second RTM_GETLINK for that ifindex returns IFLA_ADDRESS (the MAC).
// ---------------------------------------------------------------------------

/// Send an RTM_GETLINK request for `ifindex` on the already-open netlink fd.
static void nl_send_getlink(int nlfd, int ifindex, uint32_t seq)
{
    struct {
        struct nlmsghdr  nlh;
        struct ifinfomsg ifi;
    } req{};

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.ifi));
    req.nlh.nlmsg_type  = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq   = seq;
    req.ifi.ifi_family  = AF_UNSPEC;
    req.ifi.ifi_index   = ifindex;

    if (send(nlfd, &req, req.nlh.nlmsg_len, 0) < 0) {
        std::cerr << "error: netlink send(RTM_GETLINK): "
                  << std::strerror(errno) << "\n";
        std::exit(1);
    }
}

/// Read one RTM_NEWLINK reply from `nlfd` and walk its rtattr list.
/// If `out_peer_ifindex` is non-null, fill it from IFLA_LINK.
/// If `out_mac` is non-null, fill it (ETH_ALEN bytes) from IFLA_ADDRESS.
static void nl_recv_newlink(int nlfd, uint32_t seq,
                            int* out_peer_ifindex, uint8_t* out_mac)
{
    char buf[8192];
    for (;;) {
        ssize_t n = recv(nlfd, buf, sizeof(buf), 0);
        if (n < 0) {
            std::cerr << "error: netlink recv: " << std::strerror(errno) << "\n";
            std::exit(1);
        }
        const auto* nlh = reinterpret_cast<const struct nlmsghdr*>(buf);
        for (; NLMSG_OK(nlh, static_cast<uint32_t>(n)); nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_seq != seq) continue;
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                std::cerr << "error: netlink NLMSG_ERROR\n";
                std::exit(1);
            }
            if (nlh->nlmsg_type != RTM_NEWLINK) continue;

            const auto* ifi = reinterpret_cast<const struct ifinfomsg*>(NLMSG_DATA(nlh));
            const struct rtattr* rta = IFLA_RTA(ifi);
            int rta_len = static_cast<int>(IFLA_PAYLOAD(nlh));

            for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                if (out_peer_ifindex && rta->rta_type == IFLA_LINK) {
                    std::memcpy(out_peer_ifindex, RTA_DATA(rta), sizeof(int));
                }
                if (out_mac && rta->rta_type == IFLA_ADDRESS &&
                    RTA_PAYLOAD(rta) == ETH_ALEN) {
                    std::memcpy(out_mac, RTA_DATA(rta), ETH_ALEN);
                }
            }
            return;  // processed the matching RTM_NEWLINK
        }
    }
}

/// Resolve the MAC address of the veth peer of `iface_index`.
static void resolve_peer_mac(int iface_index, uint8_t mac_out[ETH_ALEN])
{
    int nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nlfd < 0) {
        std::cerr << "error: socket(AF_NETLINK): " << std::strerror(errno) << "\n";
        std::exit(1);
    }

    struct sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    if (bind(nlfd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) < 0) {
        std::cerr << "error: bind(AF_NETLINK): " << std::strerror(errno) << "\n";
        close(nlfd);
        std::exit(1);
    }

    // Step 1: get the peer's ifindex from IFLA_LINK.
    nl_send_getlink(nlfd, iface_index, 1);
    int peer_ifindex = 0;
    nl_recv_newlink(nlfd, 1, &peer_ifindex, nullptr);
    if (peer_ifindex == 0) {
        std::cerr << "error: IFLA_LINK not found — is veth1 a veth interface?\n";
        close(nlfd);
        std::exit(1);
    }

    // Step 2: get the peer's MAC from IFLA_ADDRESS.
    nl_send_getlink(nlfd, peer_ifindex, 2);
    nl_recv_newlink(nlfd, 2, nullptr, mac_out);

    close(nlfd);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

RawSocket open_raw_socket(const std::string& iface)
{
    // Open raw socket that captures all Ethernet frames.
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        std::cerr << "error: socket(AF_PACKET): " << std::strerror(errno) << "\n"
                  << "       (are you running as root or with CAP_NET_RAW?)\n";
        std::exit(1);
    }

    // Resolve interface index.
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        std::cerr << "error: SIOCGIFINDEX for '" << iface << "': "
                  << std::strerror(errno) << "\n";
        close(fd);
        std::exit(1);
    }
    int iface_index = ifr.ifr_ifindex;

    // Bind the socket to this interface.
    struct sockaddr_ll sa{};
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex  = iface_index;
    if (bind(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) < 0) {
        std::cerr << "error: bind(AF_PACKET) on '" << iface << "': "
                  << std::strerror(errno) << "\n";
        close(fd);
        std::exit(1);
    }

    // Resolve the peer's MAC address via netlink IFLA_LINK / IFLA_ADDRESS.
    RawSocket rs{};
    rs.fd          = fd;
    rs.iface_index = iface_index;
    resolve_peer_mac(iface_index, rs.mac);

    std::cout << "raw socket: " << iface
              << " index=" << iface_index
              << " peer-mac=";
    for (int i = 0; i < ETH_ALEN; ++i) {
        if (i) std::cout << ":";
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", rs.mac[i]);
        std::cout << buf;
    }
    std::cout << "\n";

    return rs;
}
