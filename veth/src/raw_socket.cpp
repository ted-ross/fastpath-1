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
#include <arpa/inet.h>
#include <unistd.h>

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

    // Resolve MAC address.
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        std::cerr << "error: SIOCGIFHWADDR for '" << iface << "': "
                  << std::strerror(errno) << "\n";
        close(fd);
        std::exit(1);
    }

    RawSocket rs{};
    rs.fd          = fd;
    rs.iface_index = iface_index;
    std::memcpy(rs.mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    std::cout << "raw socket: " << iface
              << " index=" << iface_index
              << " mac=";
    for (int i = 0; i < ETH_ALEN; ++i) {
        if (i) std::cout << ":";
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", rs.mac[i]);
        std::cout << buf;
    }
    std::cout << "\n";

    return rs;
}
