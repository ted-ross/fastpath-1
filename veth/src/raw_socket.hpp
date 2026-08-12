#pragma once

#include <cstdint>
#include <string>
#include <net/ethernet.h>  // ETH_ALEN

/// Holds the AF_PACKET/SOCK_DGRAM socket file descriptor plus the resolved
/// interface metadata needed to send IP packets back out via the veth pair.
struct RawSocket {
    int     fd;
    int     iface_index;
    uint8_t mac[ETH_ALEN];  // destination MAC (veth1's peer) for sockaddr_ll
};

/// Open an AF_PACKET/SOCK_DGRAM socket bound to `iface` for IPv4.
/// Resolves the interface index and peer MAC address via netlink.
/// Calls exit(1) on any fatal error.
RawSocket open_raw_socket(const std::string& iface);
