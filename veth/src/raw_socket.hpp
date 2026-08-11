#pragma once

#include <cstdint>
#include <string>
#include <net/ethernet.h>  // ETH_ALEN

/// Holds the AF_PACKET socket file descriptor plus the resolved
/// interface metadata needed to send frames back out.
struct RawSocket {
    int     fd;
    int     iface_index;
    uint8_t mac[ETH_ALEN];  // MAC address of veth1's peer interface
};

/// Open an AF_PACKET raw socket bound to `iface`.
/// Resolves the interface index and MAC address.
/// Calls exit(1) on any fatal error.
RawSocket open_raw_socket(const std::string& iface);
