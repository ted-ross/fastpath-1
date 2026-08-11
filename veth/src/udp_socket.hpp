#pragma once

#include <cstdint>
#include <string>
#include <netinet/in.h>

/// Holds the UDP socket file descriptor and the resolved peer address.
struct UdpSocket {
    int             fd;
    struct sockaddr_in peer_addr;
};

/// Open and bind a non-blocking UDP socket on `local_port`.
/// Resolves the peer address from `peer_ip` and `peer_port`.
/// Calls exit(1) on any fatal error.
UdpSocket open_udp_socket(uint16_t local_port,
                          const std::string& peer_ip,
                          uint16_t peer_port);
