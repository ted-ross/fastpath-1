#include "udp_socket.hpp"

#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <iostream>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

UdpSocket open_udp_socket(uint16_t local_port,
                          const std::string& peer_ip,
                          uint16_t peer_port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        std::cerr << "error: socket(AF_INET, SOCK_DGRAM): "
                  << std::strerror(errno) << "\n";
        std::exit(1);
    }

    // Bind to the local port on all interfaces.
    struct sockaddr_in local{};
    local.sin_family      = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port        = htons(local_port);
    if (bind(fd, reinterpret_cast<struct sockaddr*>(&local), sizeof(local)) < 0) {
        std::cerr << "error: bind UDP port " << local_port << ": "
                  << std::strerror(errno) << "\n";
        close(fd);
        std::exit(1);
    }

    // Set non-blocking.
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        std::cerr << "error: fcntl O_NONBLOCK on UDP socket: "
                  << std::strerror(errno) << "\n";
        close(fd);
        std::exit(1);
    }

    // Resolve peer address.
    struct sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port   = htons(peer_port);
    if (inet_pton(AF_INET, peer_ip.c_str(), &peer.sin_addr) != 1) {
        std::cerr << "error: invalid peer IP address '" << peer_ip << "'\n";
        close(fd);
        std::exit(1);
    }

    std::cout << "udp socket: listening on port " << local_port
              << ", peer " << peer_ip << ":" << peer_port << "\n";

    UdpSocket us{};
    us.fd        = fd;
    us.peer_addr = peer;
    return us;
}
