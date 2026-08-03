#include "udp_socket.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <iostream>

static void udp_throw(const std::string& msg, int err = errno)
{
    throw std::runtime_error(msg + ": " + std::strerror(err));
}

static void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) udp_throw("fcntl(F_GETFL)");
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        udp_throw("fcntl(F_SETFL O_NONBLOCK)");
}

// ── UdpSender ─────────────────────────────────────────────────────────────────

UdpSender::UdpSender(const std::string& host, uint16_t port)
{
    struct addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), std::to_string(port).c_str(),
                         &hints, &res);
    if (rc != 0)
        throw std::runtime_error(
            "getaddrinfo(" + host + "): " + gai_strerror(rc));

    fd_ = socket(res->ai_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd_ < 0) {
        freeaddrinfo(res);
        udp_throw("socket(SOCK_DGRAM sender)");
    }

    // Pre-connect so that send() / write() can be used without per-call
    // address argument, and so the kernel can route the socket immediately.
    if (connect(fd_, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        udp_throw("connect(UDP sender)");
    }
    freeaddrinfo(res);

    set_nonblocking(fd_);
}

UdpSender::~UdpSender()
{
    if (fd_ >= 0) close(fd_);
}

ssize_t UdpSender::send(const uint8_t* data, size_t len)
{
    std::cout << "Send: length=" << len << "\n";
    ssize_t n = ::send(fd_, data, len, MSG_DONTWAIT);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -1;
        udp_throw("send(UDP)");
    }
    return n;
}

// ── UdpReceiver ───────────────────────────────────────────────────────────────

UdpReceiver::UdpReceiver(uint16_t port)
{
    fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd_ < 0)
        udp_throw("socket(SOCK_DGRAM receiver)");

    // Allow rapid reuse of the port after restart.
    int one = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;   // 0.0.0.0 — accepts from any source

    if (bind(fd_, reinterpret_cast<struct sockaddr*>(&addr),
             sizeof(addr)) != 0)
        udp_throw("bind(UDP receiver port " + std::to_string(port) + ")");

    set_nonblocking(fd_);
}

UdpReceiver::~UdpReceiver()
{
    if (fd_ >= 0) close(fd_);
}

ssize_t UdpReceiver::recv(uint8_t* buf, size_t buflen)
{
    ssize_t n = ::recv(fd_, buf, buflen, MSG_DONTWAIT);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        udp_throw("recv(UDP)");
    }
    std::cout << "Recv: length=" << n << "\n";
    return n;
}
