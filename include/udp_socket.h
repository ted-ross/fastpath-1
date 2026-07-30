#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

// ── UdpSender ─────────────────────────────────────────────────────────────────
// Non-blocking UDP socket pre-connected to a remote host:port.
// send() writes a single datagram.
class UdpSender {
public:
    UdpSender(const std::string& host, uint16_t port);
    ~UdpSender();

    // Returns the number of bytes sent, or -1 on a transient error (EAGAIN).
    // Throws on a hard socket error.
    ssize_t send(const uint8_t* data, size_t len);

private:
    int fd_ = -1;
};

// ── UdpReceiver ───────────────────────────────────────────────────────────────
// Non-blocking UDP socket bound to 0.0.0.0:<port>.
class UdpReceiver {
public:
    explicit UdpReceiver(uint16_t port);
    ~UdpReceiver();

    // File descriptor for use in poll(2).
    int fd() const { return fd_; }

    // Receive one datagram into buf[0..buflen-1].
    // Returns bytes read, 0 if nothing available (EAGAIN), -1 on error.
    ssize_t recv(uint8_t* buf, size_t buflen);

private:
    int fd_ = -1;
};
