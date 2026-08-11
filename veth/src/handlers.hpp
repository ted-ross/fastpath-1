#pragma once

#include <netinet/in.h>
#include <cstdint>

/// Read one Ethernet frame from `raw_fd` (veth1).
/// If it is an IPv4 frame (EtherType 0x0800), strip the Ethernet header
/// and forward the IP payload as a UDP datagram to `peer`.
/// Non-IPv4 frames and frames that are too short are silently dropped.
void handle_raw_input(int raw_fd, int udp_fd, const struct sockaddr_in& peer);

/// Read one UDP datagram from `udp_fd`.
/// Prepend a synthetic Ethernet header (veth1 MAC as both src and dst,
/// EtherType 0x0800) and inject the resulting frame into veth1 via `raw_fd`.
void handle_udp_input(int udp_fd, int raw_fd,
                      int iface_index, const uint8_t mac[6]);
