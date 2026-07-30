#pragma once

#include <cstdint>
#include <string>

struct Config {
    std::string iface;       // network interface to attach XDP to
    std::string dest_host;   // remote tunnel endpoint IP/hostname
    uint16_t    dest_port;   // remote tunnel endpoint UDP port
    uint16_t    recv_port;   // local UDP port to receive tunnel traffic on
};

Config parse_args(int argc, char** argv);
