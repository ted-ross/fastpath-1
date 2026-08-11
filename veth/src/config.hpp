#pragma once

#include <cstdint>
#include <string>

struct Config {
    std::string peer_ip;
    uint16_t    peer_port;
    uint16_t    local_port;
};

/// Parse and validate command-line arguments.
/// Prints usage to stderr and calls exit(1) on any error.
Config parse_args(int argc, char* argv[]);
