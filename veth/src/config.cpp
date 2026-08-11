#include "config.hpp"

#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <iostream>

static void print_usage(const char* prog)
{
    std::cerr << "Usage: " << prog
              << " --peer-ip <IP> --peer-port <PORT> --local-port <PORT> [--debug]\n"
              << "\n"
              << "  --peer-ip    <IP>    IPv4 address of the remote peer\n"
              << "  --peer-port  <PORT>  UDP port on the remote peer (1-65535)\n"
              << "  --local-port <PORT>  UDP port to listen on (1-65535)\n"
              << "  --debug              Enable per-packet trace logging to stdout\n";
}

static uint16_t parse_port(const char* str, const char* name)
{
    char* end = nullptr;
    long val = std::strtol(str, &end, 10);
    if (end == str || *end != '\0' || val < 1 || val > 65535) {
        std::cerr << "error: " << name << " must be an integer in the range 1-65535\n";
        std::exit(1);
    }
    return static_cast<uint16_t>(val);
}

Config parse_args(int argc, char* argv[])
{
    static const struct option long_opts[] = {
        {"peer-ip",    required_argument, nullptr, 'i'},
        {"peer-port",  required_argument, nullptr, 'p'},
        {"local-port", required_argument, nullptr, 'l'},
        {"debug",      no_argument,       nullptr, 'd'},
        {nullptr,      0,                 nullptr,  0 }
    };

    Config cfg{};
    bool have_peer_ip    = false;
    bool have_peer_port  = false;
    bool have_local_port = false;

    int opt;
    while ((opt = getopt_long(argc, argv, "", long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'i':
                cfg.peer_ip = optarg;
                have_peer_ip = true;
                break;
            case 'p':
                cfg.peer_port = parse_port(optarg, "--peer-port");
                have_peer_port = true;
                break;
            case 'l':
                cfg.local_port = parse_port(optarg, "--local-port");
                have_local_port = true;
                break;
            case 'd':
                cfg.debug = true;
                break;
            default:
                print_usage(argv[0]);
                std::exit(1);
        }
    }

    if (!have_peer_ip || !have_peer_port || !have_local_port) {
        std::cerr << "error: --peer-ip, --peer-port, and --local-port are all required\n";
        print_usage(argv[0]);
        std::exit(1);
    }

    if (cfg.peer_ip.empty()) {
        std::cerr << "error: --peer-ip must not be empty\n";
        std::exit(1);
    }

    return cfg;
}
