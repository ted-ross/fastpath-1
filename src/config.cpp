#include "config.h"

#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <stdexcept>
#include <string>

static void print_usage(const char* prog)
{
    fprintf(stderr,
        "Usage: %s --iface <name> --dest-host <ip> --dest-port <port> --recv-port <port>\n"
        "\n"
        "Options:\n"
        "  --iface      <name>   Network interface to attach TC egress to (e.g. eth0)\n"
        "  --dest-host  <ip>     Remote tunnel endpoint IP address\n"
        "  --dest-port  <port>   Remote tunnel endpoint UDP port\n"
        "  --recv-port  <port>   Local UDP port to receive tunnel datagrams on\n"
        "  --help                Show this help and exit\n",
        prog);
}

Config parse_args(int argc, char** argv)
{
    static const struct option long_opts[] = {
        { "iface",     required_argument, nullptr, 'i' },
        { "dest-host", required_argument, nullptr, 'd' },
        { "dest-port", required_argument, nullptr, 'p' },
        { "recv-port", required_argument, nullptr, 'r' },
        { "help",      no_argument,       nullptr, 'h' },
        { nullptr,     0,                 nullptr,  0  },
    };

    Config cfg{};
    int opt;
    int opt_idx = 0;

    while ((opt = getopt_long(argc, argv, "", long_opts, &opt_idx)) != -1) {
        switch (opt) {
        case 'i':
            cfg.iface = optarg;
            break;
        case 'd':
            cfg.dest_host = optarg;
            break;
        case 'p': {
            long v = std::strtol(optarg, nullptr, 10);
            if (v <= 0 || v > 65535)
                throw std::invalid_argument("--dest-port must be 1-65535");
            cfg.dest_port = static_cast<uint16_t>(v);
            break;
        }
        case 'r': {
            long v = std::strtol(optarg, nullptr, 10);
            if (v <= 0 || v > 65535)
                throw std::invalid_argument("--recv-port must be 1-65535");
            cfg.recv_port = static_cast<uint16_t>(v);
            break;
        }
        case 'h':
            print_usage(argv[0]);
            exit(0);
        default:
            print_usage(argv[0]);
            exit(1);
        }
    }

    bool ok = true;
    if (cfg.iface.empty())     { fprintf(stderr, "error: --iface is required\n");     ok = false; }
    if (cfg.dest_host.empty()) { fprintf(stderr, "error: --dest-host is required\n"); ok = false; }
    if (cfg.dest_port == 0)    { fprintf(stderr, "error: --dest-port is required\n"); ok = false; }
    if (cfg.recv_port == 0)    { fprintf(stderr, "error: --recv-port is required\n"); ok = false; }

    if (!ok) {
        print_usage(argv[0]);
        exit(1);
    }

    return cfg;
}
