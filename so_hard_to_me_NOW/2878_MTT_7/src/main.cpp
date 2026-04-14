#include <iostream>
#include <cstdlib>
#include <csignal>
#include <ctime>
#include <random>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "server.h"
#include "network.h"
#include "prng.h"

static constexpr int DEFAULT_PORT    = 9000;
static constexpr int SESSION_TIMEOUT = 900; // seconds

static void alarm_handler(int) {
    _exit(0);
}

int main(int argc, char* argv[]) {
    int port = DEFAULT_PORT;
    if (argc > 1) {
        port = std::atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            std::cerr << "Invalid port: " << argv[1] << std::endl;
            return 1;
        }
    }

    // Reap children automatically
    signal(SIGCHLD, SIG_IGN);

    int server_fd = mtt::net::create_server_socket(port);
    if (server_fd < 0) {
        std::cerr << "Failed to create server socket on port " << port << std::endl;
        return 1;
    }

    std::cout << "[MTT] Hotel server listening on port " << port << std::endl;

    while (true) {
        struct sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd,
                               reinterpret_cast<struct sockaddr*>(&client_addr),
                               &addr_len);
        if (client_fd < 0) continue;

        pid_t pid = fork();
        if (pid < 0) {
            close(client_fd);
            continue;
        }

        if (pid == 0) {
            // Child process
            close(server_fd);

            // Set session timeout
            signal(SIGALRM, alarm_handler);
            alarm(SESSION_TIMEOUT);

            std::random_device rd;
            uint64_t seed = (static_cast<uint64_t>(rd()) << 32)
                          ^ static_cast<uint64_t>(rd())
                          ^ static_cast<uint64_t>(getpid())
                          ^ static_cast<uint64_t>(time(nullptr));

            mtt::PRNG rng(seed);

            mtt::HotelServer hotel(client_fd, rng);
            hotel.run();

            close(client_fd);
            _exit(0);
        }

        // Parent
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
