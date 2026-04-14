#include "network.h"
#include "utils.h"

#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

namespace mtt {
namespace net {

static constexpr size_t MAX_MSG_SIZE = 65536;
static constexpr size_t TRACE_BLOCKS = 8;

bool read_exact(int fd, uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, buf + total, n - total);
        if (r <= 0) return false;
        total += static_cast<size_t>(r);
    }
    return true;
}

bool write_all(int fd, const uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t w = write(fd, buf + total, n - total);
        if (w <= 0) return false;
        total += static_cast<size_t>(w);
    }
    return true;
}

bool send_plain(int fd, const std::string& msg) {
    return write_all(fd, reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
}

bool recv_plain_line(int fd, std::string& out, size_t max_len) {
    out.clear();
    while (out.size() < max_len) {
        uint8_t ch = 0;
        ssize_t r = read(fd, &ch, 1);
        if (r <= 0) {
            return false;
        }
        if (ch == '\n') {
            return true;
        }
        if (ch != '\r') {
            out.push_back(static_cast<char>(ch));
        }
    }
    return false;
}

bool send_bytes(int fd, const std::vector<uint8_t>& data) {
    uint32_t len = htonl(static_cast<uint32_t>(data.size()));
    if (!write_all(fd, reinterpret_cast<uint8_t*>(&len), 4)) return false;
    if (!data.empty()) {
        if (!write_all(fd, data.data(), data.size())) return false;
    }
    return true;
}

bool recv_bytes(int fd, std::vector<uint8_t>& out, size_t expected) {
    uint32_t net_len;
    if (!read_exact(fd, reinterpret_cast<uint8_t*>(&net_len), 4)) return false;
    uint32_t len = ntohl(net_len);
    if (len > MAX_MSG_SIZE) return false;
    if (expected > 0 && len != static_cast<uint32_t>(expected)) return false;
    out.resize(len);
    return read_exact(fd, out.data(), len);
}

bool send_encrypted(int fd, const std::vector<uint8_t>& key, const std::string& msg) {
    try {
        auto plaintext = string_to_bytes(msg);
        auto ciphertext = aes_encrypt(plaintext, key);
        return send_bytes(fd, ciphertext);
    } catch (...) {
        return false;
    }
}

bool recv_encrypted(int fd, const std::vector<uint8_t>& key, std::string& out) {
    std::vector<uint8_t> ciphertext;
    if (!recv_bytes(fd, ciphertext, 0)) return false;
    try {
        auto plaintext = aes_decrypt(ciphertext, key);
        out = bytes_to_string(plaintext);
        return true;
    } catch (...) {
        return false;
    }
}

bool perform_handshake(int fd, PRNG& rng, std::vector<uint8_t>& session_key) {
    try {
        static const std::string kPrelude =
            "MTT Hotel Transport\n"
            "This service switches to an ML-KEM/AES session before the menu.\n"
            "Type START and press Enter to begin the secure handshake.\n";
        static const std::string kHandshakeNotice =
            "[*] Switching to secure handshake...\n";
        std::string line;

        if (!send_plain(fd, kPrelude)) return false;
        while (true) {
            if (!recv_plain_line(fd, line, 128)) return false;
            line = trim(line);
            if (line == "START" || line == "start") {
                break;
            }
            if (!send_plain(fd, "[!] Type START to begin.\n")) return false;
        }
        if (!send_plain(fd, kHandshakeNotice)) return false;

        rng.reset_byte_buffer();
        std::vector<uint8_t> trace(TRACE_BLOCKS * 8, 0);
        for (size_t i = 0; i < TRACE_BLOCKS; ++i) {
            const uint64_t block = rng.next();
            for (size_t j = 0; j < 8; ++j) {
                trace[(i * 8) + j] = static_cast<uint8_t>(block >> (8 * j));
            }
        }
        if (!send_bytes(fd, trace)) return false;

        auto kem_kp = mlkem_keygen(rng);
        if (!send_bytes(fd, kem_kp.public_key)) return false;

        std::vector<uint8_t> ct_data;
        if (!recv_bytes(fd, ct_data, MLKEM_CT_SIZE)) return false;

        MLKEMCiphertext ct;
        ct.data = std::move(ct_data);
        session_key = mlkem_decapsulate(ct, kem_kp.secret_key);
        return true;
    } catch (...) {
        return false;
    }
}

int create_server_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(static_cast<uint16_t>(port));

    if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

} // namespace net
} // namespace mtt
