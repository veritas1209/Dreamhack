#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "crypto.h"
#include "prng.h"

namespace mtt {
namespace net {

bool read_exact(int fd, uint8_t* buf, size_t n);
bool write_all(int fd, const uint8_t* buf, size_t n);
bool send_plain(int fd, const std::string& msg);
bool recv_plain_line(int fd, std::string& out, size_t max_len);

bool send_bytes(int fd, const std::vector<uint8_t>& data);
bool recv_bytes(int fd, std::vector<uint8_t>& out, size_t expected);

bool send_encrypted(int fd, const std::vector<uint8_t>& key, const std::string& msg);
bool recv_encrypted(int fd, const std::vector<uint8_t>& key, std::string& out);

bool perform_handshake(int fd, PRNG& rng, std::vector<uint8_t>& session_key);

int create_server_socket(int port);

} // namespace net
} // namespace mtt
