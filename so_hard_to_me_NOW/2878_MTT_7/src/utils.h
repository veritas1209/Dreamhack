#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace mtt {

std::string hex_encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> hex_decode(const std::string& hex);

std::string bytes_to_string(const std::vector<uint8_t>& data);
std::vector<uint8_t> string_to_bytes(const std::string& str);

std::string banner();
std::string menu();

std::string trim(const std::string& s);

} // namespace mtt
