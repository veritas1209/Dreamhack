#include "utils.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace mtt {

std::string hex_encode(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

std::vector<uint8_t> hex_decode(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("hex string must have even length");
    }
    std::vector<uint8_t> result(hex.size() / 2);
    for (size_t i = 0; i < result.size(); ++i) {
        const char hi = hex[i * 2];
        const char lo = hex[(i * 2) + 1];
        if (!std::isxdigit(static_cast<unsigned char>(hi)) || !std::isxdigit(static_cast<unsigned char>(lo))) {
            throw std::invalid_argument("hex string contains non-hex characters");
        }
        unsigned int byte;
        std::istringstream(hex.substr(i * 2, 2)) >> std::hex >> byte;
        result[i] = static_cast<uint8_t>(byte);
    }
    return result;
}

std::string bytes_to_string(const std::vector<uint8_t>& data) {
    return std::string(data.begin(), data.end());
}

std::vector<uint8_t> string_to_bytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::string banner() {
    return
        "╔══════════════════════════════════════════╗\n"
        "║                                          ║\n"
        "║            M T T   H O T E L             ║\n"
        "║                                          ║\n"
        "║     Quote Desk / Voucher Desk Online     ║\n"
        "║       100 rooms await one customer.      ║\n"
        "╚══════════════════════════════════════════╝\n";
}

std::string menu() {
    return
        "\n"
        "┌──────────────────────────────┐\n"
        "│         Main Menu            │\n"
        "├──────────────────────────────┤\n"
        "│  [1] Register                │\n"
        "│  [2] Login                   │\n"
        "│  [3] View Rooms              │\n"
        "│  [4] Reserve Room            │\n"
        "│  [5] Cancel Reservation      │\n"
        "│  [6] Account Info            │\n"
        "│  [7] Request Signed Quote    │\n"
        "│  [8] Redeem Credit Voucher   │\n"
        "│  [9] Service Public Key      │\n"
        "│ [10] Get Flag                │\n"
        "│  [0] Exit                    │\n"
        "└──────────────────────────────┘\n"
        "MTT> ";
}

std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

} // namespace mtt
