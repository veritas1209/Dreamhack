#include "server.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include "network.h"
#include "utils.h"

namespace mtt {
namespace {

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        parts.push_back(item);
    }
    return parts;
}

bool is_ascii_username(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char ch) {
        return std::isalnum(ch) || ch == '_' || ch == '-';
    });
}

} // namespace

HotelServer::HotelServer(int client_fd, PRNG& rng)
    : fd_(client_fd), rng_(rng), service_keys_(mldsa_keygen(rng_)) {
    for (int i = 0; i < NUM_ROOMS; ++i) {
        rooms_[i].id = i;
    }

    std::ifstream flag_file("/flag");
    if (flag_file.is_open()) {
        std::getline(flag_file, flag_);
        while (!flag_.empty() && std::isspace(static_cast<unsigned char>(flag_.back()))) {
            flag_.pop_back();
        }
    } else {
        flag_ = "DH{fake_flag}";
    }
}

User* HotelServer::current_user() {
    if (current_user_index_ < 0 || current_user_index_ >= static_cast<int>(users_.size())) {
        return nullptr;
    }
    return &users_[static_cast<size_t>(current_user_index_)];
}

const User* HotelServer::current_user() const {
    if (current_user_index_ < 0 || current_user_index_ >= static_cast<int>(users_.size())) {
        return nullptr;
    }
    return &users_[static_cast<size_t>(current_user_index_)];
}

void HotelServer::send_msg(const std::string& msg) {
    if (!net::send_encrypted(fd_, session_key_, msg)) {
        running_ = false;
    }
}

std::string HotelServer::recv_msg() {
    std::string msg;
    if (!net::recv_encrypted(fd_, session_key_, msg)) {
        running_ = false;
        return "";
    }
    return trim(msg);
}

void HotelServer::run() {
    if (!net::perform_handshake(fd_, rng_, session_key_)) {
        return;
    }

    send_msg(banner());

    while (running_) {
        send_msg(menu());
        const std::string choice = recv_msg();
        if (!running_) {
            break;
        }

        if (choice == "1") handle_register();
        else if (choice == "2") handle_login();
        else if (choice == "3") handle_view_rooms();
        else if (choice == "4") handle_reserve();
        else if (choice == "5") handle_cancel();
        else if (choice == "6") handle_account_info();
        else if (choice == "7") handle_request_quote();
        else if (choice == "8") handle_redeem_voucher();
        else if (choice == "9") handle_show_service_key();
        else if (choice == "10") handle_check_flag();
        else if (choice == "0") {
            send_msg("Goodbye.\n");
            running_ = false;
        } else {
            send_msg("[!] Invalid option.\n");
        }
    }
}

void HotelServer::handle_register() {
    send_msg("--- Register ---\nUsername: ");
    const std::string username = recv_msg();
    if (!running_) {
        return;
    }

    if (!is_ascii_username(username)) {
        send_msg("[!] Username must be non-empty and contain only [a-zA-Z0-9_-].\n");
        return;
    }

    for (const auto& user : users_) {
        if (user.username == username) {
            send_msg("[!] Username already taken.\n");
            return;
        }
    }

    send_msg("Password: ");
    const std::string password = recv_msg();
    if (!running_) {
        return;
    }

    if (password.empty()) {
        send_msg("[!] Password cannot be empty.\n");
        return;
    }

    users_.push_back(User{username, password, INITIAL_POINTS, {}});

    std::ostringstream oss;
    oss << "\n[+] Registration successful.\n"
        << "    Account: " << username << "\n"
        << "    Balance: " << INITIAL_POINTS << " pts\n"
        << "    Service signing key is shared globally. Use [7]/[8] wisely.\n";
    send_msg(oss.str());
}

void HotelServer::handle_login() {
    send_msg("--- Login ---\nUsername: ");
    const std::string username = recv_msg();
    if (!running_) {
        return;
    }

    send_msg("Password: ");
    const std::string password = recv_msg();
    if (!running_) {
        return;
    }

    for (size_t i = 0; i < users_.size(); ++i) {
        if (users_[i].username == username && users_[i].password == password) {
            current_user_index_ = static_cast<int>(i);

            std::ostringstream oss;
            oss << "\n[+] Welcome back, " << username << ".\n"
                << "    Balance: " << users_[i].points << " pts\n"
                << "    Rooms reserved: " << users_[i].reserved_rooms.size() << "\n";
            send_msg(oss.str());
            return;
        }
    }

    send_msg("[!] Invalid credentials.\n");
}

void HotelServer::handle_view_rooms() {
    int available = 0;
    for (const auto& room : rooms_) {
        if (!room.occupied) {
            ++available;
        }
    }

    std::ostringstream oss;
    oss << "\n--- Room Status (Available: " << available << "/" << NUM_ROOMS << ") ---\n";

    for (int i = 0; i < NUM_ROOMS; ++i) {
        if (i % 10 == 0) {
            oss << "\n";
        }
        oss << "[" << std::setw(2) << i << "]" << (rooms_[i].occupied ? "●  " : "○  ");
    }
    oss << "\n\n○ = Available (" << ROOM_PRICE << " pts)  ● = Occupied\n";

    bool printed = false;
    for (const auto& room : rooms_) {
        if (!room.occupied) {
            continue;
        }
        if (!printed) {
            printed = true;
            oss << "\nOccupied rooms:\n";
        }
        oss << "  Room " << std::setw(2) << room.id << ": " << room.occupant << "\n";
    }

    send_msg(oss.str());
}

void HotelServer::handle_reserve() {
    User* user = current_user();
    if (!user) {
        send_msg("[!] Please login first.\n");
        return;
    }

    send_msg("Room number (0-99): ");
    const std::string room_str = recv_msg();
    if (!running_) {
        return;
    }

    int room_id = -1;
    try {
        room_id = std::stoi(room_str);
    } catch (...) {
        send_msg("[!] Invalid room number.\n");
        return;
    }

    if (room_id < 0 || room_id >= NUM_ROOMS) {
        send_msg("[!] Room number must be 0-99.\n");
        return;
    }
    if (rooms_[room_id].occupied) {
        send_msg("[!] Room already occupied.\n");
        return;
    }
    if (user->points < ROOM_PRICE) {
        send_msg("[!] Not enough points.\n");
        return;
    }

    user->points -= ROOM_PRICE;
    user->reserved_rooms.insert(room_id);
    rooms_[room_id].occupied = true;
    rooms_[room_id].occupant = user->username;

    std::ostringstream oss;
    oss << "\n[+] Room " << room_id << " reserved.\n"
        << "    Balance: " << user->points << " pts\n";
    send_msg(oss.str());
}

void HotelServer::handle_cancel() {
    User* user = current_user();
    if (!user) {
        send_msg("[!] Please login first.\n");
        return;
    }
    if (user->reserved_rooms.empty()) {
        send_msg("[!] You have no reservations.\n");
        return;
    }

    send_msg("Room number to cancel: ");
    const std::string room_str = recv_msg();
    if (!running_) {
        return;
    }

    int room_id = -1;
    try {
        room_id = std::stoi(room_str);
    } catch (...) {
        send_msg("[!] Invalid room number.\n");
        return;
    }

    if (user->reserved_rooms.find(room_id) == user->reserved_rooms.end()) {
        send_msg("[!] That room is not reserved by your account.\n");
        return;
    }

    user->points += ROOM_PRICE;
    user->reserved_rooms.erase(room_id);
    rooms_[room_id].occupied = false;
    rooms_[room_id].occupant.clear();

    std::ostringstream oss;
    oss << "\n[+] Room " << room_id << " cancelled.\n"
        << "    Refunded: " << ROOM_PRICE << " pts\n"
        << "    Balance: " << user->points << " pts\n";
    send_msg(oss.str());
}

void HotelServer::handle_account_info() {
    const User* user = current_user();
    if (!user) {
        send_msg("[!] Please login first.\n");
        return;
    }

    std::ostringstream oss;
    oss << "\n--- Account Info (" << user->username << ") ---\n"
        << "  Balance:        " << user->points << " pts\n"
        << "  Rooms reserved: " << user->reserved_rooms.size() << "\n"
        << "  Redeemed serials tracked globally per session.\n";

    if (!user->reserved_rooms.empty()) {
        oss << "  Room list:      ";
        for (int id : user->reserved_rooms) {
            oss << id << " ";
        }
        oss << "\n";
    }

    send_msg(oss.str());
}

void HotelServer::handle_request_quote() {
    const User* user = current_user();
    if (!user) {
        send_msg("[!] Please login first.\n");
        return;
    }

    send_msg("Quoted room number (0-99): ");
    const std::string room_str = recv_msg();
    if (!running_) {
        return;
    }

    int room_id = -1;
    try {
        room_id = std::stoi(room_str);
    } catch (...) {
        send_msg("[!] Invalid room number.\n");
        return;
    }
    if (room_id < 0 || room_id >= NUM_ROOMS) {
        send_msg("[!] Room number must be 0-99.\n");
        return;
    }

    send_msg("Custom note (hex, max 64 bytes): ");
    const std::string note_hex = recv_msg();
    if (!running_) {
        return;
    }

    std::vector<uint8_t> note_bytes;
    try {
        note_bytes = hex_decode(note_hex);
    } catch (...) {
        send_msg("[!] Invalid hex note.\n");
        return;
    }
    if (note_bytes.size() > 64) {
        send_msg("[!] Note too long.\n");
        return;
    }

    const uint64_t quote_index = quote_counter_++;
    const uint8_t profile_lane = static_cast<uint8_t>(quote_index & 0x03u);

    std::ostringstream msg_oss;
    msg_oss << "QUOTE|" << user->username
            << "|" << room_id
            << "|" << ROOM_PRICE
            << "|" << quote_index
            << "|" << note_hex;
    const std::string message = msg_oss.str();
    const auto message_bytes = string_to_bytes(message);
    MLDSAQuoteMeta meta;
    const auto signature = mldsa_sign_profiled(
        message_bytes, service_keys_.secret_key, rng_, profile_lane, meta);
    receipt_ticket_ += meta.attempts_used;
    auto mask = rng_.random_bytes(meta.support_code.size());
    for (size_t i = 0; i < meta.support_code.size(); ++i) {
        meta.support_code[i] ^= mask[i];
    }

    std::ostringstream oss;
    oss << "\n[+] Signed quote generated.\n"
        << "    Message (hex):   " << hex_encode(message_bytes) << "\n"
        << "    Signature (hex): " << hex_encode(signature) << "\n"
        << "    Receipt id:      " << receipt_ticket_ << "\n"
        << "    Reference code:  " << hex_encode(meta.support_code) << "\n";
    send_msg(oss.str());
}

void HotelServer::handle_redeem_voucher() {
    User* user = current_user();
    if (!user) {
        send_msg("[!] Please login first.\n");
        return;
    }

    send_msg("Voucher message (hex): ");
    const std::string msg_hex = recv_msg();
    if (!running_) {
        return;
    }

    send_msg("Voucher signature (hex): ");
    const std::string sig_hex = recv_msg();
    if (!running_) {
        return;
    }

    std::vector<uint8_t> message_bytes;
    std::vector<uint8_t> signature;
    try {
        message_bytes = hex_decode(msg_hex);
        signature = hex_decode(sig_hex);
    } catch (...) {
        send_msg("[!] Invalid hex input.\n");
        return;
    }

    if (!mldsa_verify(message_bytes, signature, service_keys_.public_key)) {
        send_msg("[!] Signature verification failed.\n");
        return;
    }

    const std::string message = bytes_to_string(message_bytes);
    const auto parts = split(message, '|');
    if (parts.size() != 4 || parts[0] != "CREDIT") {
        send_msg("[!] Voucher type mismatch. Expected CREDIT|user|amount|serial.\n");
        return;
    }
    if (parts[1] != user->username) {
        send_msg("[!] Voucher bound to another user.\n");
        return;
    }
    if (parts[3].empty()) {
        send_msg("[!] Serial cannot be empty.\n");
        return;
    }
    if (redeemed_serials_.count(parts[3]) != 0) {
        send_msg("[!] Serial already redeemed.\n");
        return;
    }

    int64_t amount = 0;
    try {
        amount = std::stoll(parts[2]);
    } catch (...) {
        send_msg("[!] Invalid credit amount.\n");
        return;
    }

    if (amount <= 0 || amount > 500000) {
        send_msg("[!] Credit amount must be in [1, 500000].\n");
        return;
    }

    redeemed_serials_.insert(parts[3]);
    user->points += amount;

    std::ostringstream oss;
    oss << "\n[+] Voucher redeemed.\n"
        << "    +" << amount << " pts\n"
        << "    Balance: " << user->points << " pts\n";
    send_msg(oss.str());
}

void HotelServer::handle_show_service_key() {
    std::ostringstream oss;
    oss << "\n--- Service ML-DSA Public Key ---\n"
        << "  pk(hex): " << hex_encode(service_keys_.public_key) << "\n"
        << "  format:  exact ML-DSA-44 packed public key (" << MLDSA_PK_SIZE << " bytes)\n"
        << "  note:    quote signatures and credit vouchers use the same key.\n";
    send_msg(oss.str());
}

void HotelServer::handle_check_flag() {
    const User* user = current_user();
    if (!user) {
        send_msg("[!] Please login first.\n");
        return;
    }

    int count = 0;
    for (const auto& room : rooms_) {
        if (room.occupied && room.occupant == user->username) {
            ++count;
        }
    }

    std::ostringstream oss;
    if (count == NUM_ROOMS) {
        oss << "FLAG: " << flag_ << "\n";
    } else {
        oss << "You have reserved " << count << "/" << NUM_ROOMS << " rooms.\n";
    }
    send_msg(oss.str());
}

} // namespace mtt
