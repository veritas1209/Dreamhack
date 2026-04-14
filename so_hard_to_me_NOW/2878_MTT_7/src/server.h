#pragma once

#include <array>
#include <set>
#include <string>
#include <vector>

#include "crypto.h"
#include "prng.h"

namespace mtt {

constexpr int     NUM_ROOMS      = 100;
constexpr int64_t INITIAL_POINTS = 5000;
constexpr int64_t ROOM_PRICE     = 1000;

struct User {
    std::string username;
    std::string password;
    int64_t     points = INITIAL_POINTS;
    std::set<int> reserved_rooms;
};

struct Room {
    int         id = 0;
    bool        occupied = false;
    std::string occupant;
};

class HotelServer {
public:
    HotelServer(int client_fd, PRNG& rng);
    void run();

private:
    void        send_msg(const std::string& msg);
    std::string recv_msg();
    User*       current_user();
    const User* current_user() const;

    void handle_register();
    void handle_login();
    void handle_view_rooms();
    void handle_reserve();
    void handle_cancel();
    void handle_account_info();
    void handle_request_quote();
    void handle_redeem_voucher();
    void handle_show_service_key();
    void handle_check_flag();

    int                         fd_;
    PRNG&                       rng_;
    std::vector<uint8_t>        session_key_;
    std::vector<User>           users_;
    int                         current_user_index_ = -1;
    std::array<Room, NUM_ROOMS> rooms_;
    MLDSAKeyPair                service_keys_;
    std::set<std::string>       redeemed_serials_;
    uint64_t                    quote_counter_ = 0;
    uint64_t                    receipt_ticket_ = 0;

    std::string flag_;
    bool        running_ = true;
};

} // namespace mtt
