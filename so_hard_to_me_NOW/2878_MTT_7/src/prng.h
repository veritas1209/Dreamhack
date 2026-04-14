#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace mtt {

class PRNG {
public:
    PRNG();
    explicit PRNG(uint64_t seed);

    void seed(uint64_t s);
    uint64_t next();
    uint64_t random_bits(std::size_t bits);
    uint32_t uniform_u32(uint32_t bound);
    int32_t sample_centered(int32_t bound);
    std::vector<uint8_t> random_bytes(std::size_t n);
    void reset_byte_buffer();

private:
    uint64_t raw_block();

    uint64_t state_;
    uint64_t bit_pool_;
    std::size_t bits_left_;
};

} // namespace mtt
