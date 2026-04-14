#include "prng.h"
#include "subcurve_params.h"

#include <algorithm>
#include <stdexcept>

namespace mtt {
namespace {

using u128 = unsigned __int128;

constexpr uint64_t FIELD_P = MTT_FIELD_P;
constexpr uint64_t CURVE_B   = MTT_CURVE_B;

struct ECPoint {
    uint64_t x = 0;
    uint64_t y = 0;
    bool     inf = true;
};

struct CurveParams {
    uint64_t p;
    int64_t  a;
    uint64_t b;
    ECPoint  P;
    ECPoint  Q;
};

constexpr CurveParams MAIN_CURVE{
    FIELD_P,
    -3,
    CURVE_B,
    {MTT_MAIN_P_X, MTT_MAIN_P_Y, false},
    {MTT_MAIN_Q_X, MTT_MAIN_Q_Y, false},
};

constexpr CurveParams SUB_CURVE{
    FIELD_P,
    -3,
    FIELD_P - CURVE_B,
    {MTT_SUB_P_X, MTT_SUB_P_Y, false},
    {MTT_SUB_Q_X, MTT_SUB_Q_Y, false},
};

uint64_t mod_add(uint64_t a, uint64_t b, uint64_t mod) {
    return static_cast<uint64_t>((static_cast<u128>(a) + b) % mod);
}

uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t mod) {
    return (a >= b) ? (a - b) : (mod - (b - a));
}

uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t mod) {
    return static_cast<uint64_t>((static_cast<u128>(a) * b) % mod);
}

uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t acc = 1;
    while (exp > 0) {
        if (exp & 1U) {
            acc = mod_mul(acc, base, mod);
        }
        base = mod_mul(base, base, mod);
        exp >>= 1U;
    }
    return acc;
}

uint64_t mod_inv(uint64_t x, uint64_t mod) {
    if (x == 0) {
        throw std::runtime_error("attempted inversion of zero");
    }
    return mod_pow(x, mod - 2, mod);
}

bool is_on_curve(const CurveParams& curve, const ECPoint& point) {
    if (point.inf) {
        return true;
    }

    const uint64_t lhs = mod_mul(point.y, point.y, curve.p);
    uint64_t rhs = mod_mul(point.x, point.x, curve.p);
    rhs = mod_mul(rhs, point.x, curve.p);
    rhs = mod_add(rhs, mod_mul(curve.p - 3, point.x, curve.p), curve.p);
    rhs = mod_add(rhs, curve.b, curve.p);
    return lhs == rhs;
}

ECPoint point_double(const CurveParams& curve, const ECPoint& p) {
    if (p.inf || p.y == 0) {
        return {};
    }

    const uint64_t x_sq = mod_mul(p.x, p.x, curve.p);
    const uint64_t numerator = mod_sub(mod_mul(3, x_sq, curve.p), 3 % curve.p, curve.p);
    const uint64_t denominator = mod_inv(mod_mul(2, p.y, curve.p), curve.p);
    const uint64_t slope = mod_mul(numerator, denominator, curve.p);

    const uint64_t x3 = mod_sub(mod_sub(mod_mul(slope, slope, curve.p), p.x, curve.p), p.x, curve.p);
    const uint64_t y3 = mod_sub(mod_mul(slope, mod_sub(p.x, x3, curve.p), curve.p), p.y, curve.p);
    return {x3, y3, false};
}

ECPoint point_add(const CurveParams& curve, const ECPoint& p, const ECPoint& q) {
    if (p.inf) {
        return q;
    }
    if (q.inf) {
        return p;
    }
    if (p.x == q.x) {
        if (mod_add(p.y, q.y, curve.p) == 0) {
            return {};
        }
        return point_double(curve, p);
    }

    const uint64_t numerator = mod_sub(q.y, p.y, curve.p);
    const uint64_t denominator = mod_inv(mod_sub(q.x, p.x, curve.p), curve.p);
    const uint64_t slope = mod_mul(numerator, denominator, curve.p);

    const uint64_t x3 = mod_sub(mod_sub(mod_mul(slope, slope, curve.p), p.x, curve.p), q.x, curve.p);
    const uint64_t y3 = mod_sub(mod_mul(slope, mod_sub(p.x, x3, curve.p), curve.p), p.y, curve.p);
    return {x3, y3, false};
}

ECPoint scalar_mul(const CurveParams& curve, uint64_t scalar, ECPoint point) {
    ECPoint acc{};
    while (scalar > 0) {
        if (scalar & 1U) {
            acc = point_add(curve, acc, point);
        }
        point = point_double(curve, point);
        scalar >>= 1U;
    }
    return acc;
}

} // namespace

PRNG::PRNG()
    : state_(0x12345678deadbeefULL % FIELD_P), bit_pool_(0), bits_left_(0) {
    if (state_ == 0) {
        state_ = 1;
    }
}

PRNG::PRNG(uint64_t seed_value) : PRNG() {
    seed(seed_value);
}

void PRNG::seed(uint64_t s) {
    state_ = s % FIELD_P;
    if (state_ == 0) {
        state_ = 1;
    }
    bit_pool_ = 0;
    bits_left_ = 0;
}

void PRNG::reset_byte_buffer() {
    bit_pool_ = 0;
    bits_left_ = 0;
}

uint64_t PRNG::raw_block() {
    const uint64_t a = state_ & 1U;
    const uint64_t b = (state_ >> 1U) & 1U;

    const CurveParams& output_curve = (b == 0) ? MAIN_CURVE : SUB_CURVE;
    const CurveParams& state_curve = (a == 0) ? MAIN_CURVE : SUB_CURVE;

    const ECPoint out_point = scalar_mul(output_curve, state_, output_curve.Q);
    const ECPoint next_point = scalar_mul(state_curve, state_, state_curve.P);

    if (out_point.inf || next_point.inf || !is_on_curve(output_curve, out_point) || !is_on_curve(state_curve, next_point)) {
        throw std::runtime_error("Invariant violation");
    }

    state_ = next_point.x;
    if (state_ == 0) {
        state_ = 1;
    }
    return out_point.x;
}

uint64_t PRNG::next() {
    return raw_block();
}

uint64_t PRNG::random_bits(std::size_t bits) {
    if (bits == 0 || bits > 32) {
        throw std::invalid_argument("random_bits only supports 1..32 bits");
    }

    uint64_t result = 0;
    std::size_t produced = 0;

    while (produced < bits) {
        if (bits_left_ == 0) {
            bit_pool_ = raw_block();
            bits_left_ = 61;
        }

        const std::size_t take = std::min(bits - produced, bits_left_);
        const uint64_t mask = (take == 64) ? ~0ULL : ((1ULL << take) - 1ULL);
        const uint64_t chunk = bit_pool_ & mask;
        result |= (chunk << produced);

        bit_pool_ >>= take;
        bits_left_ -= take;
        produced += take;
    }

    return result;
}

uint32_t PRNG::uniform_u32(uint32_t bound) {
    if (bound == 0) {
        throw std::invalid_argument("uniform_u32 bound must be non-zero");
    }

    const uint64_t limit = (1ULL << 32) - ((1ULL << 32) % bound);
    while (true) {
        const uint64_t candidate = random_bits(32);
        if (candidate < limit) {
            return static_cast<uint32_t>(candidate % bound);
        }
    }
}

int32_t PRNG::sample_centered(int32_t bound) {
    if (bound < 0) {
        throw std::invalid_argument("sample_centered bound must be non-negative");
    }
    if (bound == 0) {
        return 0;
    }

    const uint32_t span = static_cast<uint32_t>(2 * bound + 1);
    return static_cast<int32_t>(uniform_u32(span)) - bound;
}

std::vector<uint8_t> PRNG::random_bytes(std::size_t n) {
    std::vector<uint8_t> result(n);
    for (std::size_t i = 0; i < n; ++i) {
        result[i] = static_cast<uint8_t>(random_bits(8));
    }
    return result;
}

} // namespace mtt
