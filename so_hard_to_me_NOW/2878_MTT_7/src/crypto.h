#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include "prng.h"

namespace mtt {

constexpr size_t MLKEM_PK_SIZE      = 800;   // ML-KEM-512
constexpr size_t MLKEM_SK_SIZE      = 1632;  // ML-KEM-512
constexpr size_t MLKEM_CT_SIZE      = 768;   // ML-KEM-512
constexpr size_t SHARED_SECRET_SIZE = 32;

constexpr size_t MLDSA_PK_SIZE      = 1312;  // ML-DSA-44
constexpr size_t MLDSA_SK_SIZE      = 2560;  // ML-DSA-44
constexpr size_t MLDSA_SIG_SIZE     = 2420;  // ML-DSA-44
constexpr size_t MLDSA_SUPPORT_CODE_SIZE = 128; // packed lane-local c*t0 mod 16

struct MLKEMKeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
};

struct MLKEMCiphertext {
    std::vector<uint8_t> data;
};

struct MLDSAKeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
};

struct MLDSAQuoteMeta {
    uint16_t attempts_used = 0;
    std::vector<uint8_t> support_code;
};

MLKEMKeyPair mlkem_keygen(PRNG& rng);

std::pair<MLKEMCiphertext, std::vector<uint8_t>>
mlkem_encapsulate(const std::vector<uint8_t>& pk, PRNG& rng);

std::vector<uint8_t>
mlkem_decapsulate(const MLKEMCiphertext& ct, const std::vector<uint8_t>& sk);

MLDSAKeyPair mldsa_keygen(PRNG& rng);

std::vector<uint8_t> mldsa_sign(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& sk,
    PRNG& rng);

std::vector<uint8_t> mldsa_sign_profiled(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& sk,
    PRNG& rng,
    uint8_t profile_lane,
    MLDSAQuoteMeta& meta_out);

bool mldsa_verify(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& pk);

constexpr size_t AES_KEY_SIZE = 32;

std::vector<uint8_t> aes_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key);

std::vector<uint8_t> aes_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key);

} // namespace mtt
