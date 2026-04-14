#include "crypto.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include <openssl/evp.h>
#include <openssl/sha.h>

extern "C" {
#define MLK_CONFIG_FILE "mtt_mlkem_config.h"
#include "mlkem_native.h"
#undef MLK_CONFIG_FILE
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_CIPHERTEXTBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_SYMBYTES

#define MLD_CONFIG_FILE "mtt_mldsa_config.h"
#include "mldsa_native.h"
#undef MLD_CONFIG_FILE

int mtt_mldsa_profile_last_attempts(uint16_t* out);
int mtt_mldsa_profile_select_lane(uint8_t lane);
int mtt_mldsa_profile_fetch_lane(uint8_t lane, uint8_t* out, size_t* outlen);
}

namespace mtt {
namespace {

thread_local PRNG* g_active_rng = nullptr;

class ScopedVendorRng {
public:
    explicit ScopedVendorRng(PRNG& rng) : previous_(g_active_rng) {
        g_active_rng = &rng;
    }

    ~ScopedVendorRng() {
        g_active_rng = previous_;
    }

private:
    PRNG* previous_;
};

std::vector<uint8_t> normalize_key(const std::vector<uint8_t>& key) {
    if (key.size() == AES_KEY_SIZE) {
        return key;
    }

    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(key.data(), key.size(), digest.data());
    return digest;
}

} // namespace

extern "C" int randombytes(uint8_t* out, size_t outlen) {
    if (g_active_rng == nullptr) {
        return -1;
    }

    auto bytes = g_active_rng->random_bytes(outlen);
    for (size_t i = 0; i < outlen; ++i) {
        out[i] = bytes[i];
    }
    return 0;
}

MLKEMKeyPair mlkem_keygen(PRNG& rng) {
    MLKEMKeyPair kp;
    kp.public_key.resize(MLKEM_PK_SIZE);
    kp.secret_key.resize(MLKEM_SK_SIZE);

    ScopedVendorRng scoped(rng);
    if (crypto_kem_keypair(kp.public_key.data(), kp.secret_key.data()) != 0) {
        throw std::runtime_error("ML-KEM key generation failed");
    }

    return kp;
}

std::pair<MLKEMCiphertext, std::vector<uint8_t>>
mlkem_encapsulate(const std::vector<uint8_t>& pk, PRNG& rng) {
    if (pk.size() != MLKEM_PK_SIZE) {
        throw std::invalid_argument("invalid ML-KEM public key size");
    }

    MLKEMCiphertext ct;
    ct.data.resize(MLKEM_CT_SIZE);
    std::vector<uint8_t> ss(SHARED_SECRET_SIZE);

    ScopedVendorRng scoped(rng);
    if (crypto_kem_enc(ct.data.data(), ss.data(), pk.data()) != 0) {
        throw std::runtime_error("ML-KEM encapsulation failed");
    }

    return {ct, ss};
}

std::vector<uint8_t>
mlkem_decapsulate(const MLKEMCiphertext& ct, const std::vector<uint8_t>& sk) {
    if (ct.data.size() != MLKEM_CT_SIZE || sk.size() != MLKEM_SK_SIZE) {
        throw std::invalid_argument("invalid ML-KEM inputs");
    }

    std::vector<uint8_t> ss(SHARED_SECRET_SIZE);
    if (crypto_kem_dec(ss.data(), ct.data.data(), sk.data()) != 0) {
        throw std::runtime_error("ML-KEM decapsulation failed");
    }

    return ss;
}

MLDSAKeyPair mldsa_keygen(PRNG& rng) {
    MLDSAKeyPair kp;
    kp.public_key.resize(MLDSA_PK_SIZE);
    kp.secret_key.resize(MLDSA_SK_SIZE);

    ScopedVendorRng scoped(rng);
    if (crypto_sign_keypair(kp.public_key.data(), kp.secret_key.data()) != 0) {
        throw std::runtime_error("ML-DSA key generation failed");
    }

    return kp;
}

std::vector<uint8_t> mldsa_sign_profiled(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& sk,
    PRNG& rng,
    uint8_t profile_lane,
    MLDSAQuoteMeta& meta_out)
{
    if (sk.size() != MLDSA_SK_SIZE) {
        throw std::invalid_argument("invalid ML-DSA secret key size");
    }
    if (profile_lane >= 4) {
        throw std::invalid_argument("invalid ML-DSA profile lane");
    }

    std::vector<uint8_t> signature(MLDSA_SIG_SIZE);
    size_t siglen = 0;

    ScopedVendorRng scoped(rng);
    if (mtt_mldsa_profile_select_lane(profile_lane) != 0) {
        throw std::runtime_error("failed to select ML-DSA profile lane");
    }
    if (crypto_sign_signature(
            signature.data(),
            &siglen,
            message.data(),
            message.size(),
            nullptr,
            0,
            sk.data()) != 0) {
        throw std::runtime_error("ML-DSA signing failed");
    }

    signature.resize(siglen);

    meta_out.support_code.resize(MLDSA_SUPPORT_CODE_SIZE);
    size_t support_len = meta_out.support_code.size();
    if (mtt_mldsa_profile_last_attempts(&meta_out.attempts_used) != 0 ||
        mtt_mldsa_profile_fetch_lane(profile_lane, meta_out.support_code.data(), &support_len) != 0 ||
        support_len != MLDSA_SUPPORT_CODE_SIZE) {
        throw std::runtime_error("ML-DSA profile extraction failed");
    }

    return signature;
}

std::vector<uint8_t> mldsa_sign(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& sk,
    PRNG& rng)
{
    MLDSAQuoteMeta meta;
    return mldsa_sign_profiled(message, sk, rng, 0, meta);
}

bool mldsa_verify(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& pk)
{
    if (pk.size() != MLDSA_PK_SIZE || signature.size() != MLDSA_SIG_SIZE) {
        return false;
    }

    return crypto_sign_verify(
               signature.data(),
               signature.size(),
               message.data(),
               message.size(),
               nullptr,
               0,
               pk.data()) == 0;
}

std::vector<uint8_t> aes_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key)
{
    const auto normalized_key = normalize_key(key);
    const std::array<uint8_t, 16> iv{};

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("failed to allocate cipher context");
    }

    std::vector<uint8_t> ciphertext(plaintext.size() + 32);
    int out_len1 = 0;
    int out_len2 = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, normalized_key.data(), iv.data()) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len1, plaintext.data(), static_cast<int>(plaintext.size())) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len1, &out_len2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES encryption failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(static_cast<size_t>(out_len1 + out_len2));
    return ciphertext;
}

std::vector<uint8_t> aes_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key)
{
    const auto normalized_key = normalize_key(key);
    const std::array<uint8_t, 16> iv{};

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("failed to allocate cipher context");
    }

    std::vector<uint8_t> plaintext(ciphertext.size() + 32);
    int out_len1 = 0;
    int out_len2 = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, normalized_key.data(), iv.data()) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext.data(), &out_len1, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len1, &out_len2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES decryption failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(static_cast<size_t>(out_len1 + out_len2));
    return plaintext;
}

} // namespace mtt
