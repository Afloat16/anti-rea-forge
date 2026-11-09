// Offline verifier for high-entropy, issuer-generated native tokens.
// Requires C++17 and OpenSSL libcrypto. The digest is public and patchable.
#pragma once

#include <array>
#include <string_view>

#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace releaseguard {

using native_token_digest = std::array<unsigned char, 32>;

inline bool verify_native_token(std::string_view candidate,
                                const native_token_digest& expected) noexcept {
    // Reject noncanonical forms, whitespace and embedded NULs. No strlen or
    // implicit trimming: the caller controls the length of the input view.
    if (candidate.size() != 68 || candidate.substr(0, 4) != "rg1_") return false;
    for (const char c : candidate.substr(4)) {
        if (!(('0' <= c && c <= '9') || ('a' <= c && c <= 'f'))) return false;
    }

    // sizeof includes exactly one trailing NUL, as in the Python issuer.
    static constexpr char domain[] = "OpenReleaseGuard/native-token/v1";
    unsigned char actual[EVP_MAX_MD_SIZE] = {};
    unsigned int length = 0;
    const EVP_MD* algorithm = EVP_sha256();
    if (!algorithm) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    const bool computed =
        EVP_DigestInit_ex(ctx, algorithm, nullptr) == 1 &&
        EVP_DigestUpdate(ctx, domain, sizeof(domain)) == 1 &&
        EVP_DigestUpdate(ctx, candidate.data(), candidate.size()) == 1 &&
        EVP_DigestFinal_ex(ctx, actual, &length) == 1;
    EVP_MD_CTX_free(ctx);
    const bool accepted = computed && length == expected.size() &&
                          CRYPTO_memcmp(actual, expected.data(), expected.size()) == 0;
    OPENSSL_cleanse(actual, sizeof(actual));
    return accepted;
}

}  // namespace releaseguard
