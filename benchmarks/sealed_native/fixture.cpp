// Synthetic data only. The key is supplied as exactly 32 stdin bytes.
#include <array>
#include <cstdio>
#include <vector>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include "releaseguard_asset.hpp"
#include "material.hpp"

volatile unsigned char rg_diagnostic_sink;

extern "C" __attribute__((noinline)) int rg_asset_gate(const releaseguard::native_asset_key& key) {
    std::array<unsigned char, 32> digest{};
    if (SHA256(key.data(), key.size(), digest.data()) == nullptr) return 0;
    return CRYPTO_memcmp(digest.data(), expected_key_digest, digest.size()) == 0;
}

int main() {
    for (unsigned char value : public_decoy) rg_diagnostic_sink = value;
#if RG_CASE == 2
    for (unsigned char value : accidentally_bundled_key) rg_diagnostic_sink = value;
#endif
    releaseguard::native_asset_key key{};
    if (std::fread(key.data(), 1, key.size(), stdin) != key.size() || std::fgetc(stdin) != EOF) return 2;
    if (!rg_asset_gate(key)) return 1;
    std::vector<unsigned char> output;
#if RG_CASE == 0
    output.assign(ordinary_plaintext, ordinary_plaintext + sizeof ordinary_plaintext);
#else
    if (!releaseguard::open_embedded_asset(key, output)) return 1;
#endif
    OPENSSL_cleanse(key.data(), key.size());
    return std::fwrite(output.data(), 1, output.size(), stdout) == output.size() ? 0 : 2;
}
