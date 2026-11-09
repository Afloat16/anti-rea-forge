// C++17/OpenSSL reader for Open Release Guard sealed data assets v1.
// The master key is supplied by the caller. Only authenticated plaintext is returned.
#pragma once

#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace releaseguard {

using native_asset_key = std::array<unsigned char, 32>;

struct native_asset_view {
    std::array<unsigned char, 32> salt;
    std::array<unsigned char, 12> nonce;
    const unsigned char* ciphertext;
    std::size_t ciphertext_size;
    const unsigned char* aad;
    std::size_t aad_size;
};

inline bool open_native_asset(const native_asset_key& master, native_asset_view asset,
                              std::vector<unsigned char>& output) {
    // A failed call must not leave plaintext from an earlier successful call.
    if (!output.empty()) OPENSSL_cleanse(output.data(), output.size());
    output.clear();
    static constexpr unsigned char info_prefix[] =
        "OpenReleaseGuard\0sealed-asset\0v1\0HKDF-SHA256/AES-256-GCM";
    constexpr std::size_t max_plaintext = 1024 * 1024;
    constexpr std::size_t tag_size = 16;
    if (!asset.ciphertext || !asset.aad || asset.ciphertext_size < tag_size ||
        asset.ciphertext_size > max_plaintext + tag_size || asset.aad_size == 0 ||
        asset.aad_size > 1024 - sizeof(info_prefix)) return false;

    std::array<unsigned char, 1024> info{};
    std::memcpy(info.data(), info_prefix, sizeof(info_prefix));
    std::memcpy(info.data() + sizeof(info_prefix), asset.aad, asset.aad_size);
    const std::size_t info_size = sizeof(info_prefix) + asset.aad_size;
    const std::size_t payload_size = asset.ciphertext_size - tag_size;
    // All allocations precede derivation/decryption. swap below cannot throw.
    std::vector<unsigned char> plaintext(payload_size + EVP_MAX_BLOCK_LENGTH);
    std::array<unsigned char, 32> package_key{};
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> derive(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cipher(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    std::size_t key_size = package_key.size();
    int written = 0;
    int final_bytes = 0;
    const bool authenticated = derive && cipher &&
        EVP_PKEY_derive_init(derive.get()) > 0 &&
        EVP_PKEY_CTX_set_hkdf_mode(derive.get(), EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(derive.get(), EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(derive.get(), asset.salt.data(), asset.salt.size()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(derive.get(), master.data(), master.size()) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(derive.get(), info.data(), static_cast<int>(info_size)) > 0 &&
        EVP_PKEY_derive(derive.get(), package_key.data(), &key_size) > 0 &&
        key_size == package_key.size() &&
        EVP_DecryptInit_ex(cipher.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_IVLEN, asset.nonce.size(), nullptr) == 1 &&
        EVP_DecryptInit_ex(cipher.get(), nullptr, nullptr, package_key.data(), asset.nonce.data()) == 1 &&
        EVP_DecryptUpdate(cipher.get(), nullptr, &written, asset.aad, static_cast<int>(asset.aad_size)) == 1 &&
        EVP_DecryptUpdate(cipher.get(), plaintext.data(), &written, asset.ciphertext,
                          static_cast<int>(payload_size)) == 1 &&
        written >= 0 && static_cast<std::size_t>(written) == payload_size &&
        EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_TAG, tag_size,
                            const_cast<unsigned char*>(asset.ciphertext + payload_size)) == 1 &&
        EVP_DecryptFinal_ex(cipher.get(), plaintext.data() + written, &final_bytes) == 1 &&
        final_bytes == 0;
    OPENSSL_cleanse(package_key.data(), package_key.size());
    if (!authenticated) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        return false;
    }
    plaintext.resize(payload_size);
    output.swap(plaintext);
    return true;
}

}  // namespace releaseguard
