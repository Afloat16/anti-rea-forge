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

namespace native_asset_detail {

inline constexpr unsigned char info_prefix[] =
    "OpenReleaseGuard\0sealed-asset\0v1\0HKDF-SHA256/AES-256-GCM";
inline constexpr std::size_t max_plaintext = 1024 * 1024;
inline constexpr std::size_t tag_size = 16;

inline bool valid_view(native_asset_view asset) noexcept {
    return asset.ciphertext && asset.aad && asset.ciphertext_size >= tag_size &&
           asset.ciphertext_size <= max_plaintext + tag_size && asset.aad_size > 0 &&
           asset.aad_size <= 1024 - sizeof(info_prefix);
}

}  // namespace native_asset_detail

// output must describe capacity writable bytes, with exclusive access until
// this call returns. It must not overlap the master key, ciphertext or AAD.
// output_size must refer to a separate object outside that buffer.
// Even an empty asset requires a nonnull output and at least one byte of capacity.
// The whole supplied buffer is erased on entry and again after authentication
// failure. A null output or zero capacity is rejected without accessing memory.
inline bool open_native_asset_into(const native_asset_key& master, native_asset_view asset,
                                   unsigned char* output, std::size_t capacity,
                                   std::size_t& output_size) {
    output_size = 0;
    if (!output || capacity == 0) return false;
    OPENSSL_cleanse(output, capacity);
    if (!native_asset_detail::valid_view(asset)) return false;
    const std::size_t payload_size = asset.ciphertext_size - native_asset_detail::tag_size;
    if (payload_size > capacity) return false;

    std::array<unsigned char, 1024> info{};
    std::memcpy(info.data(), native_asset_detail::info_prefix, sizeof(native_asset_detail::info_prefix));
    std::memcpy(info.data() + sizeof(native_asset_detail::info_prefix), asset.aad, asset.aad_size);
    const std::size_t info_size = sizeof(native_asset_detail::info_prefix) + asset.aad_size;
    std::array<unsigned char, 32> package_key{};
    std::array<unsigned char, EVP_MAX_BLOCK_LENGTH> final_block{};
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
        // AES-GCM has a one-byte EVP block size, so Update needs payload_size bytes.
        EVP_DecryptUpdate(cipher.get(), output, &written, asset.ciphertext,
                          static_cast<int>(payload_size)) == 1 &&
        written >= 0 && static_cast<std::size_t>(written) == payload_size &&
        EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_TAG, native_asset_detail::tag_size,
                            const_cast<unsigned char*>(asset.ciphertext + payload_size)) == 1 &&
        EVP_DecryptFinal_ex(cipher.get(), final_block.data(), &final_bytes) == 1 &&
        final_bytes == 0;
    OPENSSL_cleanse(package_key.data(), package_key.size());
    OPENSSL_cleanse(final_block.data(), final_block.size());
    if (!authenticated) {
        OPENSSL_cleanse(output, capacity);
        return false;
    }
    output_size = payload_size;
    return true;
}

inline bool open_native_asset(const native_asset_key& master, native_asset_view asset,
                              std::vector<unsigned char>& output) {
    // A failed call must not leave plaintext from an earlier successful call.
    if (!output.empty()) OPENSSL_cleanse(output.data(), output.size());
    output.clear();
    if (!native_asset_detail::valid_view(asset)) return false;
    const std::size_t payload_size = asset.ciphertext_size - native_asset_detail::tag_size;
    // This compatibility API owns an ordinary allocation. Protected-memory
    // callers can instead pass their existing allocation to the bounded API.
    std::vector<unsigned char> plaintext(payload_size == 0 ? 1 : payload_size);
    std::size_t output_size = 0;
    if (!open_native_asset_into(master, asset, plaintext.data(), plaintext.size(), output_size)) return false;
    plaintext.resize(output_size);
    output.swap(plaintext);
    return true;
}

}  // namespace releaseguard
