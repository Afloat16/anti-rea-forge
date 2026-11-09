// Compile after native-asset-export, then pipe the external raw 32-byte key to stdin.
#include "releaseguard_asset.hpp"

#include <cstdio>
#include <exception>
#include <iostream>
#include <vector>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

int main() {
#if defined(_WIN32)
    if (_setmode(_fileno(stdin), _O_BINARY) == -1 ||
        _setmode(_fileno(stdout), _O_BINARY) == -1) return 2;
#endif
    releaseguard::native_asset_key key{};
    std::vector<unsigned char> plaintext;
    int status = 2;
    try {
        std::cin.read(reinterpret_cast<char*>(key.data()), key.size());
        if (std::cin.gcount() == static_cast<std::streamsize>(key.size()) &&
            std::cin.peek() == std::char_traits<char>::eof() && !std::cin.bad()) {
            if (releaseguard::open_embedded_asset(key, plaintext)) {
                // Replace this output with the application's data consumer.
                if (!plaintext.empty()) {
                    std::cout.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
                }
                std::cout.flush();
                status = std::cout ? 0 : 2;
            } else {
                status = 3;
            }
        }
    } catch (const std::exception&) {
        status = 2;
    }
    OPENSSL_cleanse(key.data(), key.size());
    if (!plaintext.empty()) OPENSSL_cleanse(plaintext.data(), plaintext.size());
    return status;
}
