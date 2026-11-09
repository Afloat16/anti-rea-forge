// Project-owned Linux ELF fixture. Only the diagnostic control adds a leaked
// reference to the verifier build. "material.hpp" exists solely in the lab.
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include "material.hpp"
#if RG_CASE != 0
#include "releaseguard_token.hpp"
#endif

extern "C" __attribute__((noinline,used)) const char *rg_example_token() {
    return RG_DECOY;
}
#if RG_CASE == 2
extern "C" __attribute__((noinline,used)) const char *rg_mispackaged_diagnostic() {
    return RG_LEAKED_REFERENCE;
}
#endif
extern "C" __attribute__((noinline,used)) int rg_admit(const char *data, std::size_t size) {
#if RG_CASE == 0
    return size == 68 && std::memcmp(data, RG_LEAKED_REFERENCE, 68) == 0;
#else
    return releaseguard::verify_issued_token(std::string_view(data, size));
#endif
}

int main(int argc, char **argv) {
    if (argc == 2 && std::strcmp(argv[1], "--example") == 0) {
        std::puts(rg_example_token());
        return 0;
    }
    if (argc != 1) return 2;
    std::string candidate;
    if (!std::getline(std::cin, candidate)) return 2;
    bool admitted = rg_admit(candidate.data(), candidate.size()) != 0;
    std::puts(admitted ? "ACCEPTED" : "DENIED");
    return admitted ? 0 : 1;
}
