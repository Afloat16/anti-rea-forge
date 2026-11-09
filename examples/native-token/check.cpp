// A minimal, offline verifier. Read a single bounded line from standard input.
// Never echo credentials, pass them in argv, or compile them into this file.
#include "releaseguard_token.hpp"
#include <cstdio>
#include <string>

int main() {
    std::string candidate;
    candidate.reserve(69);
    for (int ch; (ch = std::getchar()) != EOF && ch != '\n';) {
        if (candidate.size() == 69) return 1;
        candidate.push_back(static_cast<char>(ch));
    }
    if (std::ferror(stdin)) return 2;
    if (!candidate.empty() && candidate.back() == '\r') candidate.pop_back();
    const bool accepted = releaseguard::verify_issued_token(candidate);
    std::puts(accepted ? "ACCEPTED" : "DENIED");
    return accepted ? 0 : 1;
}
