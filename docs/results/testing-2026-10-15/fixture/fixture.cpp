#include <cstdio>
#include <cstring>
#include <releaseguard/literal.hpp>
__attribute__((noinline)) bool allowed(const char* input) {
    auto expected = RG_TEXT("RG_TEST_799b7bc55fbdf397165aa99368c53fb2");
    return std::strcmp(input, expected.c_str()) == 0;
}
int main(int argc,char** argv) {
    if (argc != 2) { std::puts("USAGE: sample VALUE"); return 2; }
    if (allowed(argv[1])) {std::puts("ACCEPTED"); return 0;}
    std::puts("DENIED"); return 1;
}
