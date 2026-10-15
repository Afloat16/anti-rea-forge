#include <iostream>

#ifdef RELEASEGUARD_EXAMPLE_PROTECTED
#include "releaseguard_build.hpp"
#include <releaseguard/literal.hpp>
#endif

int main()
{
    std::cout << "ReleaseGuard example: build mitigations enabled.\n";
#ifdef RELEASEGUARD_EXAMPLE_PROTECTED
    // Keep the decoded object alive for the entire use of its c_str() buffer.
    auto message = RG_TEXT("releaseguard-demo-private-literal");
    std::cout << message.c_str() << '\n';
#else
    std::cout << "releaseguard-demo-private-literal\n";
#endif
    return 0;
}
