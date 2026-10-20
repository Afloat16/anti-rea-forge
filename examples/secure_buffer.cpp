#include <releaseguard/secure_buffer.hpp>

#include <exception>
#include <iostream>

int main() {
    try {
        // Default options require a successful memory lock. This example
        // contains no secret and reports only protections actually acquired.
        releaseguard::secure_buffer buffer(128);
        const auto status = buffer.protection_status();
        std::cout << std::boolalpha
                  << "locked=" << status.locked << '\n'
                  << "guard_pages=" << status.guard_pages << '\n'
                  << "dump_excluded=" << status.dump_excluded << '\n'
                  << "linux_madv_dontdump="
                  << (status.dump_exclusion == releaseguard::dump_exclusion_kind::linux_madv_dontdump)
                  << '\n';
        buffer.clear();
        return 0;
    } catch (const std::exception&) {
        std::cerr << "secure_buffer required protections unavailable\n";
        return 1;
    }
}
