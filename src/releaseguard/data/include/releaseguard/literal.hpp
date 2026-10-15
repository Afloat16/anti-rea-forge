#ifndef RELEASEGUARD_LITERAL_HPP
#define RELEASEGUARD_LITERAL_HPP

// C++17 reversible static masking for string literals. Include the generated
// releaseguard_build.hpp (which defines RELEASEGUARD_BUILD_SEED) first.
// This hides selected literal bytes from a simple static strings scan; it is
// not encryption, does not hide keys, and cannot prevent runtime inspection or
// reverse engineering. Never put credentials or signing secrets in RG_TEXT.

#ifndef RELEASEGUARD_BUILD_SEED
#error "RELEASEGUARD_BUILD_SEED must be defined; include releaseguard_build.hpp before releaseguard/literal.hpp"
#endif

#ifndef __COUNTER__
#error "RG_TEXT requires compiler support for __COUNTER__"
#endif

#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>

#if defined(_MSC_VER)
#define RELEASEGUARD_DETAIL_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) && !defined(__clang__)
#define RELEASEGUARD_DETAIL_NOINLINE __attribute__((noinline, noclone))
#elif defined(__clang__)
#define RELEASEGUARD_DETAIL_NOINLINE __attribute__((noinline))
#else
#error "RG_TEXT requires a supported noinline attribute (MSVC, GCC or Clang)"
#endif

namespace releaseguard {
namespace detail {

// Every operation is unsigned, including deliberate modulo-2^64 overflow.
constexpr std::uint64_t splitmix64(std::uint64_t value) noexcept {
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

template <typename Char>
using unsigned_char_t = typename std::make_unsigned<Char>::type;

template <typename Char, std::uint64_t Seed, std::uint64_t Site>
constexpr unsigned_char_t<Char> mask(std::size_t index) noexcept {
    using unit = unsigned_char_t<Char>;
    static_assert(std::numeric_limits<unit>::digits <= 64,
                  "RG_TEXT supports code units up to 64 bits");
    const auto value = static_cast<unit>(splitmix64(
        Seed ^ splitmix64(Site) ^
        (static_cast<std::uint64_t>(index) * UINT64_C(0xd6e8feb86659fd93))));
    return value == 0 ? unit{1} : value;
}

template <typename Char, std::size_t N, std::uint64_t Seed, std::uint64_t Site>
struct encoded_literal {
    unsigned_char_t<Char> units[N];
};

template <std::uint64_t Seed, std::uint64_t Site, typename Char, std::size_t N>
constexpr encoded_literal<Char, N, Seed, Site>
encode(const Char (&value)[N]) noexcept {
    static_assert(std::is_same<Char, char>::value ||
                      std::is_same<Char, wchar_t>::value ||
                      std::is_same<Char, char16_t>::value ||
                      std::is_same<Char, char32_t>::value,
                  "RG_TEXT accepts C++17 character string literals");
    encoded_literal<Char, N, Seed, Site> result{};
    for (std::size_t i = 0; i < N; ++i) {
        result.units[i] = static_cast<unsigned_char_t<Char>>(value[i]) ^
                          mask<Char, Seed, Site>(i);
    }
    return result;
}

} // namespace detail

// Owns its plaintext until destruction. Binding the RG_TEXT result to a named
// local uses mandatory C++17 copy elision. The object cannot be copied or moved;
// pointers from it must not outlive it. Rvalue data access is deliberately
// rejected, so `const char* p = RG_TEXT("...").c_str()` cannot dangle silently.
template <typename Char, std::size_t N, std::uint64_t Seed, std::uint64_t Site>
class basic_literal final {
public:
    using value_type = Char;

    RELEASEGUARD_DETAIL_NOINLINE explicit basic_literal(
        const detail::encoded_literal<Char, N, Seed, Site>& encoded) noexcept {
        // Volatile loads are observable operations: optimized and LTO builds
        // must actually read the encoded payload before producing plaintext.
        // noinline additionally keeps this decode out of the calling site.
        const volatile detail::unsigned_char_t<Char>* input = encoded.units;
        for (std::size_t i = 0; i < N; ++i) {
            plaintext_[i] = static_cast<Char>(
                input[i] ^ detail::mask<Char, Seed, Site>(i));
        }
    }

    basic_literal(const basic_literal&) = delete;
    basic_literal& operator=(const basic_literal&) = delete;
    basic_literal(basic_literal&&) = delete;
    basic_literal& operator=(basic_literal&&) = delete;

    RELEASEGUARD_DETAIL_NOINLINE ~basic_literal() noexcept {
        // Wipe the owned buffer only. Copies intentionally made by the caller,
        // registers and library/OS buffers are outside this object's lifetime.
        volatile Char* output = plaintext_;
        for (std::size_t i = 0; i < N; ++i) {
            output[i] = Char{};
        }
    }

    const Char* c_str() const & noexcept { return plaintext_; }
    const Char* c_str() const && = delete;
    Char* data() & noexcept { return plaintext_; }
    const Char* data() const & noexcept { return plaintext_; }
    Char* data() && = delete;
    const Char* data() const && = delete;
    constexpr std::size_t size() const noexcept { return N - 1; }

private:
    Char plaintext_[N];
};

namespace detail {

template <typename Char, std::size_t N, std::uint64_t Seed, std::uint64_t Site>
inline basic_literal<Char, N, Seed, Site>
open(const encoded_literal<Char, N, Seed, Site>& value) noexcept {
    return basic_literal<Char, N, Seed, Site>(value);
}

} // namespace detail
} // namespace releaseguard

#define RELEASEGUARD_DETAIL_TEXT(value, site)                                  \
    ([]() {                                                                  \
        constexpr auto releaseguard_encoded =                                \
            ::releaseguard::detail::encode<                                   \
                static_cast<std::uint64_t>(RELEASEGUARD_BUILD_SEED),            \
                static_cast<std::uint64_t>(site)>(value);                      \
        return ::releaseguard::detail::open(releaseguard_encoded);             \
    }())

// Example: auto endpoint = RG_TEXT("https://example.invalid/");
//          use(endpoint.c_str()); // endpoint must remain alive during use.
#define RG_TEXT(value) RELEASEGUARD_DETAIL_TEXT(value, __COUNTER__)

#undef RELEASEGUARD_DETAIL_NOINLINE

#endif // RELEASEGUARD_LITERAL_HPP
