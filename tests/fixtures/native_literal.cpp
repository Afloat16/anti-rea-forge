#include "releaseguard_build.hpp"
#include "releaseguard/literal.hpp"

#include <array>
#include <iostream>
#include <new>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

template <typename Text>
void emit(const char* name, const Text& text) {
    using unit = typename std::make_unsigned<typename Text::value_type>::type;
    std::cout << name << ':' << std::dec << text.size() << ':';
    for (std::size_t i = 0; i < text.size(); ++i) {
        std::cout << std::hex << static_cast<std::uint64_t>(
            static_cast<unit>(text.data()[i])) << ',';
    }
    std::cout << std::dec << '\n';
}

template <typename Maker>
bool wiped(Maker make) {
    using Text = decltype(make());
    alignas(Text) unsigned char bytes[sizeof(Text)];
    // C++17 guaranteed copy elision also applies to this placement new.
    auto* text = ::new (static_cast<void*>(bytes)) Text(make());
    text->~Text();
    for (unsigned char byte : bytes) {
        if (byte != 0) {
            return false;
        }
    }
    return true;
}

int main() {
    auto narrow = RG_TEXT("RG_ASCII_SENTINEL_6dd935a7654147df");
    auto utf8 = RG_TEXT(u8"RG_UTF8_SENTINEL_5e24571f_\u4e2d\u6587_\U0001f512");
    auto wide = RG_TEXT(L"RG_WIDE_SENTINEL_c45849ad_\u4e2d\u6587_\U0001f512");
    auto utf16 = RG_TEXT(u"RG_UTF16_SENTINEL_774f62a3_\u4e2d\u6587_\U0001f512");
    auto utf32 = RG_TEXT(U"RG_UTF32_SENTINEL_f107b3d6_\u4e2d\u6587_\U0001f512");
    auto empty = RG_TEXT("");
    auto embedded = RG_TEXT("RG_NUL_SENTINEL_3107\0AFTER_NUL");
    auto repeated_first = RG_TEXT("RG_REPEAT_SENTINEL_173d6d2f");
    auto repeated_second = RG_TEXT("RG_REPEAT_SENTINEL_173d6d2f");
    static_assert(!std::is_copy_constructible<decltype(narrow)>::value, "no copy");
    static_assert(!std::is_move_constructible<decltype(narrow)>::value, "no move");
    static_assert(!std::is_copy_assignable<decltype(narrow)>::value, "no copy");
    static_assert(!std::is_move_assignable<decltype(narrow)>::value, "no move");
    static_assert(!std::is_same<decltype(repeated_first),
                               decltype(repeated_second)>::value,
                  "each RG_TEXT call must have a separate site");
    if (narrow.c_str()[narrow.size()] != '\0' || empty.c_str()[0] != '\0' ||
        utf16.c_str()[utf16.size()] != u'\0' ||
        !wiped([] { return RG_TEXT("RG_WIPE_SENTINEL_fdb72118"); }) ||
        !wiped([] { return RG_TEXT(u"RG_WIPE_UTF16_SENTINEL_11d44cbd"); })) {
        return 2;
    }

    std::cout << "wchar_bytes:" << sizeof(wchar_t) << '\n';
    emit("char", narrow);
    emit("utf8", utf8);
    emit("wide", wide);
    emit("utf16", utf16);
    emit("utf32", utf32);
    emit("empty", empty);
    emit("embedded", embedded);
    emit("repeat1", repeated_first);
    emit("repeat2", repeated_second);

    std::array<std::string, 8> results;
    std::vector<std::thread> threads;
    for (std::size_t i = 0; i < results.size(); ++i) {
        threads.emplace_back([&, i] {
            auto local = RG_TEXT("RG_THREAD_SENTINEL_15989c25");
            local.data()[0] = static_cast<char>('A' + i);
            results[i].assign(local.data(), local.size());
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    for (const auto& result : results) {
        std::cout << "thread:";
        for (unsigned char unit : result) {
            std::cout << std::hex << static_cast<unsigned int>(unit) << ',';
        }
        std::cout << std::dec << '\n';
    }
}
