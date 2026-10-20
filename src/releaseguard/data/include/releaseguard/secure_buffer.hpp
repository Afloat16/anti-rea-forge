#ifndef RELEASEGUARD_SECURE_BUFFER_HPP
#define RELEASEGUARD_SECURE_BUFFER_HPP

// C++17 memory hygiene for one owned native allocation, not encryption or
// protection from ptrace, injected code, hooks, debuggers or memory inspection.
// Dump exclusion affects cooperating OS dump mechanisms only. Copies, caller
// buffers, registers, swap already written and other process memory are not
// wiped by this object. Do not use data() after its owner's lifetime ends.
//
// Two inaccessible guard pages surround the PAGE-ROUNDED payload allocation.
// Rounding leaves a padding gap after size(): guards are not bounds checks for
// individual objects or every overflow. The payload is mapped read/write, with
// no executable permission requested. Callers must provide synchronization.

#include <cstddef>
#include <limits>
#include <stdexcept>
#include <system_error>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <cerrno>
#include <sys/mman.h>
#include <unistd.h>
#else
#error "releaseguard::secure_buffer supports Windows and Linux only"
#endif

namespace releaseguard {

struct secure_buffer_options {
    // Both protections are attempted where supported, even if not required.
    // A required protection must succeed or construction throws and cleans up.
    bool require_lock = true;
    bool require_dump_exclusion = false;
};

enum class dump_exclusion_kind {
    none,
    linux_madv_dontdump
};

struct secure_buffer_status {
    bool locked = false;
    bool dump_excluded = false;
    bool guard_pages = false;
    dump_exclusion_kind dump_exclusion = dump_exclusion_kind::none;
};

class secure_buffer final {
public:
    static constexpr std::size_t max_size = 1024 * 1024;

    explicit secure_buffer(std::size_t size, secure_buffer_options options = {})
        : size_(size) {
        if (size == 0 || size > max_size) {
            throw std::length_error("secure_buffer size must be 1..1048576 bytes");
        }
        const std::size_t page = page_size();
        const std::size_t maximum = (std::numeric_limits<std::size_t>::max)();
        if (page == 0 || page > maximum / 2) {
            throw std::length_error("secure_buffer page size is unsupported");
        }
        const std::size_t remainder = size % page;
        const std::size_t padding = remainder == 0 ? 0 : page - remainder;
        if (size > maximum - padding) {
            throw std::length_error("secure_buffer rounded size overflows");
        }
        payload_bytes_ = size + padding;
        if (payload_bytes_ > maximum - 2 * page) {
            throw std::length_error("secure_buffer reserved size overflows");
        }
        reserved_bytes_ = payload_bytes_ + 2 * page;

        try {
            allocate(page);
            status_.guard_pages = true;
            lock_pages(options.require_lock);
            exclude_from_dumps(options.require_dump_exclusion);
        } catch (...) {
            release();
            throw;
        }
    }

    secure_buffer(const secure_buffer&) = delete;
    secure_buffer& operator=(const secure_buffer&) = delete;
    secure_buffer(secure_buffer&&) = delete;
    secure_buffer& operator=(secure_buffer&&) = delete;

    ~secure_buffer() noexcept { release(); }

    unsigned char* data() & noexcept { return payload_; }
    const unsigned char* data() const & noexcept { return payload_; }
    unsigned char* data() && = delete;
    const unsigned char* data() const && = delete;
    std::size_t size() const noexcept { return size_; }
    secure_buffer_status protection_status() const noexcept { return status_; }

    void clear() noexcept {
        if (!writable_) {
            return;
        }
        // Include page padding, not just the requested visible byte count.
#if defined(_WIN32)
        SecureZeroMemory(payload_, payload_bytes_);
#else
        volatile unsigned char* output = payload_;
        for (std::size_t i = 0; i < payload_bytes_; ++i) {
            output[i] = 0;
        }
#endif
    }

private:
    static std::size_t page_size() {
#if defined(_WIN32)
        SYSTEM_INFO information{};
        GetSystemInfo(&information);
        if (information.dwPageSize == 0) {
            throw std::system_error(ERROR_NOT_SUPPORTED, std::system_category(),
                                    "secure_buffer page size unavailable");
        }
        return static_cast<std::size_t>(information.dwPageSize);
#else
        errno = 0;
        const long value = ::sysconf(_SC_PAGESIZE);
        if (value <= 0) {
            throw std::system_error(errno == 0 ? EINVAL : errno, std::generic_category(),
                                    "secure_buffer page size unavailable");
        }
        return static_cast<std::size_t>(value);
#endif
    }

    void allocate(std::size_t page) {
#if defined(_WIN32)
        reservation_ = static_cast<unsigned char*>(
            VirtualAlloc(nullptr, reserved_bytes_, MEM_RESERVE, PAGE_NOACCESS));
        if (reservation_ == nullptr) {
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                    "secure_buffer reservation failed");
        }
        payload_ = reservation_ + page;
        if (VirtualAlloc(payload_, payload_bytes_, MEM_COMMIT, PAGE_READWRITE) == nullptr) {
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                    "secure_buffer payload commit failed");
        }
#else
        void* mapping = ::mmap(nullptr, reserved_bytes_, PROT_NONE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED) {
            throw std::system_error(errno, std::generic_category(),
                                    "secure_buffer reservation failed");
        }
        reservation_ = static_cast<unsigned char*>(mapping);
        payload_ = reservation_ + page;
        if (::mprotect(payload_, payload_bytes_, PROT_READ | PROT_WRITE) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "secure_buffer payload protection failed");
        }
#endif
        writable_ = true;
    }

    void lock_pages(bool required) {
#if defined(_WIN32)
        if (VirtualLock(payload_, payload_bytes_) != 0) {
            status_.locked = true;
        } else if (required) {
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                    "secure_buffer required memory lock failed");
        }
#else
        if (::mlock(payload_, payload_bytes_) == 0) {
            status_.locked = true;
        } else if (required) {
            throw std::system_error(errno, std::generic_category(),
                                    "secure_buffer required memory lock failed");
        }
#endif
    }

    void exclude_from_dumps(bool required) {
#if defined(__linux__) && defined(MADV_DONTDUMP)
        if (::madvise(payload_, payload_bytes_, MADV_DONTDUMP) == 0) {
            status_.dump_excluded = true;
            status_.dump_exclusion = dump_exclusion_kind::linux_madv_dontdump;
        } else if (required) {
            throw std::system_error(errno, std::generic_category(),
                                    "secure_buffer required dump exclusion failed");
        }
#else
        // No WER integration is implemented. In particular, VirtualLock is not
        // treated as Windows dump exclusion. Do not load a DLL from user paths.
        if (required) {
#if defined(_WIN32)
            throw std::system_error(ERROR_NOT_SUPPORTED, std::system_category(),
                                    "secure_buffer dump exclusion is unavailable");
#else
            throw std::system_error(ENOTSUP, std::generic_category(),
                                    "secure_buffer dump exclusion is unavailable");
#endif
        }
#endif
    }

    void release() noexcept {
        if (reservation_ == nullptr) {
            return;
        }
        // Wipe while the pages are still mapped, writable and (if acquired)
        // locked. Failure during partial construction also follows this path.
        clear();
#if defined(_WIN32)
        if (status_.locked) {
            (void)VirtualUnlock(payload_, payload_bytes_);
        }
        (void)VirtualFree(reservation_, 0, MEM_RELEASE);
#else
        if (status_.locked) {
            (void)::munlock(payload_, payload_bytes_);
        }
        (void)::munmap(reservation_, reserved_bytes_);
#endif
        reservation_ = nullptr;
        payload_ = nullptr;
        writable_ = false;
        status_ = {};
    }

    unsigned char* reservation_ = nullptr;
    unsigned char* payload_ = nullptr;
    std::size_t size_ = 0;
    std::size_t payload_bytes_ = 0;
    std::size_t reserved_bytes_ = 0;
    bool writable_ = false;
    secure_buffer_status status_{};
};

} // namespace releaseguard

#endif // RELEASEGUARD_SECURE_BUFFER_HPP
