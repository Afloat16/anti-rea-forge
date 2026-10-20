"""Compile and execute only our own secure allocation samples on Linux/Windows.

Tests inspect live mappings, use clear() while the allocation is owned and let
isolated POSIX children fault on guard pages. No freed-memory reads are used.
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INCLUDE = ROOT / "src" / "releaseguard" / "data" / "include"

SAMPLE = r'''
#include <releaseguard/secure_buffer.hpp>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#if defined(__linux__)
#include <csignal>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <sys/resource.h>
#include <sys/wait.h>
#endif

using releaseguard::secure_buffer;
using releaseguard::secure_buffer_options;
using releaseguard::dump_exclusion_kind;
static_assert(!std::is_copy_constructible<secure_buffer>::value, "no copying");
static_assert(!std::is_copy_assignable<secure_buffer>::value, "no copying");
static_assert(!std::is_move_constructible<secure_buffer>::value, "no moving");
static_assert(!std::is_move_assignable<secure_buffer>::value, "no moving");
static_assert(noexcept(std::declval<secure_buffer&>().clear()), "clear is noexcept");
static_assert(std::is_same<decltype(std::declval<const secure_buffer&>().data()),
                           const unsigned char*>::value, "const data");

#if defined(__linux__)
struct mapping_flags {
    bool available = false;
    bool found = false;
    bool rw_nonexec = false;
    bool locked = false;
    bool dontdump = false;
};

mapping_flags inspect_live(const secure_buffer& buffer) {
    std::ifstream smaps("/proc/self/smaps");
    mapping_flags result;
    result.available = smaps.is_open();
    bool current = false;
    std::string line;
    const auto address = reinterpret_cast<std::uintptr_t>(buffer.data());
    while (std::getline(smaps, line)) {
        unsigned long long begin = 0, end = 0;
        char permissions[5] = {};
        if (std::sscanf(line.c_str(), "%llx-%llx %4s", &begin, &end, permissions) == 3) {
            current = begin <= address && address < end;
            if (current) {
                result.found = true;
                result.rw_nonexec = permissions[0] == 'r' && permissions[1] == 'w' && permissions[2] == '-';
            }
        } else if (current && line.compare(0, 8, "VmFlags:") == 0) {
            std::istringstream words(line.substr(8));
            std::string word;
            while (words >> word) {
                result.locked = result.locked || word == "lo";
                result.dontdump = result.dontdump || word == "dd";
            }
        }
    }
    return result;
}

int guard_fault(bool right) {
    const pid_t child = ::fork();
    if (child < 0) return 80;
    if (child == 0) {
        const rlimit no_core{0, 0};
        (void)::setrlimit(RLIMIT_CORE, &no_core);
        std::signal(SIGSEGV, SIG_DFL);
        std::signal(SIGBUS, SIG_DFL);
        secure_buffer buffer(17, secure_buffer_options{false, false});
        const auto page = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
        const auto base = reinterpret_cast<std::uintptr_t>(buffer.data());
        const auto address = right ? base + page : base - 1;
        // Deliberately invalid native access, isolated in a child. Integer
        // address calculation locates the allocation guard, not freed storage.
        *reinterpret_cast<volatile unsigned char*>(address) = 0x42;
        ::_exit(81);
    }
    int status = 0;
    if (::waitpid(child, &status, 0) != child) return 82;
    return WIFSIGNALED(status) && (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS) ? 0 : 83;
}

int required_lock_failure() {
    const pid_t child = ::fork();
    if (child < 0) return 90;
    if (child == 0) {
        const rlimit no_lock{0, 0};
        if (::setrlimit(RLIMIT_MEMLOCK, &no_lock) != 0) ::_exit(91);
        try {
            secure_buffer buffer(32);
            // CAP_IPC_LOCK can bypass a zero limit. Report this environment
            // explicitly rather than pretending that failure was exercised.
            ::_exit(buffer.protection_status().locked ? 77 : 92);
        } catch (const std::system_error&) {
            secure_buffer optional(32, secure_buffer_options{false, false});
            ::_exit(optional.protection_status().locked ? 93 : 0);
        }
    }
    int status = 0;
    if (::waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 94;
    return WEXITSTATUS(status);
}
#endif

int main(int argc, char** argv) {
    const std::string mode = argc > 1 ? argv[1] : "normal";
    if (mode == "invalid") {
        for (const auto size : {std::size_t{0}, secure_buffer::max_size + 1,
                               (std::numeric_limits<std::size_t>::max)()}) {
            try { secure_buffer buffer(size, {false, false}); return 10; }
            catch (const std::length_error&) {}
        }
        return 0;
    }
    if (mode == "required-dump") {
#if defined(_WIN32)
        try { secure_buffer buffer(32, {false, true}); return 11; }
        catch (const std::system_error&) { return 0; }
#else
        try {
            secure_buffer buffer(32, {false, true});
            const auto status = buffer.protection_status();
            return status.dump_excluded && status.dump_exclusion == dump_exclusion_kind::linux_madv_dontdump ? 0 : 12;
        } catch (const std::system_error&) { return 77; }
#endif
    }
    if (mode == "default-lock") {
        try {
            secure_buffer buffer(32);
            return buffer.protection_status().locked ? 0 : 13;
        } catch (const std::system_error&) { return 77; }
    }
#if defined(__linux__)
    if (mode == "guard-left") return guard_fault(false);
    if (mode == "guard-right") return guard_fault(true);
    if (mode == "lock-failure") return required_lock_failure();
#endif

    for (const auto size : {std::size_t{1}, std::size_t{17}, std::size_t{4097}, secure_buffer::max_size}) {
        secure_buffer buffer(size, {false, false});
        if (buffer.size() != size || buffer.data() == nullptr) return 20;
        const auto status = buffer.protection_status();
        if (!status.guard_pages) return 21;
        for (std::size_t i = 0; i < size; ++i) {
            if (buffer.data()[i] != 0) return 22;
            buffer.data()[i] = static_cast<unsigned char>(i % 251 + 1);
        }
        const secure_buffer& view = buffer;
        if (view.data()[size - 1] != static_cast<unsigned char>((size - 1) % 251 + 1)) return 23;
#if defined(__linux__)
        const auto observed = inspect_live(buffer);
        if (observed.available && (!observed.found || !observed.rw_nonexec ||
            status.locked != observed.locked || status.dump_excluded != observed.dontdump)) return 24;
        if (status.dump_excluded != (status.dump_exclusion == dump_exclusion_kind::linux_madv_dontdump)) return 25;
#else
        if (status.dump_excluded || status.dump_exclusion != dump_exclusion_kind::none) return 26;
        MEMORY_BASIC_INFORMATION payload{}, left{}, right{};
        SYSTEM_INFO information{};
        GetSystemInfo(&information);
        const auto page = static_cast<std::size_t>(information.dwPageSize);
        const auto rounded = ((size + page - 1) / page) * page;
        const auto address = reinterpret_cast<std::uintptr_t>(buffer.data());
        if (VirtualQuery(buffer.data(), &payload, sizeof(payload)) == 0 ||
            VirtualQuery(reinterpret_cast<void*>(address - 1), &left, sizeof(left)) == 0 ||
            VirtualQuery(reinterpret_cast<void*>(address + rounded), &right, sizeof(right)) == 0 ||
            payload.State != MEM_COMMIT || payload.Protect != PAGE_READWRITE ||
            left.State != MEM_RESERVE || right.State != MEM_RESERVE) return 27;
#endif
        buffer.clear();
        buffer.clear();
        for (std::size_t i = 0; i < size; ++i) if (buffer.data()[i] != 0) return 28;
        buffer.data()[0] = 0xA5; // clear retains a usable allocation.
    }
    // Repeated independent lifetimes exercise normal destruction/release.
    for (int i = 0; i < 128; ++i) {
        secure_buffer first(32, {false, false});
        secure_buffer second(32, {false, false});
        if (first.data() == second.data()) return 30;
        first.data()[0] = 0xA5;
        if (second.data()[0] != 0) return 31;
    }
    std::cout << "secure-buffer-ok\n";
}
'''

CLEANUP_SAMPLE = r'''
// Independent GNU linker wrappers inspect pages immediately BEFORE the real
// unlock/unmap, while that storage remains mapped. Never inspect freed pages.
#include <releaseguard/secure_buffer.hpp>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sys/mman.h>

static int failure_mode;
static void* payload;
static std::size_t payload_size;
static int release_count;
static int unlock_count;
static bool zero_at_release;
static bool zero_at_unlock;

static bool is_zero() {
    const volatile unsigned char* bytes = static_cast<unsigned char*>(payload);
    for (std::size_t i = 0; i < payload_size; ++i) if (bytes[i] != 0) return false;
    return true;
}

extern "C" int __real_mprotect(void*, std::size_t, int);
extern "C" int __real_mlock(const void*, std::size_t);
extern "C" int __real_madvise(void*, std::size_t, int);
extern "C" int __real_munlock(const void*, std::size_t);
extern "C" int __real_munmap(void*, std::size_t);

extern "C" int __wrap_mprotect(void* address, std::size_t size, int protection) {
    payload = address;
    payload_size = size;
    if (failure_mode == 1) { errno = EACCES; return -1; }
    const int result = __real_mprotect(address, size, protection);
    if (result == 0) std::memset(address, 0xa5, size);
    return result;
}
extern "C" int __wrap_mlock(const void* address, std::size_t size) {
    if (failure_mode == 2) { errno = EPERM; return -1; }
    return __real_mlock(address, size);
}
extern "C" int __wrap_madvise(void* address, std::size_t size, int advice) {
    if (failure_mode == 3) { errno = EINVAL; return -1; }
    return __real_madvise(address, size, advice);
}
extern "C" int __wrap_munlock(const void* address, std::size_t size) {
    ++unlock_count;
    zero_at_unlock = is_zero();
    return __real_munlock(address, size);
}
extern "C" int __wrap_munmap(void* address, std::size_t size) {
    ++release_count;
    if (failure_mode != 1) zero_at_release = is_zero();
    return __real_munmap(address, size);
}

int main(int argc, char** argv) {
    failure_mode = argc > 1 ? std::atoi(argv[1]) : 0;
    bool threw = false;
    try {
        releaseguard::secure_buffer buffer(17, {true, true});
        if (failure_mode != 0) return 10;
        // Also dirty the mapped page padding after the visible 17 bytes.
        std::memset(buffer.data(), 0x77, payload_size);
    } catch (const std::system_error&) { threw = true; }
    if (threw != (failure_mode != 0)) return 11;
    if (release_count != 1) return 12;
    if (failure_mode != 1 && !zero_at_release) return 13;
    if (failure_mode == 0 || failure_mode == 3) {
        if (unlock_count != 1 || !zero_at_unlock) return 14;
    } else if (unlock_count != 0) return 15;
    std::cout << "cleanup-ok\n";
}
'''


def find_compiler() -> list[str] | None:
    if os.environ.get("CXX"):
        command = shlex.split(os.environ["CXX"], posix=os.name != "nt")
        if command and shutil.which(command[0]):
            return command
    for name in ("g++", "clang++", "cl"):
        if path := shutil.which(name):
            return [path]
    return None


class SecureBufferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() not in {"Linux", "Windows"}:
            raise unittest.SkipTest("secure_buffer supports Linux/Windows only")
        cls.compiler = find_compiler()
        if not cls.compiler:
            raise unittest.SkipTest("C++17 compiler unavailable")
        cls.msvc = Path(cls.compiler[0]).stem.lower() in {"cl", "clang-cl"}
        cls.temporary = tempfile.TemporaryDirectory(prefix="rg-secure-buffer-")
        cls.directory = Path(cls.temporary.name)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    def compile(self, name: str, source: str = SAMPLE, optimization: str = "O2", *, lto: bool = False, extra_flags: list[str] | None = None):
        build = self.directory / name
        build.mkdir(exist_ok=True)
        source_path = build / "sample.cpp"
        source_path.write_text(source, encoding="utf-8")
        binary = build / ("sample.exe" if os.name == "nt" else "sample")
        if self.msvc:
            flags = ["/Od"] if optimization == "O0" else ["/O2"]
            if lto:
                flags.append("/GL")
            command = self.compiler + [
                "/nologo", "/std:c++17", "/EHsc", "/utf-8", "/W4",
                f"/I{INCLUDE}", *flags, str(source_path), f"/Fe:{binary}", f"/Fo:{build / 'sample.obj'}",
            ]
            if lto:
                command.extend(["/link", "/LTCG"])
        else:
            command = self.compiler + [
                "-std=c++17", "-Wall", "-Wextra", "-pedantic", f"-{optimization}",
                "-I", str(INCLUDE), str(source_path), "-o", str(binary),
            ]
            if lto:
                command.append("-flto")
        command.extend(extra_flags or [])
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, cwd=build)
        return result, binary

    def built(self, name: str, **kwargs) -> Path:
        result, binary = self.compile(name, **kwargs)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return binary

    def run_sample(self, binary: Path, mode: str = "normal", *, optional: bool = False):
        result = subprocess.run([str(binary), mode], capture_output=True, text=True, timeout=20)
        if optional and result.returncode == 77:
            self.skipTest("required protection cannot be exercised in this OS/resource environment")
        self.assertEqual(result.returncode, 0, f"{mode}: {result.stdout}{result.stderr}")
        return result

    def test_live_allocation_clear_and_flags_o0(self):
        result = self.run_sample(self.built("o0", optimization="O0"))
        self.assertEqual(result.stdout, "secure-buffer-ok\n")

    def test_live_allocation_clear_and_flags_o2(self):
        result = self.run_sample(self.built("o2"))
        self.assertEqual(result.stdout, "secure-buffer-ok\n")

    @unittest.skipUnless(platform.system() == "Linux", "live Linux VmFlags require Linux")
    def test_live_flags_independently_match_linux_smaps(self):
        if not Path("/proc/self/smaps").is_file():
            self.skipTest("/proc/self/smaps is unavailable in this sandbox; OS-return status is still exercised")
        self.run_sample(self.built("linux-live-flags"))

    def test_optimized_lto_allocation_and_clear(self):
        probe, _ = self.compile("lto-probe", "int main() {}\n", lto=True)
        if probe.returncode:
            self.skipTest("compiler/linker LTO unavailable")
        self.run_sample(self.built("lto", optimization="O3", lto=True))

    def test_zero_oversize_and_overflow_sizes_rejected(self):
        self.run_sample(self.built("invalid"), "invalid")

    def test_default_requires_a_real_memory_lock(self):
        self.run_sample(self.built("default-lock"), "default-lock", optional=True)

    def test_requested_dump_exclusion_is_real_or_fails_closed(self):
        self.run_sample(self.built("required-dump"), "required-dump", optional=platform.system() == "Linux")

    @unittest.skipUnless(platform.system() == "Linux", "POSIX child guard tests require Linux")
    def test_both_guard_pages_fault_in_isolated_children(self):
        binary = self.built("guards")
        self.run_sample(binary, "guard-left")
        self.run_sample(binary, "guard-right")

    @unittest.skipUnless(platform.system() == "Linux", "POSIX resource limits require Linux")
    def test_required_lock_fails_closed_with_zero_memlock_limit(self):
        self.run_sample(self.built("lock-failure"), "lock-failure", optional=True)

    def cleanup_binary(self, name: str) -> Path:
        if platform.system() != "Linux" or self.msvc or "g++" not in Path(self.compiler[0]).name:
            self.skipTest("before-release syscall wrappers require Linux GCC/GNU linker")
        probe, _ = self.compile("cleanup-lto-probe", "int main() {}\n", lto=True)
        if probe.returncode:
            self.skipTest("compiler/linker LTO unavailable")
        return self.built(
            name, source=CLEANUP_SAMPLE, optimization="O3", lto=True,
            extra_flags=["-Werror", "-Wl,--wrap=mprotect,--wrap=mlock,--wrap=madvise,--wrap=munlock,--wrap=munmap"],
        )

    @unittest.skipUnless(platform.system() == "Linux", "GNU syscall-wrapper regressions require Linux")
    def test_partial_construction_failure_cleans_up_exactly_once(self):
        binary = self.cleanup_binary("partial-cleanup")
        self.run_sample(binary, "1")  # mprotect failure: do not wipe PROT_NONE.
        self.run_sample(binary, "2")  # mlock failure: wipe every writable page.

    @unittest.skipUnless(platform.system() == "Linux", "GNU syscall-wrapper regressions require Linux")
    def test_destructor_and_dump_failure_wipe_before_unlock_and_unmap(self):
        # These two paths require the OS to grant a real lock and DONTDUMP.
        probe = self.built("cleanup-protections")
        self.run_sample(probe, "default-lock", optional=True)
        self.run_sample(probe, "required-dump", optional=True)
        binary = self.cleanup_binary("destructor-cleanup")
        self.run_sample(binary, "0")
        self.run_sample(binary, "3")

    def test_temporary_data_pointer_is_a_compile_error(self):
        for const in (False, True):
            with self.subTest(const=const):
                expression = "static_cast<const releaseguard::secure_buffer&&>(releaseguard::secure_buffer(16))" if const else "releaseguard::secure_buffer(16)"
                source = '#include <releaseguard/secure_buffer.hpp>\nint main(){ auto* p = ' + expression + '.data(); (void)p; }\n'
                result, _ = self.compile("rvalue-" + str(const), source)
                self.assertNotEqual(result.returncode, 0)

    def test_minimal_example_compiles_and_reports_only_status(self):
        binary = self.built("example", source=(ROOT / "examples" / "secure_buffer.cpp").read_text())
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
        if result.returncode == 1 and result.stderr == "secure_buffer required protections unavailable\n":
            self.skipTest("default required memory lock unavailable")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        values = dict(line.split("=", 1) for line in result.stdout.splitlines())
        self.assertEqual(set(values), {"locked", "guard_pages", "dump_excluded", "linux_madv_dontdump"})
        self.assertEqual(values["locked"], "true")
        self.assertEqual(values["guard_pages"], "true")
        self.assertTrue(all(value in {"true", "false"} for value in values.values()))


if __name__ == "__main__":
    unittest.main()
