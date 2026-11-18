"""Compile the real generated loader to exercise C++ static teardown order."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from releaseguard.native_code_seal import seal_virtualized_ir
from tests.test_native_code_seal import CONTEXT, fixture


class NativeLoaderLifetimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def unavailable(reason):
            if (os.environ.get("RELEASEGUARD_REQUIRE_OPENSSL_NATIVE") == "1"
                    or os.environ.get("RELEASEGUARD_REQUIRE_NATIVE_VIRTUALIZATION") == "1"):
                raise AssertionError(reason)
            raise unittest.SkipTest(reason)
        cls.cxx = shutil.which("c++")
        if not sys.platform.startswith("linux") or not cls.cxx:
            unavailable("generated code loader requires Linux C++17 and OpenSSL development files")
        temporary = tempfile.TemporaryDirectory(prefix="native-loader-lifetime-")
        cls.addClassCleanup(temporary.cleanup)
        cls.work = Path(temporary.name)
        check = subprocess.run(
            [cls.cxx, "-std=c++17", "-x", "c++", "-", "-lcrypto", "-o", str(cls.work / "check")],
            input="#include <openssl/crypto.h>\nint main(){return OPENSSL_INIT_NO_ATEXIT?0:1;}\n",
            capture_output=True, text=True, timeout=60)
        if check.returncode:
            unavailable("OpenSSL development headers or libcrypto linker unavailable")
        source, coverage = fixture()
        _, files, cls.details = seal_virtualized_ir(source, coverage, bytes(range(32)), **CONTEXT)
        for name, data in files.items():
            (cls.work / name).write_bytes(data)

    def build_and_run(self, name, program):
        # C++ definitions stand in for LLVM's externally visible null bindings.
        # Authentication, secure allocation, ownership and teardown all use the
        # production generated loader, with no mocked crypto or memory APIs.
        declarations = ["unsigned char " + self.details["ready_symbol"] + " = 0;"]
        checks = [self.details["ready_symbol"] + " == 0"]
        for item in self.details["storage"]:
            ctype = "unsigned char" if item["kind"] == "bytecode" else "std::uint64_t"
            declarations.append(ctype + "* " + item["symbol"] + " = nullptr;")
            checks.append(item["symbol"] + " == nullptr")
        source = ('#include "releaseguard_native_code.hpp"\n#include <cstdint>\n#include <cstdio>\n'
                  + 'extern "C" {\n' + "\n".join(declarations) + "\n}\n"
                  + "namespace code = " + self.details["cpp_namespace"] + ";\n"
                  + "releaseguard::native_asset_key key = {"
                  + ",".join(str(value) for value in range(32)) + "};\n"
                  + "bool closed() { return " + " && ".join(checks) + "; }\n" + program)
        path = self.work / (name + ".cpp")
        path.write_text(source, encoding="utf-8")
        app = self.work / name
        compiled = subprocess.run(
            [self.cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", str(path),
             str(self.work / "releaseguard_native_code.cpp"), "-lcrypto", "-o", str(app)],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        self.assertEqual(compiled.stderr, "")
        result = subprocess.run([str(app)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return result.stdout

    def test_late_destructor_cannot_resurrect_retired_module_storage(self):
        output = self.build_and_run("late-destructor", '''
struct LateCaller {
    ~LateCaller() {
        const bool was_closed = closed();
        const bool reopened = code::initialize_native_code(key);
        const bool still_closed = closed();
        code::clear_native_code();
        std::printf("late closed=%d blocked=%d still_closed=%d\\n",
                    was_closed, !reopened, still_closed);
    }
} late_caller;
int main() {
    // Keep crypto alive so its unrelated shutdown does not mask a successful
    // access to the already-destroyed module memory_owner in late_caller.
    if (OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, nullptr) != 1) return 1;
    if (!code::initialize_native_code(key)) return 2;
    code::clear_native_code();
    if (!closed()) return 3;
    if (!code::initialize_native_code(key)) return 4;
    std::puts("ordinary reopen=1");
}
''')
        self.assertEqual(output, "ordinary reopen=1\nlate closed=1 blocked=1 still_closed=1\n")

    def test_early_global_owner_can_clear_and_reinitialize_before_module_teardown(self):
        output = self.build_and_run("early-global-owner", '''
struct EarlyCaller {
    bool initialized = false;
    EarlyCaller() {
        initialized = OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, nullptr) == 1 &&
                      code::initialize_native_code(key);
    }
    ~EarlyCaller() {
        code::clear_native_code();
        const bool was_closed = closed();
        const bool reopened = code::initialize_native_code(key);
        code::clear_native_code();
        std::printf("early closed=%d reopened=%d final_closed=%d\\n",
                    was_closed, reopened, closed());
    }
} early_caller;
int main() {
    if (!early_caller.initialized || closed()) return 1;
    std::puts("global initialize=1");
}
''')
        self.assertEqual(output, "global initialize=1\nearly closed=1 reopened=1 final_closed=1\n")


if __name__ == "__main__":
    unittest.main()
