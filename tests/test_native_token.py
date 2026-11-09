"""Native token issuance, output separation and actual C++/OpenSSL interop."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from releaseguard.core import GuardError, write_new
from releaseguard.native_token import issue_native_token


class NativeTokenFiles(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name).resolve()
        self.public = self.work / "build" / "generated"
        self.secret = self.work / "issuer only" / "bearer.txt"
        self.public.parent.mkdir()
        self.secret.parent.mkdir(mode=0o700)

    def test_only_verifier_is_public_and_issue_report_contains_no_bearer(self):
        result = issue_native_token(self.public, self.secret)
        self.assertTrue(result["ok"])
        self.assertEqual(Path(result["public_header"]), self.public / "releaseguard_token.hpp")
        bearer = self.secret.read_bytes()
        self.assertTrue(re.fullmatch(rb"rg1_[0-9a-f]{64}\n", bearer))
        public_files = {p.relative_to(self.public).as_posix(): p.read_bytes()
                        for p in self.public.rglob("*") if p.is_file()}
        self.assertEqual(set(public_files), {"releaseguard_token.hpp", "releaseguard/token_verify.hpp"})
        self.assertFalse(any(bearer[:-1] in data for data in public_files.values()))
        self.assertFalse(bearer[:-1] in json.dumps(result).encode())
        octets = re.findall(rb"0x([0-9a-f]{2})", public_files["releaseguard_token.hpp"])
        self.assertEqual(bytes.fromhex(b"".join(octets).decode("ascii")),
                         hashlib.sha256(b"OpenReleaseGuard/native-token/v1\0" + bearer[:-1]).digest())
        if os.name == "posix":
            self.assertFalse(stat.S_IMODE(self.secret.stat().st_mode) & 0o177)

    def test_independent_issues_do_not_reuse_the_same_credential_or_verifier(self):
        other_public = self.public.with_name("another")
        other_secret = self.secret.with_name("another.txt")
        issue_native_token(self.public, self.secret)
        issue_native_token(other_public, other_secret)
        self.assertFalse(self.secret.read_bytes() == other_secret.read_bytes())
        self.assertNotEqual((self.public / "releaseguard_token.hpp").read_bytes(),
                            (other_public / "releaseguard_token.hpp").read_bytes())

    def test_public_and_private_outputs_must_be_separate(self):
        for invalid in (self.public, self.public.parent / "same-folder.txt",
                        self.public / "credential", self.public / "nest" / "token",
                        self.secret.parent / "missing" / "token"):
            with self.subTest(path=invalid):
                with self.assertRaises((GuardError, OSError)):
                    issue_native_token(self.public, invalid)
                self.assertFalse(self.public.exists())

    def test_existing_outputs_are_preserved(self):
        self.public.mkdir()
        (self.public / "sentinel").write_bytes(b"keep")
        with self.assertRaises(GuardError):
            issue_native_token(self.public, self.secret)
        self.assertEqual((self.public / "sentinel").read_bytes(), b"keep")
        self.assertFalse(self.secret.exists())
        self.secret.write_bytes(b"existing token file")
        other = self.public.with_name("fresh")
        with self.assertRaises(GuardError):
            issue_native_token(other, self.secret)
        self.assertFalse(other.exists())
        self.assertEqual(self.secret.read_bytes(), b"existing token file")

    def test_rollback_does_not_remove_a_competing_private_output(self):
        def collision(path, content, **kwargs):
            if path == self.secret:
                path.write_bytes(b"belongs to the other writer")
            write_new(path, content, **kwargs)

        with patch("releaseguard.native_token.write_new", side_effect=collision):
            with self.assertRaises(FileExistsError):
                issue_native_token(self.public, self.secret)
        self.assertFalse(self.public.exists())
        self.assertEqual(self.secret.read_bytes(), b"belongs to the other writer")

    def test_failure_to_create_a_header_rolls_back_without_issuing_token(self):
        def fail(path, content, **kwargs):
            if path.name == "releaseguard_token.hpp":
                raise OSError("test write failure")
            write_new(path, content, **kwargs)

        with patch("releaseguard.native_token.write_new", side_effect=fail):
            with self.assertRaises(OSError):
                issue_native_token(self.public, self.secret)
        self.assertFalse(self.public.exists())
        self.assertFalse(self.secret.exists())

    def test_link_destinations_and_linked_parent_are_rejected(self):
        alias = self.work / "alias"
        try:
            alias.symlink_to(self.secret.parent, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory link creation unavailable on this host")
        with self.assertRaises(GuardError):
            issue_native_token(self.public, alias / self.secret.name)
        self.assertFalse(self.public.exists())
        self.assertFalse(self.secret.exists())
        self.secret.symlink_to(self.work / "missing")
        with self.assertRaises(GuardError):
            issue_native_token(self.public, self.secret)
        self.assertTrue(self.secret.is_symlink())
        self.assertFalse(self.public.exists())


_FIXTURE = r"""
#include "releaseguard_token.hpp"
#include <iostream>
#include <iterator>
#include <string>
int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "no-provider") {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (EVP_set_default_properties(nullptr, "provider=nonexistent") != 1) return 2;
#else
        return 77;
#endif
    }
    const std::string candidate{std::istreambuf_iterator<char>{std::cin},
                                std::istreambuf_iterator<char>{}};
    return releaseguard::verify_issued_token(candidate) ? 0 : 3;
}
"""


class CompiledNativeToken(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Portable Python issuance is tested on all platforms. These compilation
        # checks use a Unix-style C++ toolchain with OpenSSL development files.
        # The dedicated Linux CI job requires these checks instead of skipping.
        def unavailable(reason):
            if os.environ.get("RELEASEGUARD_REQUIRE_OPENSSL_NATIVE") == "1":
                raise AssertionError(reason)
            raise unittest.SkipTest(reason)

        cxx = shutil.which("c++")
        if os.name != "posix" or not cxx:
            unavailable("requires Unix-style C++17 toolchain and libcrypto")
        temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        work = Path(temp.name)
        # A standalone readiness check distinguishes missing dependencies from a
        # regression in our header. Compilation of the actual header must pass.
        ready = subprocess.run(
            [cxx, "-std=c++17", "-x", "c++", "-", "-lcrypto", "-o", str(work / "check")],
            input="#include <openssl/evp.h>\nint main(){return EVP_sha256()?0:1;}\n",
            text=True, capture_output=True, timeout=60,
        )
        if ready.returncode:
            unavailable("OpenSSL development headers or libcrypto linker unavailable")
        public = work / "include"
        private = work / "issuer"
        private.mkdir(mode=0o700)
        output = private / "token"
        issue_native_token(public, output)
        cls.token = output.read_bytes()[:-1]
        source = work / "check_token.cpp"
        source.write_text(_FIXTURE, encoding="ascii")
        cls.app = work / "check_token"
        compiled = subprocess.run(
            [cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-O2", "-I", str(public),
             str(source), "-lcrypto", "-o", str(cls.app)], capture_output=True, text=True, timeout=60,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def call(self, data, *args):
        proc = subprocess.run([str(self.app), *args], input=data, capture_output=True, timeout=15)
        self.assertEqual(proc.stdout, b"")
        return proc.returncode

    def test_real_cpp_verifier_accepts_only_exact_issued_input(self):
        token = self.token
        self.assertEqual(self.call(token), 0)
        altered = token[:-1] + (b"1" if token.endswith(b"0") else b"0")
        invalid = [b"", token[:-1], token + b"\n", token + b"\0junk", b"\0" + token[1:],
                   token[:4] + b"\xff" + token[5:], b"RG1_" + token[4:], b"rg1_" + b"F" * 64,
                   b"rg1_" + b"z" * 64, altered]
        for index, data in enumerate(invalid):
            with self.subTest(case=index):
                self.assertEqual(self.call(data), 3)

    def test_openssl_provider_error_fails_closed_even_with_correct_bearer(self):
        status = self.call(self.token, "no-provider")
        if status == 77:
            self.skipTest("OpenSSL provider property controls require OpenSSL 3")
        self.assertEqual(status, 3)
