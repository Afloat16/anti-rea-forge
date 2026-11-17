"""Keyless build export and real C++17/OpenSSL interoperability for sealed data."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from releaseguard.core import GuardError, write_new
from releaseguard.native_asset import export_native_asset
from releaseguard.sealed import MAX_ASSET_BYTES, _context, seal_asset, open_asset


CONTEXT = dict(product="demo", release="1.0", purpose="data", asset_id="config/table")


class NativeAssetFiles(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name).resolve()
        self.output = self.work / "generated"
        self.key = secrets.token_bytes(32)
        self.plaintext = secrets.token_bytes(32)
        self.document = seal_asset(self.plaintext, self.key, **CONTEXT)

    def export(self, document=None, **context):
        return export_native_asset(self.document if document is None else document,
                                   self.output, **{**CONTEXT, **context})

    def test_only_exact_ciphertext_and_trusted_context_are_emitted(self):
        before = json.dumps(self.document, sort_keys=True)
        result = self.export()
        self.assertEqual(before, json.dumps(self.document, sort_keys=True))
        self.assertEqual(result["ciphertext_bytes"], 48)
        files = {p.relative_to(self.output).as_posix(): p.read_bytes()
                 for p in self.output.rglob("*") if p.is_file()}
        self.assertEqual(set(files), {"releaseguard_asset.hpp", "releaseguard/sealed_asset.hpp"})
        header = files["releaseguard_asset.hpp"]
        for name in ("salt", "nonce", "ciphertext"):
            chunk = header.split(("embedded_asset_" + name + " = {").encode())[1].split(b"};")[0]
            self.assertEqual(bytes.fromhex(b"".join(re.findall(rb"0x([a-f0-9]{2})", chunk)).decode()),
                             base64.b64decode(self.document[name]))
        chunk = header.split(b"embedded_asset_aad = {")[1].split(b"};")[0]
        self.assertEqual(bytes.fromhex(b"".join(re.findall(rb"0x([a-f0-9]{2})", chunk)).decode()),
                         _context(**CONTEXT))
        for value in (self.key, self.plaintext):
            self.assertNotIn(value, b"".join(files.values()))
            self.assertNotIn(value.hex(), json.dumps(result))

    def test_malformed_envelope_or_context_has_no_outputs(self):
        malformed = [
            {}, {**self.document, "unexpected": "field"},
            {**self.document, "format": "other"},
            {**self.document, "salt": base64.b64encode(bytes(31)).decode()},
            {**self.document, "nonce": base64.b64encode(bytes(13)).decode()},
            {**self.document, "ciphertext": base64.b64encode(bytes(15)).decode()},
            {**self.document, "salt": self.document["salt"] + "\n"},
        ]
        for document in malformed:
            with self.subTest(document=document):
                with self.assertRaises(GuardError):
                    self.export(document)
                self.assertFalse(self.output.exists())
        for context in (dict(product=" bad"), dict(asset_id=""),
                        {field: "😀" * 128 for field in CONTEXT}):
            with self.subTest(context=context):
                with self.assertRaises(GuardError):
                    self.export(**context)
                self.assertFalse(self.output.exists())

    def test_existing_files_links_and_failed_writes_are_preserved(self):
        self.output.mkdir()
        sentinel = self.output / "keep"
        sentinel.write_bytes(b"other owner")
        with self.assertRaises(GuardError):
            self.export()
        self.assertEqual(sentinel.read_bytes(), b"other owner")
        sentinel.unlink()
        self.output.rmdir()

        def fail(path, data, **kwargs):
            if path.name == "releaseguard_asset.hpp":
                raise OSError("injected write failure")
            write_new(path, data, **kwargs)
        with patch("releaseguard.native_asset.write_new", side_effect=fail):
            with self.assertRaisesRegex(OSError, "injected"):
                self.export()
        self.assertFalse(self.output.exists())
        try:
            self.output.symlink_to(self.work / "missing")
        except (OSError, NotImplementedError):
            return
        with self.assertRaises(GuardError):
            self.export()
        self.assertTrue(self.output.is_symlink())

    def test_export_does_not_claim_to_authenticate_without_the_key(self):
        altered = {**self.document, "ciphertext": base64.b64encode(bytes(48)).decode()}
        result = self.export(altered)
        self.assertEqual(result["authentication"], "performed by the native opener with an external key")
        with self.assertRaises(GuardError):
            open_asset(altered, self.key, **CONTEXT)


FIXTURE = r"""
#include "releaseguard_asset.hpp"
#include <algorithm>
#include <iostream>
#include <string_view>

int main(int argc, char** argv) {
    const std::string_view requested = argc > 1 ? argv[1] : "ordinary";
    const bool direct = requested.substr(0, 7) == "direct-";
    const std::string_view mode = direct ? requested.substr(7) : requested;
    releaseguard::native_asset_key key{};
    std::cin.read(reinterpret_cast<char*>(key.data()), key.size());
    if (std::cin.gcount() != 32 || std::cin.peek() != EOF) return 2;
    auto asset = releaseguard::embedded_asset;
    auto ciphertext = releaseguard::embedded_asset_ciphertext;
    auto aad = releaseguard::embedded_asset_aad;
    asset.ciphertext = ciphertext.data();
    asset.aad = aad.data();
    if (mode == "bad-tag") ciphertext.back() ^= 1;
    if (mode == "bad-ciphertext") ciphertext.front() ^= 1;
    if (mode == "bad-context") aad.back() ^= 1;
    if (mode == "bad-salt") asset.salt.front() ^= 1;
    if (mode == "bad-nonce") asset.nonce.front() ^= 1;
    if (mode == "truncated") --asset.ciphertext_size;
    if (mode == "short-tag") asset.ciphertext_size = 15;
    if (mode == "oversized") asset.ciphertext_size = 1024 * 1024 + 17;
    if (mode == "null-ciphertext") asset.ciphertext = nullptr;
    if (mode == "null-aad") asset.aad = nullptr;
    if (mode == "empty-aad") asset.aad_size = 0;
    if (mode == "oversized-aad") asset.aad_size = 1025;
    if (mode == "no-provider") {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (EVP_set_default_properties(nullptr, "provider=nonexistent") != 1) return 2;
#else
        return 77;
#endif
    }
    if (direct) {
        const std::size_t payload_size = releaseguard::embedded_asset_ciphertext.size() - 16;
        std::size_t capacity = payload_size == 0 ? 1 : payload_size;
        if (mode == "extra-capacity") capacity += 11;
        if (mode == "small-capacity") --capacity;
        if (mode == "zero-capacity") capacity = 0;
        std::vector<unsigned char> buffer(capacity + 2, 0xab);
        unsigned char* output = mode == "null-output" ? nullptr : buffer.data() + 1;
        std::size_t output_size = 137;
        bool result = releaseguard::open_native_asset_into(key, asset, output, capacity, output_size);
        const bool first_opened = result;
        if (mode == "repeat-wrong-key" && result) {
            key.front() ^= 1;
            output_size = 137;
            result = releaseguard::open_native_asset_into(key, asset, output, capacity, output_size);
        }
        OPENSSL_cleanse(key.data(), key.size());
        if (mode == "repeat-wrong-key" && !first_opened) return 4;
        if (buffer.front() != 0xab || buffer.back() != 0xab) return 4;
        if (!result) {
            const unsigned char expected = output == nullptr ? 0xab : 0;
            const bool cleared = std::all_of(buffer.begin() + 1, buffer.end() - 1,
                                            [expected](unsigned char value) { return value == expected; });
            return output_size == 0 && cleared ? 3 : 4;
        }
        if (output_size != payload_size || output_size > capacity) return 4;
        if (!std::all_of(buffer.begin() + 1 + output_size, buffer.end() - 1,
                         [](unsigned char value) { return value == 0; })) return 4;
        std::cout.write(reinterpret_cast<const char*>(output), output_size);
        OPENSSL_cleanse(output, capacity);
        return 0;
    }
    std::vector<unsigned char> output(137, 0xab);
    const bool result = mode == "wrapper"
        ? releaseguard::open_embedded_asset(key, output)
        : releaseguard::open_native_asset(key, asset, output);
    OPENSSL_cleanse(key.data(), key.size());
    if (!result) return output.empty() ? 3 : 4;
    std::cout.write(reinterpret_cast<const char*>(output.data()), output.size());
    if (!output.empty()) OPENSSL_cleanse(output.data(), output.size());
    return 0;
}
"""


class CompiledNativeAsset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def unavailable(reason):
            if os.environ.get("RELEASEGUARD_REQUIRE_OPENSSL_NATIVE") == "1":
                raise AssertionError(reason)
            raise unittest.SkipTest(reason)
        cxx = shutil.which("c++")
        if os.name != "posix" or not cxx:
            unavailable("requires Unix-style C++17 toolchain and libcrypto")
        temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        cls.work = Path(temp.name).resolve()
        cls.cxx = cxx
        ready = subprocess.run(
            [cxx, "-std=c++17", "-x", "c++", "-", "-lcrypto", "-o", str(cls.work / "check")],
            input="#include <openssl/evp.h>\n#include <openssl/kdf.h>\nint main(){return EVP_PKEY_HKDF?0:1;}\n",
            text=True, capture_output=True, timeout=60)
        if ready.returncode:
            unavailable("OpenSSL development headers or libcrypto linker unavailable")
        cls.source = cls.work / "reader.cpp"
        cls.source.write_text(FIXTURE, encoding="ascii")
        cls.key = secrets.token_bytes(32)
        cls.payload = secrets.token_bytes(32)
        cls.app = cls.build("normal", cls.payload, CONTEXT)

    @classmethod
    def build(cls, name, plaintext, context):
        folder = cls.work / name
        folder.mkdir()
        document = seal_asset(plaintext, cls.key, **context)
        export_native_asset(document, folder / "include", **context)
        app = folder / "reader"
        compiled = subprocess.run(
            [cls.cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
             "-I", str(folder / "include"), str(cls.source), "-lcrypto", "-o", str(app)],
            capture_output=True, text=True, timeout=120)
        if compiled.returncode:
            raise AssertionError(compiled.stderr)
        return app

    def call(self, key, mode="ordinary", app=None):
        return subprocess.run([str(self.app if app is None else app), mode],
                              input=key, capture_output=True, timeout=20)

    def test_exact_python_ciphertext_decrypts_natively_without_plaintext_or_key_in_elf(self):
        for mode in ("ordinary", "wrapper"):
            result = self.call(self.key, mode)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, self.payload)
        self.assertNotIn(self.key, self.app.read_bytes())
        self.assertNotIn(self.payload, self.app.read_bytes())

    def test_direct_buffer_exact_capacity_and_cleansed_padding(self):
        for mode in ("direct-ordinary", "direct-extra-capacity"):
            with self.subTest(mode=mode):
                result = self.call(self.key, mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, self.payload)

    def test_direct_buffer_rejects_short_null_and_zero_capacities(self):
        for mode in ("direct-small-capacity", "direct-null-output", "direct-zero-capacity"):
            with self.subTest(mode=mode):
                result = self.call(self.key, mode)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_direct_buffer_failures_wipe_previous_output_and_reset_size(self):
        wrong = bytes([self.key[0] ^ 1]) + self.key[1:]
        calls = [("wrong-key", self.call(wrong, "direct-ordinary"))]
        modes = ("bad-tag", "bad-ciphertext", "bad-context", "bad-salt", "bad-nonce",
                 "truncated", "short-tag", "oversized", "null-ciphertext", "null-aad",
                 "empty-aad", "oversized-aad", "repeat-wrong-key")
        calls.extend((mode, self.call(self.key, "direct-" + mode)) for mode in modes)
        for mode, result in calls:
            with self.subTest(mode=mode):
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(result.stdout, b"")
        result = self.call(self.key, "direct-no-provider")
        if result.returncode == 77:
            self.skipTest("OpenSSL provider controls require OpenSSL 3")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_direct_buffer_uses_no_cpp_plaintext_allocation(self):
        source = self.work / "no-plaintext-allocation.cpp"
        source.write_text(r'''
#include "releaseguard_asset.hpp"
#include <cstdio>
#include <new>

extern bool refuse_allocation;

int main(int argc, char**) {
    releaseguard::native_asset_key key{};
    if (std::fread(key.data(), 1, key.size(), stdin) != key.size()) return 2;
    std::array<unsigned char, 32> output{};
    std::size_t output_size = 137;
    bool opened = false;
    refuse_allocation = true;
    try {
        if (argc > 1) {
            std::vector<unsigned char> ordinary;
            opened = releaseguard::open_native_asset(key, releaseguard::embedded_asset, ordinary);
        } else {
            opened = releaseguard::open_native_asset_into(
                key, releaseguard::embedded_asset, output.data(), output.size(), output_size);
        }
    } catch (const std::bad_alloc&) {
        OPENSSL_cleanse(key.data(), key.size());
        return 3;
    }
    refuse_allocation = false;
    OPENSSL_cleanse(key.data(), key.size());
    if (!opened || output_size != output.size()) return 4;
    const bool written = std::fwrite(output.data(), 1, output.size(), stdout) == output.size();
    OPENSSL_cleanse(output.data(), output.size());
    return written ? 0 : 5;
}
''', encoding="ascii")
        allocator = self.work / "allocation-control.cpp"
        allocator.write_text(r'''
#include <cstdlib>
#include <new>

bool refuse_allocation = false;
void* operator new(std::size_t size) {
    if (refuse_allocation) throw std::bad_alloc();
    void* memory = std::malloc(size == 0 ? 1 : size);
    if (!memory) throw std::bad_alloc();
    return memory;
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }
''', encoding="ascii")
        app = self.work / "no-plaintext-allocation"
        compiled = subprocess.run(
            [self.cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
             "-I", str(self.app.parent / "include"), str(source), str(allocator),
             "-lcrypto", "-o", str(app)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        for arguments, expected_code, expected_output in (
            ([], 0, self.payload), (["vector-control"], 3, b""),
        ):
            result = subprocess.run([str(app), *arguments], input=self.key,
                                    capture_output=True, timeout=20)
            self.assertEqual(result.returncode, expected_code, result.stderr)
            self.assertEqual(result.stdout, expected_output)

    def test_two_assets_in_separate_translation_units_keep_their_own_data(self):
        translation_units = []
        for name, payload in (("first", b"asset A"), ("second", b"asset B")):
            context = {**CONTEXT, "asset_id": name}
            document = seal_asset(payload, self.key, **context)
            export_native_asset(document, self.work / name, **context)
            source = self.work / (name + ".cpp")
            source.write_text(
                '#include "' + name + '/releaseguard_asset.hpp"\n'
                'bool open_' + name + '(const releaseguard::native_asset_key& key, '
                'std::vector<unsigned char>& output) {'
                'return releaseguard::open_embedded_asset(key, output); }\n',
                encoding="ascii")
            translation_units.append(source)
        main = self.work / "multiple.cpp"
        main.write_text(
            '#include "first/releaseguard/sealed_asset.hpp"\n#include <iostream>\n'
            'bool open_first(const releaseguard::native_asset_key&, std::vector<unsigned char>&);\n'
            'bool open_second(const releaseguard::native_asset_key&, std::vector<unsigned char>&);\n'
            'int main() { releaseguard::native_asset_key key{}; '
            'std::cin.read(reinterpret_cast<char*>(key.data()), key.size()); '
            'if (std::cin.gcount() != 32) return 2; '
            'std::vector<unsigned char> first, second; '
            'if (!open_first(key, first) || !open_second(key, second)) return 3; '
            'std::cout.write(reinterpret_cast<const char*>(first.data()), first.size()); '
            'std::cout.write(reinterpret_cast<const char*>(second.data()), second.size()); '
            'return 0; }\n',
            encoding="ascii")
        app = self.work / "multiple-assets"
        compiled = subprocess.run(
            [self.cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
             *map(str, translation_units), str(main), "-lcrypto", "-o", str(app)],
            text=True, capture_output=True, timeout=120)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        result = subprocess.run([str(app)], input=self.key, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"asset Aasset B")

    def test_wrong_key_context_tag_lengths_and_provider_leave_empty_output(self):
        wrong = bytes([self.key[0] ^ 1]) + self.key[1:]
        calls = [self.call(wrong)]
        modes = ("bad-tag", "bad-ciphertext", "bad-context", "bad-salt", "bad-nonce",
                 "truncated", "short-tag", "oversized", "null-ciphertext", "null-aad",
                 "empty-aad", "oversized-aad")
        calls.extend(self.call(self.key, mode) for mode in modes)
        for index, result in enumerate(calls):
            with self.subTest(case=index):
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(result.stdout, b"")
        result = self.call(self.key, "no-provider")
        if result.returncode == 77:
            self.skipTest("OpenSSL provider controls require OpenSSL 3")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, b"")

    def test_empty_single_byte_unicode_and_maximum_plaintext(self):
        for name, payload, context in (
            ("empty", b"", CONTEXT),
            ("one", b"\xff", CONTEXT),
            ("unicode", bytes(range(256)), {**CONTEXT, "asset_id": '资源/café/"\\"'}),
            ("maximum", secrets.token_bytes(MAX_ASSET_BYTES), CONTEXT),
        ):
            with self.subTest(case=name):
                app = self.build(name, payload, context)
                result = self.call(self.key, "wrapper", app)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, payload)
                result = self.call(self.key, "bad-tag", app)
                self.assertEqual(result.returncode, 3)
                self.assertEqual(result.stdout, b"")
                result = self.call(self.key, "direct-ordinary", app)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, payload)
                result = self.call(self.key, "direct-bad-tag", app)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(result.stdout, b"")
