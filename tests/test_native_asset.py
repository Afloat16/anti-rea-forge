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
#include <iostream>
#include <string_view>

int main(int argc, char** argv) {
    const std::string_view mode = argc > 1 ? argv[1] : "ordinary";
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
