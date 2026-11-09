"""Authenticated VM storage, guarded integer ABIs and native loader lifecycle."""

from __future__ import annotations

import base64
import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from releaseguard.core import GuardError
from releaseguard.native_asset import export_native_asset
from releaseguard.native_code_seal import seal_virtualized_ir
from releaseguard.sealed import SEALED_FORMAT, open_asset, seal_asset


CONTEXT = dict(product="code-test", release="1", module_id="integer-module")
ASSET_CONTEXT = dict(product=CONTEXT["product"], release=CONTEXT["release"],
                     purpose="vm-code", asset_id=CONTEXT["module_id"])
CODE = bytes((index * 73 + 17) & 255 for index in range(64))
WORDS = [0xa1b2c3d4e5f60718 + index * 0x0203040506070809 for index in range(8)]
DESCRIPTORS = struct.pack("<8Q", *WORDS)


def fixture(wrappers=(("rg_compute", 32),)):
    encoded = "".join(f"\\{value:02X}" for value in CODE)
    descriptor = "private constant [8 x i64] [" + ", ".join(f"i64 {value}" for value in WORDS) + "]"
    source = f'''target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"
@code = private constant [64 x i8] c"{encoded}"
@descriptors = {descriptor}
@native_calls = private constant [1 x ptr] zeroinitializer
@llvm.compiler.used = appending global [3 x ptr] [ptr @code, ptr @descriptors, ptr @native_calls], section "llvm.metadata"
define private i64 @vm_runtime(i64 %token, ptr %returns, ptr %arguments) {{
entry:
  %token.unadd = sub i64 %token, 1
  %token.index = mul i64 %token.unadd, 1
  %descriptor.index.ok = icmp ult i64 %token.index, 1
  br i1 %descriptor.index.ok, label %descriptor.decode, label %default.return
descriptor.decode:
  %descriptor.guard.row = mul i64 %token.index, 8
  %descriptor.guard.index = add i64 %descriptor.guard.row, 7
  %descriptor.guard.ptr = getelementptr inbounds [8 x i64], ptr @descriptors, i64 0, i64 %descriptor.guard.index
  %descriptor.guard.encrypted = load i64, ptr %descriptor.guard.ptr, align 8
  %descriptor.key.add = add i64 0, 0
  %descriptor.key.mask = add i64 0, 0
  %descriptor.key.rot = add i64 0, 1
  %descriptor.guard.unadd = sub i64 %descriptor.guard.encrypted, %descriptor.key.add
  %descriptor.guard.unxor = xor i64 %descriptor.guard.unadd, %descriptor.key.mask
  %descriptor.guard.plain.amount = and i64 %descriptor.key.rot, 63
  %descriptor.guard.plain.right = lshr i64 %descriptor.guard.unxor, %descriptor.guard.plain.amount
  %descriptor.guard.plain.neg = sub i64 0, %descriptor.guard.plain.amount
  %descriptor.guard.plain.left.amount = and i64 %descriptor.guard.plain.neg, 63
  %descriptor.guard.plain.left = shl i64 %descriptor.guard.unxor, %descriptor.guard.plain.left.amount
  %descriptor.guard.plain = or i64 %descriptor.guard.plain.left, %descriptor.guard.plain.right
  %descriptor.guard.expected.mul1 = add i64 0, 0
  %descriptor.guard.expected.shr31 = lshr i64 %descriptor.guard.expected.mul1, 31
  %descriptor.guard.expected = xor i64 %descriptor.guard.expected.mul1, %descriptor.guard.expected.shr31
  %descriptor.guard.ok = icmp eq i64 %descriptor.guard.plain, %descriptor.guard.expected
  br i1 %descriptor.guard.ok, label %descriptor.ready, label %default.return
descriptor.ready:
  %argument = load i64, ptr %arguments, align 8
  %byte = load i8, ptr @code, align 1
  %wide = zext i8 %byte to i64
  %descriptor = load i64, ptr @descriptors, align 8
  %native = load ptr, ptr @native_calls, align 8
  %mixed = xor i64 %argument, %descriptor
  %result = add i64 %mixed, %wide
  ret i64 %result
default.return:
  ret i64 0
}}
'''
    observations = []
    for name, width in wrappers:
        attribute = "zeroext " if width < 32 else ""
        parameter_attribute = " zeroext" if width < 32 else ""
        widen = f"zext i{width} %x to i64" if width < 64 else "add i64 %x, 0"
        returned = (f"  %narrow = trunc i64 %result to i{width}\n  ret i{width} %narrow"
                    if width < 64 else "  ret i64 %result")
        source += f'''define {attribute}i{width} @{name}(i{width}{parameter_attribute} %x) {{
entry:
  %returns = alloca [3 x i64], align 8
  %arguments = alloca [16 x i64], align 8
  %wide = {widen}
  store i64 %wide, ptr %arguments, align 8
  %token = add i64 0, 1
  %result = call i64 @vm_runtime(i64 %token, ptr %returns, ptr %arguments)
{returned}
}}
'''
        observations.append({
            "name": name, "requested": True, "changed": True,
            "vm_coverage": {
                "wrapper_replaced": True, "runtime_function": "vm_runtime", "original_body_absent": True,
                "bytecode_globals": [{"name": "code", "bytes": len(CODE), "sha256": hashlib.sha256(CODE).hexdigest()}],
                "descriptor_globals": [{"name": "descriptors", "words": len(WORDS),
                                         "ir_sha256": hashlib.sha256(descriptor.encode()).hexdigest()}],
            },
        })
    return source, observations


def embedded_array(header, name):
    block = header.split(("embedded_asset_" + name + " = {").encode())[1].split(b"};")[0]
    return bytes(int(value, 16) for value in re.findall(rb"0x([0-9a-f]{2})", block))


def document_from_files(files):
    header = files["releaseguard_native_code_asset.hpp"]
    return {"format": SEALED_FORMAT, **{name: base64.b64encode(embedded_array(header, name)).decode("ascii")
                                       for name in ("salt", "nonce", "ciphertext")}}


class NativeCodeSealValidation(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_bytes(32)
        self.source, self.coverage = fixture()

    def seal(self, source=None, coverage=None, **context):
        return seal_virtualized_ir(self.source if source is None else source,
                                   self.coverage if coverage is None else coverage,
                                   self.key, **{**CONTEXT, **context})

    def test_all_initializers_are_encrypted_and_only_zero_storage_remains(self):
        rewritten, files, details = self.seal()
        plaintext = open_asset(document_from_files(files), self.key, **ASSET_CONTEXT)
        self.assertEqual(plaintext[:len(CODE) + 56], CODE + DESCRIPTORS[:56])
        self.assertEqual(plaintext[len(CODE) + 56:len(CODE) + 64], plaintext[-8:])
        self.assertNotEqual(plaintext[-8:], bytes(8))
        self.assertEqual(len(plaintext), len(CODE) + len(DESCRIPTORS) + 8)
        self.assertEqual(details["payload_bytes"], len(plaintext))
        self.assertEqual(details["payload_sha256"], hashlib.sha256(plaintext).hexdigest())
        self.assertEqual(len(files), 4)
        material = rewritten.encode() + b"".join(files.values()) + json.dumps(details).encode()
        for secret in (CODE, DESCRIPTORS, self.key):
            self.assertNotIn(secret, material)
            self.assertNotIn(secret.hex().encode(), material)
        for word in WORDS:
            self.assertNotIn(str(word), rewritten)
        for item in details["storage"]:
            self.assertRegex(item["symbol"], r"^[A-Za-z_][A-Za-z0-9_]*$")
            self.assertIn("@" + item["symbol"] + " = global", rewritten)
        self.assertEqual(rewritten.count("zeroinitializer"), 4)
        self.assertIn("ret i32 0", rewritten)
        self.assertNotIn("@code", rewritten)
        self.assertNotIn("@descriptors", rewritten)

    def test_descriptor_guards_are_fresh_and_report_only_their_shape(self):
        first, second = self.seal(), self.seal()
        left = open_asset(document_from_files(first[1]), self.key, **ASSET_CONTEXT)
        right = open_asset(document_from_files(second[1]), self.key, **ASSET_CONTEXT)
        self.assertNotEqual(left[-8:], right[-8:])
        for bundle, plaintext in ((first, left), (second, right)):
            metadata = bundle[2]["randomized_descriptor_guards"]
            self.assertEqual(metadata["records"], 1)
            self.assertEqual(metadata["descriptor_word_index"], 7)
            self.assertTrue(metadata["nonzero_guard_required"])
            guard = struct.unpack("<Q", plaintext[-8:])[0]
            public = bundle[0] + json.dumps(bundle[2])
            self.assertNotIn(str(guard), public)
            self.assertNotIn(plaintext[-8:].hex(), public)
            self.assertIn("icmp eq i64 %descriptor.guard.encrypted", bundle[0])
            self.assertIn("guard.nonzero = icmp ne i64", bundle[0])
        with patch("releaseguard.native_code_seal.secrets.randbelow", return_value=0):
            _, files, _ = self.seal()
        self.assertEqual(open_asset(document_from_files(files), self.key, **ASSET_CONTEXT)[-8:], struct.pack("<Q", 1))

    def test_guard_shape_changes_and_extra_value_uses_fail_closed(self):
        changes = (
            ("%descriptor.guard.row, 7", "%descriptor.guard.row, 6"),
            ("%token.index, 8", "%token.unadd, 8"),
            ("%token.index, 1", "%token.index, 2"),
            ("ptr @descriptors, i64 0, i64 %descriptor.guard.index", "ptr @descriptors, i64 0, i64 7"),
            ("load i64, ptr %descriptor.guard.ptr, align 8", "load i64, ptr @descriptors, align 8"),
            ("icmp eq i64 %descriptor.guard.plain", "icmp ne i64 %descriptor.guard.plain"),
            ("  %argument = load", "  %extra = add i64 %descriptor.guard.encrypted, 1\n  %argument = load"),
            ("default.return:\n  ret i64 0", "default.return:\n  br label %descriptor.ready"),
            ("default.return:\n  ret i64 0", "default.return:\n  br label %descriptor.decode"),
        )
        for before, after in changes:
            with self.subTest(change=before), self.assertRaises(GuardError):
                self.seal(source=self.source.replace(before, after))

    def test_module_assembly_is_rejected_and_ident_is_removed(self):
        with self.assertRaisesRegex(GuardError, "module assembly"):
            self.seal(source=self.source + '\nmodule asm "owned marker"\n')
        rewritten, _, _ = self.seal(source=self.source + '\n!llvm.ident = !{!9}\n!9 = !{!"owned marker"}\n')
        self.assertNotIn("!llvm.ident", rewritten)

    def test_linker_metadata_is_rejected_and_source_filename_is_normalized(self):
        for name in ("llvm.linker.options", "llvm.dependent-libraries"):
            with self.subTest(name=name), self.assertRaisesRegex(GuardError, "linker metadata"):
                self.seal(source=self.source + f'\n!{name} = !{{!9}}\n!9 = !{{!"owned marker"}}\n')
        for filename in ("", 'source_filename = "owned-private-marker"\n'):
            rewritten, _, _ = self.seal(source=filename + self.source)
            self.assertEqual(rewritten.count('source_filename = "releaseguard-sealed-code"'), 1)
            self.assertNotIn("owned-private-marker", rewritten)

    def test_required_native_tests_fail_without_tool_configuration(self):
        with patch.dict(os.environ, {"RELEASEGUARD_REQUIRE_NATIVE_VIRTUALIZATION": "1"}, clear=True):
            with self.assertRaisesRegex(AssertionError, "requires RELEASEGUARD_LLVM_BIN"):
                NativeCodeSealCompiled.setUpClass()

    def test_real_encryption_rejects_wrong_key_tamper_and_context(self):
        _, files, _ = self.seal()
        document = document_from_files(files)
        with self.assertRaises(GuardError):
            open_asset(document, bytes(value ^ 0xff for value in self.key), **ASSET_CONTEXT)
        for field in ("salt", "nonce", "ciphertext"):
            altered = dict(document)
            data = bytearray(base64.b64decode(document[field]))
            data[-1] ^= 1
            altered[field] = base64.b64encode(data).decode("ascii")
            with self.subTest(field=field), self.assertRaises(GuardError):
                open_asset(altered, self.key, **ASSET_CONTEXT)
        for field in ASSET_CONTEXT:
            with self.subTest(field=field), self.assertRaises(GuardError):
                open_asset(document, self.key, **{**ASSET_CONTEXT, field: "different"})

    def test_unsupported_or_uncovered_storage_is_rejected(self):
        changes = (
            self.source.replace("[1 x ptr] zeroinitializer", "[1 x ptr] [ptr @vm_runtime]"),
            self.source.replace("@native_calls = private constant", "@native_calls = private global"),
            self.source + '@extra = private constant [4 x i8] c"abcd"\n',
            self.source.replace("i64 " + str(WORDS[0]), "i64 1"),
            self.source.replace("x86_64-pc-linux-gnu", "i686-pc-linux-gnu"),
        )
        for source in changes:
            with self.subTest(source=source[-80:]), self.assertRaises(GuardError):
                self.seal(source=source)
        uncovered = copy.deepcopy(self.coverage)
        uncovered[0]["requested"] = False
        uncovered[0]["vm_coverage"] = None
        with self.assertRaisesRegex(GuardError, "retained original"):
            self.seal(coverage=uncovered)

    def test_unverified_multiblock_or_pointer_abi_wrappers_are_rejected(self):
        altered = copy.deepcopy(self.coverage)
        altered[0]["vm_coverage"]["wrapper_replaced"] = False
        with self.assertRaises(GuardError):
            self.seal(coverage=altered)
        for source in (
            self.source.replace("define i32 @rg_compute(i32 %x)", "define ptr @rg_compute(i32 %x)"),
            self.source.replace("define i32 @rg_compute(i32 %x)", "define i32 @rg_compute(ptr %x)"),
            self.source.replace("  %returns = alloca", "  br label %next\nnext:\n  %returns = alloca"),
            self.source.replace("define i32 @rg_compute(i32 %x) {", "define i32 @rg_compute(i32 %x) #9 {")
            + "attributes #9 = { memory(none) }\n",
        ):
            with self.subTest(source=source[-80:]), self.assertRaises(GuardError):
                self.seal(source=source)

    def test_context_derived_names_are_independent_and_keys_are_validated(self):
        first = self.seal()[2]
        second = self.seal(module_id="second-module")[2]
        self.assertNotEqual(first["cpp_namespace"], second["cpp_namespace"])
        self.assertNotEqual(first["ready_symbol"], second["ready_symbol"])
        with self.assertRaises(GuardError):
            seal_virtualized_ir(self.source, self.coverage, bytes(31), **CONTEXT)
        with self.assertRaises(GuardError):
            self.seal(module_id=" invalid")


class NativeCodeSealCompiled(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        llvm = os.environ.get("RELEASEGUARD_LLVM_BIN")
        cls.cxx = shutil.which("c++")
        if not llvm or not cls.cxx:
            reason = "requires RELEASEGUARD_LLVM_BIN plus C++17/OpenSSL development files"
            if os.environ.get("RELEASEGUARD_REQUIRE_NATIVE_VIRTUALIZATION") == "1":
                raise AssertionError(reason)
            raise unittest.SkipTest(reason)
        cls.llvm = Path(llvm)
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.work = Path(temporary.name)
        cls.key = secrets.token_bytes(32)
        cls.wrong = bytes(value ^ 0xff for value in cls.key)
        source, coverage = fixture()
        cls.bundle = seal_virtualized_ir(source, coverage, cls.key, **CONTEXT)
        cls.normal, cls.folder = cls.build("normal", cls.bundle)

    @classmethod
    def run_tool(cls, arguments):
        result = subprocess.run(list(map(str, arguments)), capture_output=True, timeout=120)
        if result.returncode or result.stderr:
            raise AssertionError(result.stderr.decode(errors="replace"))
        return result

    @classmethod
    def emit(cls, folder, bundle):
        ir, files, details = bundle
        folder.mkdir()
        for name, content in files.items():
            (folder / name).write_bytes(content)
        (folder / "input.ll").write_text(ir)
        cls.run_tool([cls.llvm / "opt", "-S", "-passes=verify", "-verify-each", folder / "input.ll",
                      "-o", folder / "verified.ll"])
        cls.run_tool([cls.llvm / "llc", "-O=2", "-relocation-model=pic", "-filetype=obj",
                      folder / "verified.ll", "-o", folder / "protected.o"])
        return details

    @classmethod
    def build(cls, name, bundle):
        folder = cls.work / name
        details = cls.emit(folder, bundle)
        namespace = details["cpp_namespace"]
        (folder / "shim.cpp").write_text('''#include "releaseguard_native_code.hpp"
extern "C" bool rg_initialize(const unsigned char* input) {
    releaseguard::native_asset_key key{};
    std::memcpy(key.data(), input, key.size());
    const bool result = ''' + namespace + '''::initialize_native_code(key);
    OPENSSL_cleanse(key.data(), key.size());
    return result;
}
extern "C" void rg_clear() { ''' + namespace + '''::clear_native_code(); }
''')
        library = folder / "module.so"
        cls.run_tool([cls.cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                      folder / "protected.o", folder / "releaseguard_native_code.cpp", folder / "shim.cpp",
                      "-lcrypto", "-o", library])
        loaded = ctypes.CDLL(str(library))
        loaded.rg_initialize.argtypes = [ctypes.c_char_p]
        loaded.rg_initialize.restype = ctypes.c_bool
        loaded.rg_clear.argtypes = []
        loaded.rg_clear.restype = None
        for wrapper in details["guarded_wrappers"]:
            ctype = {"i1": ctypes.c_bool, "i8": ctypes.c_uint8, "i16": ctypes.c_uint16,
                     "i32": ctypes.c_uint32, "i64": ctypes.c_uint64}[wrapper["return_type"]]
            function = getattr(loaded, wrapper["name"])
            function.argtypes = [ctype]
            function.restype = ctype
        return loaded, folder

    def assert_cleared(self, loaded, details):
        self.assertEqual(ctypes.c_ubyte.in_dll(loaded, details["ready_symbol"]).value, 0)
        for item in details["storage"]:
            memory = (ctypes.c_ubyte * item["bytes"]).in_dll(loaded, item["symbol"])
            self.assertEqual(bytes(memory), bytes(item["bytes"]))

    def test_unlock_clear_and_failed_reinitialization(self):
        loaded = self.normal
        loaded.rg_clear()
        self.assert_cleared(loaded, self.bundle[2])
        self.assertEqual(loaded.rg_compute(123), 0)
        self.assertTrue(loaded.rg_initialize(self.key))
        for value in (0, 1, 255, 65535, 0x7fffffff, 0x80000000, 0xffffffff):
            self.assertEqual(loaded.rg_compute(value), ((value ^ WORDS[0]) + CODE[0]) & 0xffffffff)
        self.assertFalse(loaded.rg_initialize(self.wrong))
        self.assert_cleared(loaded, self.bundle[2])
        self.assertEqual(loaded.rg_compute(123), 0)
        self.assertTrue(loaded.rg_initialize(self.key))
        loaded.rg_clear()
        self.assert_cleared(loaded, self.bundle[2])
        self.assertEqual(loaded.rg_compute(123), 0)
        image = (self.folder / "module.so").read_bytes()
        for secret in (CODE, DESCRIPTORS, self.key):
            self.assertNotIn(secret, image)

    def test_cleared_storage_rejects_even_with_ready_forced(self):
        loaded = self.normal
        loaded.rg_clear()
        ready = ctypes.c_ubyte.in_dll(loaded, self.bundle[2]["ready_symbol"])
        ready.value = 1
        try:
            for value in (0, 1, 123, 0xffffffff):
                self.assertEqual(loaded.rg_compute(value), 0)
        finally:
            loaded.rg_clear()
        self.assert_cleared(loaded, self.bundle[2])

    def test_supported_integer_return_and_parameter_abis(self):
        source, coverage = fixture(tuple(("rg_width_" + str(width), width) for width in (1, 8, 16, 32, 64)))
        bundle = seal_virtualized_ir(source, coverage, self.key, **{**CONTEXT, "module_id": "widths"})
        loaded, _ = self.build("widths", bundle)
        for width in (1, 8, 16, 32, 64):
            self.assertEqual(getattr(loaded, "rg_width_" + str(width))(1), 0)
        self.assertTrue(loaded.rg_initialize(self.key))
        for width in (1, 8, 16, 32, 64):
            mask = (1 << width) - 1
            for value in (0, mask):
                self.assertEqual(getattr(loaded, "rg_width_" + str(width))(value),
                                 ((value ^ WORDS[0]) + CODE[0]) & mask)
        loaded.rg_clear()
        self.assert_cleared(loaded, bundle[2])

    def test_authenticated_length_digest_tamper_and_context_fail_before_copy(self):
        variants = {}
        for field in ("ciphertext", "aad"):
            files = dict(self.bundle[1])
            header = files["releaseguard_native_code_asset.hpp"]
            marker = ("embedded_asset_" + field + " = {").encode()
            offset = header.index(marker) + len(marker)
            matched = re.search(rb"0x([0-9a-f]{2})", header[offset:])
            start, end = offset + matched.start(), offset + matched.end()
            header = header[:start] + f"0x{int(matched[1], 16) ^ 1:02x}".encode() + header[end:]
            files["releaseguard_native_code_asset.hpp"] = header
            variants[field] = files
        original = open_asset(document_from_files(self.bundle[1]), self.key, **ASSET_CONTEXT)
        for name, plaintext in (("authenticated-short", original[:-1]),
                                ("authenticated-different", bytes(value ^ 1 for value in original))):
            encrypted = seal_asset(plaintext, self.key, **ASSET_CONTEXT)
            destination = self.work / (name + "-asset")
            export_native_asset(encrypted, destination, **ASSET_CONTEXT)
            files = dict(self.bundle[1])
            files["releaseguard_native_code_asset.hpp"] = (destination / "releaseguard_asset.hpp").read_bytes().replace(
                b'#include "releaseguard/sealed_asset.hpp"', b'#include "releaseguard_sealed_asset.hpp"')
            variants[name] = files
        for name, files in variants.items():
            with self.subTest(failure=name):
                loaded, _ = self.build(name, (self.bundle[0], files, self.bundle[2]))
                self.assertFalse(loaded.rg_initialize(self.key))
                self.assert_cleared(loaded, self.bundle[2])
                self.assertEqual(loaded.rg_compute(123), 0)

    def test_forced_gcm_final_success_still_rejects_wrong_key(self):
        namespace = self.bundle[2]["cpp_namespace"]
        driver = self.folder / "driver.cpp"
        driver.write_text('''#include "releaseguard_native_code.hpp"
#include <cstdint>
#include <cstdio>
extern "C" std::uint32_t rg_compute(std::uint32_t);
int main() {
    releaseguard::native_asset_key key{};
    if (std::fread(key.data(), 1, key.size(), stdin) != key.size()) return 2;
    bool opened = ''' + namespace + '''::initialize_native_code(key);
    OPENSSL_cleanse(key.data(), key.size());
    std::printf("%u %u\\n", opened ? 1u : 0u, rg_compute(123));
    ''' + namespace + '''::clear_native_code();
    return 0;
}
''')
        app = self.folder / "hook-control"
        self.run_tool([self.cxx, "-std=c++17", "-O2", self.folder / "protected.o",
                       self.folder / "releaseguard_native_code.cpp", driver, "-lcrypto", "-o", app])
        hook_source = self.folder / "forced-final.cpp"
        hook_source.write_text('''#include <openssl/evp.h>
#include <cstdio>
extern "C" int EVP_DecryptFinal_ex(EVP_CIPHER_CTX*, unsigned char*, int* written) {
    *written = 0;
    std::fputs("FORCED_GCM_FINAL\\n", stderr);
    return 1;
}
''')
        hook = self.folder / "forced-final.so"
        self.run_tool([self.cxx, "-shared", "-fPIC", hook_source, "-o", hook])
        env = {**os.environ, "LD_PRELOAD": str(hook)}
        for key, expected in ((self.wrong, b"0 0\n"),
                              (self.key, f"1 {((123 ^ WORDS[0]) + CODE[0]) & 0xffffffff}\n".encode())):
            result = subprocess.run([str(app)], input=key, capture_output=True, env=env, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, expected)
            self.assertEqual(result.stderr, b"FORCED_GCM_FINAL\n")

    def test_two_modules_link_and_initialize_independently(self):
        folders, bundles, keys = [], [], []
        for name in ("first", "second"):
            key = secrets.token_bytes(32)
            source, coverage = fixture((("rg_" + name, 32),))
            bundle = seal_virtualized_ir(source, coverage, key, **{**CONTEXT, "module_id": name})
            folder = self.work / name
            self.emit(folder, bundle)
            folders.append(folder)
            bundles.append(bundle)
            keys.append(key)
        first, second = (bundle[2]["cpp_namespace"] for bundle in bundles)
        source = self.work / "two.cpp"
        source.write_text('''#include "first/releaseguard_native_code.hpp"
#include "second/releaseguard_native_code.hpp"
#include <cstdint>
#include <cstdio>
extern "C" std::uint32_t rg_first(std::uint32_t);
extern "C" std::uint32_t rg_second(std::uint32_t);
int main() {
    releaseguard::native_asset_key a{}, b{};
    if (std::fread(a.data(), 1, a.size(), stdin) != a.size() ||
        std::fread(b.data(), 1, b.size(), stdin) != b.size()) return 2;
    if (rg_first(123) || rg_second(123)) return 3;
    if (!''' + first + '''::initialize_native_code(a) || rg_first(123) == 0 || rg_second(123)) return 4;
    if (''' + second + '''::initialize_native_code(a) || rg_second(123)) return 5;
    if (!''' + second + '''::initialize_native_code(b) || rg_second(123) != rg_first(123)) return 6;
    ''' + first + '''::clear_native_code();
    if (rg_first(123) || rg_second(123) == 0) return 7;
    ''' + second + '''::clear_native_code();
    OPENSSL_cleanse(a.data(), a.size());
    OPENSSL_cleanse(b.data(), b.size());
    return rg_second(123) == 0 ? 0 : 8;
}
''')
        app = self.work / "two-modules"
        self.run_tool([self.cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", source,
                       *(path for folder in folders for path in
                         (folder / "protected.o", folder / "releaseguard_native_code.cpp")),
                       "-lcrypto", "-o", app])
        result = subprocess.run([str(app)], input=b"".join(keys), capture_output=True, timeout=30)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))
        image = app.read_bytes()
        for key in keys:
            self.assertNotIn(key, image)


if __name__ == "__main__":
    unittest.main()
