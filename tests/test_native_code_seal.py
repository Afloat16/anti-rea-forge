"""Authenticated VM storage, guarded integer ABIs and native loader lifecycle."""

from __future__ import annotations

import base64
import copy
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from releaseguard.core import GuardError
from releaseguard.native_asset import export_native_asset
from releaseguard.native_code_seal import seal_virtualized_ir
from releaseguard.sealed import SEALED_FORMAT, _context, open_asset, seal_asset


CONTEXT = dict(product="code-test", release="1", module_id="integer-module")
ASSET_CONTEXT = dict(product=CONTEXT["product"], release=CONTEXT["release"],
                     purpose="vm-code", asset_id=CONTEXT["module_id"])
CODE = bytes((index * 73 + 17) & 255 for index in range(64))
WORDS = [0xa1b2c3d4e5f60718 + index * 0x0203040506070809 for index in range(8)]
DESCRIPTORS = struct.pack("<8Q", *WORDS)


def fixture(wrappers=(("rg_compute", 32),), code=CODE):
    encoded = "".join(f"\\{value:02X}" for value in code)
    descriptor = "private constant [8 x i64] [" + ", ".join(f"i64 {value}" for value in WORDS) + "]"
    source = f'''target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"
@code = private constant [{len(code)} x i8] c"{encoded}"
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
                "bytecode_globals": [{"name": "code", "bytes": len(code), "sha256": hashlib.sha256(code).hexdigest()}],
                "descriptor_globals": [{"name": "descriptors", "words": len(WORDS),
                                         "ir_sha256": hashlib.sha256(descriptor.encode()).hexdigest()}],
            },
        })
    return source, observations


def pcsection_fixtures(source):
    marker = b"OWNED-PLAINTEXT!"
    metadata = ('\n!90 = !{!"rg_owned_aux", !91}\n!91 = !{'
                + ", ".join("i64 " + str(word) for word in struct.unpack("<2Q", marker)) + '}\n')
    replacements = {
        "wrapper": ("define i32 @rg_compute(i32 %x) {",
                    "define i32 @rg_compute(i32 %x) !pcsections !90 {"),
        "runtime": ("define private i64 @vm_runtime(i64 %token, ptr %returns, ptr %arguments) {",
                    "define private i64 @vm_runtime(i64 %token, ptr %returns, ptr %arguments) !pcsections !90 {"),
        "instruction": ("  %argument = load i64, ptr %arguments, align 8",
                        "  %argument = load i64, ptr %arguments, align 8, !pcsections !90"),
    }
    variants = {}
    for name, (original, replacement) in replacements.items():
        if source.count(original) != 1:
            raise AssertionError("PC section fixture requires its exact original instruction/header")
        variants[name] = source.replace(original, replacement) + metadata
    return marker, variants


def uncovered_function(linkage=""):
    # The full-width immediate survives code generation as inspectable bytes.
    marker = b"OWNED-FN"
    value = int.from_bytes(marker, "little")
    definition = (f"define {linkage}i64 @uncovered_plaintext_function(i64 %value) {{\n"
                  f"entry:\n  %result = xor i64 %value, {value}\n  ret i64 %result\n}}\n")
    return marker, definition


def noncanonical_definitions():
    _, definition = uncovered_function("private ")
    return {
        "indented": definition.replace("define ", "  define ", 1),
        "tab": definition.replace("define ", "define\t", 1),
        "same-line": "declare i64 @unused_declaration() " + definition,
        "split-header": definition.replace("define ", "define\n", 1),
    }


def with_definition_identifiers(source):
    # These identifier/label spellings and quoted/comment text are legal data,
    # not extra function definitions. A custom metadata attachment is inert.
    source = 'source_filename = "define text"\n' + source
    source = source.replace("%x", "%define").replace("entry:", "define:")
    source = source.replace("define i32 @rg_compute(i32 %define) {",
                            "define i32 @rg_compute(i32 %define) !define !99 {")
    return source + '\ndeclare i64 @define(i64)\n!99 = !{}\n; define private i64 @comment() {\n'


def with_runtime_helpers(source):
    """Keep an ordinary transitive private helper chain in the VM runtime."""
    source = source.replace("  %result = add i64 %mixed, %wide",
                            "  %helper.result = call i64 @runtime_helper(i64 %mixed)\n"
                            "  %result = add i64 %helper.result, %wide")
    return source + '''
define private i64 @runtime_helper(i64 %value) {
entry:
  %result = call i64 @runtime_leaf(i64 %value)
  ret i64 %result
}
define private i64 @runtime_leaf(i64 %value) {
entry:
  ret i64 %value
}
'''


def embedded_array(header, name):
    block = header.split(("embedded_asset_" + name + " = {").encode())[1].split(b"};")[0]
    return bytes(int(value, 16) for value in re.findall(rb"0x([0-9a-f]{2})", block))


def document_from_files(files):
    header = files["releaseguard_native_code_asset.hpp"]
    return {"format": SEALED_FORMAT, **{name: base64.b64encode(embedded_array(header, name)).decode("ascii")
                                       for name in ("salt", "nonce", "ciphertext")}}


def legacy_tag(source):
    return hashlib.sha256(_context(**ASSET_CONTEXT)
                          + hashlib.sha256(source.encode()).digest()).hexdigest()[:24]


class NativeCodeSealValidation(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_bytes(32)
        self.source, self.coverage = fixture()

    def seal(self, source=None, coverage=None, **context):
        return seal_virtualized_ir(self.source if source is None else source,
                                   self.coverage if coverage is None else coverage,
                                   self.key, **{**CONTEXT, **context})

    def test_all_initializers_are_encrypted_and_only_null_bindings_remain(self):
        rewritten, files, details = self.seal()
        plaintext = open_asset(document_from_files(files), self.key, **ASSET_CONTEXT)
        self.assertEqual(plaintext[:len(CODE) + 56], CODE + DESCRIPTORS[:56])
        self.assertEqual(plaintext[len(CODE) + 56:len(CODE) + 64], plaintext[-8:])
        self.assertNotEqual(plaintext[-8:], bytes(8))
        self.assertEqual(len(plaintext), len(CODE) + len(DESCRIPTORS) + 8)
        self.assertEqual(details["payload_bytes"], len(plaintext))
        self.assertEqual(details["payload_sha256"], hashlib.sha256(plaintext).hexdigest())
        self.assertEqual(len(files), 5)
        material = rewritten.encode() + b"".join(files.values()) + json.dumps(details).encode()
        for secret in (CODE, DESCRIPTORS, self.key):
            self.assertNotIn(secret, material)
            self.assertNotIn(secret.hex().encode(), material)
        for word in WORDS:
            self.assertNotIn(str(word), rewritten)
        for item in details["storage"]:
            self.assertRegex(item["symbol"], r"^[A-Za-z_][A-Za-z0-9_]*$")
            self.assertIn("@" + item["symbol"] + " = global ptr null", rewritten)
            self.assertIn("load ptr, ptr @" + item["symbol"], rewritten)
        self.assertEqual(rewritten.count("zeroinitializer"), 1)
        self.assertIn("ret i32 0", rewritten)
        self.assertNotIn("@code", rewritten)
        self.assertNotIn("@descriptors", rewritten)

    def test_storage_offsets_align_tables_and_decrypt_into_one_protected_mapping(self):
        source, coverage = fixture(code=CODE[:-1])
        rewritten, files, details = self.seal(source, coverage)
        plaintext = open_asset(document_from_files(files), self.key, **ASSET_CONTEXT)
        entries = {item["kind"]: item for item in details["storage"]}
        self.assertEqual(entries["bytecode"]["offset_bytes"], 0)
        self.assertEqual(entries["descriptor"]["offset_bytes"], 64)
        self.assertEqual(entries["guard_expected"]["offset_bytes"], 128)
        self.assertEqual(plaintext[:63], CODE[:-1])
        self.assertEqual(plaintext[63], 0)
        self.assertEqual(plaintext[64:120], DESCRIPTORS[:56])
        self.assertEqual(plaintext[120:128], plaintext[128:136])
        loader = files["releaseguard_native_code.cpp"].decode()
        self.assertIn("open_native_asset_into", loader)
        self.assertIn("secure_buffer_options{true, true}", loader)
        self.assertIn("pending->make_read_only()", loader)
        self.assertNotIn("std::vector", loader)
        self.assertNotIn("std::memcpy", loader)
        for item in details["storage"]:
            self.assertIn("icmp ne ptr", rewritten)
            if item["kind"] != "bytecode":
                self.assertEqual(item["offset_bytes"] % 8, 0)
        self.assertTrue(details["memory_protection"]["direct_authenticated_decryption"])

    def test_storage_constant_expressions_fail_before_emission(self):
        source = self.source.replace("load i8, ptr @code, align 1",
                                     "load i8, ptr getelementptr ([64 x i8], ptr @code, i64 0, i64 1), align 1")
        with self.assertRaisesRegex(GuardError, "constant-expression"):
            self.seal(source=source)

    def test_wrappers_cannot_directly_read_storage_and_helpers_need_global_reads(self):
        source = self.source.replace("%wide = zext i32 %x to i64",
                                     "%wide = load i64, ptr @descriptors, align 8")
        with self.assertRaisesRegex(GuardError, "wrapper has unsupported global dependencies"):
            self.seal(source=source)
        for attribute in ("readnone", "argmemonly", "memory(none)", "memory(argmem: readwrite)",
                          "speculatable memory(read)"):
            source = self.source.replace("ptr %arguments) {", "ptr %arguments) #99 {")
            source += "\nattributes #99 = { " + attribute + " }\n"
            with self.subTest(attribute=attribute), self.assertRaisesRegex(GuardError, "helper memory attributes"):
                self.seal(source=source)

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

    def test_uncovered_globals_fail_closed_for_all_linkage_and_storage_forms(self):
        # These bytes used to survive sealing with internal/unnamed_addr linkage.
        payload = '[16 x i8] c"OWNED-PLAINTEXT!"'
        definitions = [modifier + " " + payload for modifier in (
            "private constant", "private unnamed_addr constant", "private local_unnamed_addr constant",
            "internal constant", "constant", "available_externally constant", "linkonce_odr constant",
            "private global", "internal global", "private thread_local constant",
            "private addrspace(1) constant")]
        definitions += [
            "external global i64", "private constant i64 918273645",
            "private constant { i32, i32 } { i32 9182, i32 7364 }",
            "private alias [64 x i8], ptr @code",
            "ifunc i64 (i64, ptr, ptr), ptr @vm_runtime",
        ]
        for definition in definitions:
            with self.subTest(definition=definition), self.assertRaisesRegex(GuardError, "Unsealed VM storage"):
                self.seal(source=self.source + "\n@uncovered = " + definition + "\n")

    def test_uncovered_function_definitions_fail_closed_for_all_linkages(self):
        # A cloned/outlined original body must not survive beside the encrypted
        # wrappers simply because it was absent from the original coverage list.
        for linkage in ("", "internal ", "private ", "available_externally ", "linkonce_odr ", "weak "):
            _, definition = uncovered_function(linkage)
            with self.subTest(linkage=linkage), self.assertRaisesRegex(GuardError, "Uncovered VM function"):
                self.seal(source=self.source + "\n" + definition)

    def test_removed_original_cannot_leave_an_uncovered_definition(self):
        coverage = copy.deepcopy(self.coverage)
        coverage.append({"name": "original_removed", "requested": False, "removed": True})
        _, definition = uncovered_function("internal ")
        with self.assertRaisesRegex(GuardError, "Uncovered VM function"):
            self.seal(source=self.source + "\n" + definition, coverage=coverage)

    def test_noncanonical_function_definition_cannot_escape_the_inventory(self):
        for name, definition in noncanonical_definitions().items():
            with self.subTest(syntax=name), self.assertRaisesRegex(
                    GuardError, "Unsupported VM function definition"):
                self.seal(source=self.source + "\n" + definition)

    def test_definition_keyword_in_names_labels_strings_and_comments_is_not_counted(self):
        source = with_definition_identifiers(self.source)
        rewritten, _, _ = self.seal(source=source)
        self.assertIn("declare i64 @define(i64)", rewritten)
        self.assertIn("i32 %define", rewritten)
        self.assertIn("!define !99", rewritten)
        self.assertIn("\ndefine:\n", rewritten)

    def test_runtime_dependency_closure_keeps_transitive_private_helpers_and_declarations(self):
        source = with_runtime_helpers(self.source)
        # A declaration has no body to disclose and need not be a VM wrapper.
        source += "\ndeclare i32 @unused_external_declaration(i32)\n"
        rewritten, _, details = self.seal(source=source)
        self.assertIn("define private i64 @runtime_helper", rewritten)
        self.assertIn("define private i64 @runtime_leaf", rewritten)
        self.assertIn("declare i32 @unused_external_declaration(i32)", rewritten)
        self.assertEqual([item["name"] for item in details["guarded_wrappers"]], ["rg_compute"])
        with self.assertRaisesRegex(GuardError, "runtime helpers must remain private"):
            self.seal(source=source.replace("define private i64 @runtime_leaf", "define i64 @runtime_leaf"))

    def test_unrecognized_global_syntax_is_rejected_instead_of_ignored(self):
        for declaration in (
            '@"quoted" = private constant i64 1234',
            '@0 = private constant i64 1234',
            '  @indented = private constant i64 1234',
            '@tabbed\t= private constant i64 1234',
            '@nospace= private constant i64 1234',
        ):
            with self.subTest(declaration=declaration), self.assertRaisesRegex(GuardError, "global definition"):
                self.seal(source=self.source + "\n" + declaration + "\n")

    def test_retention_metadata_accepts_only_verified_symbols_and_exact_layout(self):
        existing = ('@llvm.compiler.used = appending global [3 x ptr] '
                    '[ptr @code, ptr @descriptors, ptr @native_calls], section "llvm.metadata"')
        for name in ("llvm.used", "llvm.compiler.used"):
            retained = ("@" + name + ' = appending global [5 x ptr] '
                        '[ptr @code, ptr @descriptors, ptr @native_calls, ptr @vm_runtime, ptr @rg_compute], '
                        'section "llvm.metadata", align 8')
            rewritten, _, details = self.seal(source=self.source.replace(existing, retained))
            self.assertEqual(details["validated_retention_globals"], [name])
            self.assertIn("@" + name + " = appending global", rewritten)
            self.assertIn("ptr @" + details["storage"][0]["symbol"], rewritten)
            self.assertNotIn("ptr @code,", rewritten)
        for replacement in (
            existing.replace("[3 x ptr]", "[4 x ptr]"),
            existing.replace("ptr @code,", "ptr @missing,"),
            existing.replace("ptr @code,", "ptr null,"),
            existing.replace("ptr @code,", "ptr inttoptr (i64 123456 to ptr),"),
            existing.replace('section "llvm.metadata"', 'section ".rodata"'),
            existing.replace("appending global", "private constant"),
            existing.replace("@llvm.compiler.used", "@llvm.unrecognized"),
            '@llvm.used = private alias [64 x i8], ptr @code',
        ):
            with self.subTest(replacement=replacement), self.assertRaises(GuardError):
                self.seal(source=self.source.replace(existing, replacement))
        with self.assertRaisesRegex(GuardError, "must not read retention metadata"):
            self.seal(source=self.source.replace("%native = load ptr, ptr @native_calls",
                                                 "%native = load ptr, ptr @llvm.compiler.used"))

    def test_object_emitting_and_unknown_named_metadata_fail_closed(self):
        # LLVM 18 emits llvm.commandline strings in .GCC.command.line even if no
        # instruction references them. Debug metadata similarly exposes sources.
        for name in ("llvm.commandline", "llvm.dbg.cu", "llvm.annotations", "unknown"):
            source = self.source + f'\n!{name} = !{{!90}}\n!90 = !{{!"OWNED_PRIVATE_MARKER"}}\n'
            with self.subTest(name=name), self.assertRaisesRegex(GuardError, "named metadata"):
                self.seal(source=source)
        source = (self.source + '\n!llvm.module.flags = !{!90}\n'
                  '!90 = !{i32 1, !"wchar_size", i32 4}\n')
        self.assertIn("!llvm.module.flags", self.seal(source=source)[0])
        with self.assertRaisesRegex(GuardError, "debug metadata"):
            self.seal(source=self.source + '\n!90 = !DIFile(filename: "private.c", directory: "/private")\n')
        # Debug-like strings in a compiler identity are data, not an IR node.
        source = self.source + '\n!llvm.ident = !{!90}\n!90 = !{!"compiler !DIFile(foo)"}\n'
        self.assertNotIn("!llvm.ident", self.seal(source=source)[0])

    def test_object_emitting_attached_metadata_fails_closed(self):
        _, variants = pcsection_fixtures(self.source)
        for location, source in variants.items():
            with self.subTest(location=location), self.assertRaisesRegex(
                    GuardError, "object-emitting attached metadata"):
                self.seal(source=source)
        # Text inside comments/strings is not an attachment.
        source = (self.source + '\n; !pcsections !90\n!llvm.ident = !{!90}\n'
                  '!90 = !{!"compiler !pcsections !91"}\n')
        self.assertNotIn("!llvm.ident", self.seal(source=source)[0])

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
        self.assertNotEqual(first["cpp_namespace"], "releaseguard::code_" + legacy_tag(self.source))
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
            self.assertIsNone(ctypes.c_void_p.in_dll(loaded, item["symbol"]).value)

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

    def test_uncovered_global_and_commandline_bytes_are_rejected_before_codegen(self):
        source, coverage = fixture()
        marker = b"OWNED-PLAINTEXT!"
        cases = {
            "unnamed-global": '@uncovered = private unnamed_addr constant [16 x i8] c"OWNED-PLAINTEXT!"',
            "internal-global": '@uncovered = internal constant [16 x i8] c"OWNED-PLAINTEXT!"',
            "commandline": '!llvm.commandline = !{!90}\n!90 = !{!"OWNED-PLAINTEXT!"}',
        }
        for name, addition in cases.items():
            with self.subTest(name=name):
                ir = source + "\n" + addition + "\n"
                original = self.work / (name + ".ll")
                original.write_text(ir)
                verified = self.work / (name + "-verified.ll")
                artifact = self.work / (name + ".o")
                self.run_tool([self.llvm / "opt", "-S", "-passes=verify", "-verify-each", original,
                               "-o", verified])
                self.run_tool([self.llvm / "llc", "-O=2", "-relocation-model=pic", "-filetype=obj",
                               verified, "-o", artifact])
                self.assertIn(marker, artifact.read_bytes())
                expected_error = "named metadata" if name == "commandline" else "Unsealed VM storage"
                with self.assertRaisesRegex(GuardError, expected_error):
                    seal_virtualized_ir(verified.read_text(), coverage, self.key, **CONTEXT)

    def test_pcsections_emit_plaintext_but_are_rejected_before_sealing(self):
        # LLVM 18's AsmPrinter emits the auxiliary metadata constants directly
        # into rg_owned_aux. Numbered nodes alone must not evade the inventory.
        source, coverage = fixture()
        marker, variants = pcsection_fixtures(source)
        for location, ir in variants.items():
            with self.subTest(location=location):
                original = self.work / ("pcsections-" + location + ".ll")
                original.write_text(ir)
                verified = self.work / ("pcsections-" + location + "-verified.ll")
                artifact = self.work / ("pcsections-" + location + ".o")
                self.run_tool([self.llvm / "opt", "-S", "-passes=verify", "-verify-each", original,
                               "-o", verified])
                self.run_tool([self.llvm / "llc", "-O=2", "-relocation-model=pic", "-filetype=obj",
                               verified, "-o", artifact])
                self.assertIn(marker, artifact.read_bytes())
                with self.assertRaisesRegex(GuardError, "object-emitting attached metadata"):
                    seal_virtualized_ir(verified.read_text(), coverage, self.key, **CONTEXT)

    def test_uncovered_function_has_real_object_bytes_and_sealing_rejects_it(self):
        source, coverage = fixture()
        for linkage in ("", "internal ", "private "):
            name = linkage.strip() or "external"
            marker, definition = uncovered_function(linkage)
            original = self.work / ("uncovered-function-" + name + ".ll")
            original.write_text(source + "\n" + definition)
            verified = self.work / ("uncovered-function-" + name + "-verified.ll")
            artifact = self.work / ("uncovered-function-" + name + ".o")
            with self.subTest(linkage=name):
                self.run_tool([self.llvm / "opt", "-S", "-passes=verify", "-verify-each", original,
                               "-o", verified])
                self.run_tool([self.llvm / "llc", "-O=2", "-relocation-model=pic", "-filetype=obj",
                               verified, "-o", artifact])
                self.assertIn(marker, artifact.read_bytes())
                with self.assertRaisesRegex(GuardError, "Uncovered VM function"):
                    seal_virtualized_ir(verified.read_text(), coverage, self.key, **CONTEXT)

    def test_real_llvm_accepts_noncanonical_headers_that_the_direct_sealer_rejects(self):
        source, coverage = fixture()
        for name, definition in noncanonical_definitions().items():
            original = self.work / ("noncanonical-function-" + name + ".ll")
            verified = self.work / ("noncanonical-function-" + name + "-verified.ll")
            text = source + "\n" + definition
            original.write_text(text)
            with self.subTest(syntax=name):
                self.run_tool([self.llvm / "opt", "-S", "-passes=verify", "-verify-each", original,
                               "-o", verified])
                # The supported CLI canonicalizes first. This specifically
                # checks the direct API cannot pass an unparsed definition on.
                with self.assertRaisesRegex(GuardError, "Unsupported VM function definition"):
                    seal_virtualized_ir(text, coverage, self.key, **CONTEXT)
                with self.assertRaisesRegex(GuardError, "Uncovered VM function"):
                    seal_virtualized_ir(verified.read_text(), coverage, self.key, **CONTEXT)

    def test_real_llvm_definition_identifiers_remain_compatible(self):
        source, coverage = fixture()
        original = self.work / "definition-identifiers.ll"
        verified = self.work / "definition-identifiers-verified.ll"
        original.write_text(with_definition_identifiers(source))
        self.run_tool([self.llvm / "opt", "-S", "-passes=verify", "-verify-each", original,
                       "-o", verified])
        bundle = seal_virtualized_ir(verified.read_text(), coverage, self.key, **CONTEXT)
        loaded, _ = self.build("definition-identifiers", bundle)
        self.addCleanup(loaded.rg_clear)
        self.assertEqual(loaded.rg_compute(123), 0)
        self.assertTrue(loaded.rg_initialize(self.key))
        self.assertEqual(loaded.rg_compute(123), ((123 ^ WORDS[0]) + CODE[0]) & 0xffffffff)
        loaded.rg_clear()
        self.assertEqual(loaded.rg_compute(123), 0)

    def test_private_runtime_helper_chain_preserves_authorized_results_and_clear(self):
        source, coverage = fixture()
        bundle = seal_virtualized_ir(with_runtime_helpers(source), coverage, self.key, **CONTEXT)
        loaded, _ = self.build("runtime-helper-chain", bundle)
        self.addCleanup(loaded.rg_clear)
        self.assertEqual(loaded.rg_compute(123), 0)
        self.assertTrue(loaded.rg_initialize(self.key))
        for value in (0, 1, 123, 0x80000000, 0xffffffff):
            self.assertEqual(loaded.rg_compute(value), ((value ^ WORDS[0]) + CODE[0]) & 0xffffffff)
        loaded.rg_clear()
        self.assertEqual(loaded.rg_compute(123), 0)
        self.assert_cleared(loaded, bundle[2])

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

    def test_storage_has_aligned_read_only_locked_dump_excluded_mapping(self):
        loaded = self.normal
        self.addCleanup(loaded.rg_clear)
        self.assertTrue(loaded.rg_initialize(self.key))
        payload = open_asset(document_from_files(self.bundle[1]), self.key, **ASSET_CONTEXT)
        base = ctypes.c_void_p.in_dll(loaded, self.bundle[2]["storage"][0]["symbol"]).value
        self.assertEqual(base % os.sysconf("SC_PAGESIZE"), 0)
        for item in self.bundle[2]["storage"]:
            address = ctypes.c_void_p.in_dll(loaded, item["symbol"]).value
            self.assertEqual(address, base + item["offset_bytes"])
            self.assertEqual(ctypes.string_at(address, item["bytes"]),
                             payload[item["offset_bytes"]:item["offset_bytes"] + item["bytes"]])
            if item["kind"] != "bytecode":
                self.assertEqual(address % 8, 0)
        try:
            mappings = Path("/proc/self/smaps").read_text()
        except OSError as error:
            if os.environ.get("RELEASEGUARD_REQUIRE_NATIVE_VIRTUALIZATION") == "1":
                raise AssertionError("Required native memory observations unavailable") from error
            self.skipTest(str(error))
        ranges = list(re.finditer(r"^([0-9a-f]+)-([0-9a-f]+) ([rwxps-]+) .*$", mappings, re.MULTILINE))
        region = next(index for index, row in enumerate(ranges) if int(row[1], 16) <= base < int(row[2], 16))
        self.assertEqual(ranges[region][3], "r--p")
        end = ranges[region + 1].start() if region + 1 < len(ranges) else len(mappings)
        flags = re.search(r"^VmFlags:\s*(.*)$", mappings[ranges[region].start():end], re.MULTILINE)[1].split()
        self.assertIn("lo", flags)
        self.assertIn("dd", flags)

    def test_missing_storage_binding_locks_wrapper_and_clear_unmaps_payload(self):
        loaded = self.normal
        self.addCleanup(loaded.rg_clear)
        self.assertTrue(loaded.rg_initialize(self.key))
        for item in self.bundle[2]["storage"]:
            binding = ctypes.c_void_p.in_dll(loaded, item["symbol"])
            original = binding.value
            binding.value = None
            try:
                self.assertEqual(loaded.rg_compute(123), 0)
            finally:
                binding.value = original
        base = ctypes.c_void_p.in_dll(loaded, self.bundle[2]["storage"][0]["symbol"]).value
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte)]
        libc.mincore.restype = ctypes.c_int
        residency = ctypes.c_ubyte()
        page = os.sysconf("SC_PAGESIZE")
        loaded.rg_clear()
        self.assert_cleared(loaded, self.bundle[2])
        ctypes.set_errno(0)
        self.assertEqual(libc.mincore(base, page, ctypes.byref(residency)), -1)
        self.assertEqual(ctypes.get_errno(), errno.ENOMEM)
        loaded.rg_clear()

    def test_authenticated_vm_storage_rejects_process_writes(self):
        namespace = self.bundle[2]["cpp_namespace"]
        symbol = self.bundle[2]["storage"][0]["symbol"]
        source = self.folder / "write-protection.cpp"
        source.write_text('''#include "releaseguard_native_code.hpp"
#include <cstdio>
#include <sys/resource.h>
extern "C" unsigned char* ''' + symbol + ''';
int main(int argc, char**) {
    rlimit limit{0, 0};
    if (setrlimit(RLIMIT_CORE, &limit) != 0) return 2;
    releaseguard::native_asset_key key{};
    if (std::fread(key.data(), 1, key.size(), stdin) != key.size()) return 3;
    const bool opened = ''' + namespace + '''::initialize_native_code(key);
    OPENSSL_cleanse(key.data(), key.size());
    if (!opened) return 4;
    if (argc > 1) {
        volatile unsigned char* output = ''' + symbol + ''';
        *output = 0;
        return 5;
    }
    ''' + namespace + '''::clear_native_code();
    return 0;
}
''')
        app = self.folder / "write-protection"
        self.run_tool([self.cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
                       self.folder / "protected.o", self.folder / "releaseguard_native_code.cpp",
                       source, "-lcrypto", "-o", app])
        for arguments, expected in (([], 0), (["write"], -signal.SIGSEGV)):
            result = subprocess.run([str(app), *arguments], input=self.key, capture_output=True, timeout=30)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (expected, b"", b""))

    def test_fork_wipes_child_vm_storage_and_preserves_parent(self):
        loaded = self.normal
        self.addCleanup(loaded.rg_clear)
        self.assertTrue(loaded.rg_initialize(self.key))
        expected = ((123 ^ WORDS[0]) + CODE[0]) & 0xffffffff
        child = os.fork()
        if child == 0:
            signal.alarm(10)
            try:
                if loaded.rg_compute(123) != 0:
                    os._exit(11)
                for item in self.bundle[2]["storage"]:
                    address = ctypes.c_void_p.in_dll(loaded, item["symbol"]).value
                    if ctypes.string_at(address, item["bytes"]) != bytes(item["bytes"]):
                        os._exit(12)
                if not loaded.rg_initialize(self.key) or loaded.rg_compute(123) != expected:
                    os._exit(13)
                loaded.rg_clear()
                os._exit(0)
            except BaseException:
                os._exit(14)
        _, status = os.waitpid(child, 0)
        self.assertTrue(os.WIFEXITED(status), status)
        self.assertEqual(os.WEXITSTATUS(status), 0)
        self.assertEqual(loaded.rg_compute(123), expected)

    def test_global_user_initialization_and_destruction_preserve_owner_order(self):
        namespace = self.bundle[2]["cpp_namespace"]
        source = self.folder / "global-user.cpp"
        source.write_text('''#include "releaseguard_native_code.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
extern "C" std::uint32_t rg_compute(std::uint32_t);
struct user_lifetime {
    user_lifetime() {
        releaseguard::native_asset_key key{};
        if (std::fread(key.data(), 1, key.size(), stdin) != key.size()) std::exit(2);
        const bool opened = ''' + namespace + '''::initialize_native_code(key);
        OPENSSL_cleanse(key.data(), key.size());
        if (!opened) std::exit(3);
    }
    ~user_lifetime() {
        std::printf("%u\\n", rg_compute(123));
        ''' + namespace + '''::clear_native_code();
    }
};
user_lifetime user;
int main() { std::printf("%u\\n", rg_compute(123)); }
''')
        expected = f"{((123 ^ WORDS[0]) + CODE[0]) & 0xffffffff}\n".encode() * 2
        loader = self.folder / "releaseguard_native_code.cpp"
        for order, inputs in (("user-first", [source, loader]), ("loader-first", [loader, source])):
            app = self.folder / order
            self.run_tool([self.cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
                           *inputs, self.folder / "protected.o", "-lcrypto", "-o", app])
            result = subprocess.run([str(app)], input=self.key, capture_output=True, timeout=30)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b""))

    def test_loader_os_failures_revoke_bindings_and_release_every_mapping(self):
        namespace = self.bundle[2]["cpp_namespace"]
        declarations, null_checks = [], []
        for item in self.bundle[2]["storage"]:
            ctype = "unsigned char" if item["kind"] == "bytecode" else "std::uint64_t"
            declarations.append(f'extern "C" {ctype}* {item["symbol"]};')
            null_checks.append(f'    if ({item["symbol"]} != nullptr) return 20;')
        source = self.folder / "memory-failures.cpp"
        source.write_text('''#include "releaseguard_native_code.hpp"
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <sys/mman.h>
#include <unistd.h>
''' + "\n".join(declarations) + '''
extern "C" unsigned char ''' + self.bundle[2]["ready_symbol"] + ''';
extern "C" void* __real_mmap(void*, std::size_t, int, int, int, off_t);
extern "C" int __real_mprotect(void*, std::size_t, int);
extern "C" int __real_mlock(const void*, std::size_t);
extern "C" int __real_madvise(void*, std::size_t, int);
extern "C" int __real_munmap(void*, std::size_t);
static int mode = 0;
static void* reservation = nullptr;
static unsigned char* payload = nullptr;
static std::size_t payload_bytes = 0;
static bool writable = false, read_only = false;
static unsigned active = 0, released = 0, unwiped = 0, violations = 0;
extern "C" void* __wrap_mmap(void* address, std::size_t size, int protection,
                              int flags, int fd, off_t offset) {
    if (mode == 1) { errno = ENOMEM; return MAP_FAILED; }
    void* result = __real_mmap(address, size, protection, flags, fd, offset);
    if (result != MAP_FAILED) {
        if (active != 0) ++violations;
        ++active;
        reservation = result;
        const auto page = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
        payload = static_cast<unsigned char*>(result) + page;
        payload_bytes = size - 2 * page;
        writable = read_only = false;
    }
    return result;
}
extern "C" int __wrap_mprotect(void* address, std::size_t size, int protection) {
    if ((mode == 2 && protection == (PROT_READ | PROT_WRITE)) ||
        (mode == 6 && protection == PROT_READ) ||
        (mode == 7 && read_only && protection == (PROT_READ | PROT_WRITE))) {
        errno = EACCES;
        return -1;
    }
    const int result = __real_mprotect(address, size, protection);
    if (result == 0 && address == payload) {
        writable = (protection & PROT_WRITE) != 0;
        read_only = protection == PROT_READ;
    }
    return result;
}
extern "C" int __wrap_mlock(const void* address, std::size_t size) {
    if (mode == 3) { errno = EAGAIN; return -1; }
    return __real_mlock(address, size);
}
extern "C" int __wrap_madvise(void* address, std::size_t size, int advice) {
    if ((mode == 4 && advice == MADV_DONTDUMP) || (mode == 5 && advice == MADV_WIPEONFORK)) {
        errno = EINVAL;
        return -1;
    }
    return __real_madvise(address, size, advice);
}
extern "C" int __wrap_munmap(void* address, std::size_t size) {
    if (address != reservation || active != 1) ++violations;
    if (writable) {
        for (std::size_t index = 0; index < payload_bytes; ++index) {
            if (payload[index] != 0) { ++violations; break; }
        }
    } else if (read_only) {
        ++unwiped;
    }
    const int result = __real_munmap(address, size);
    if (result == 0) { --active; ++released; reservation = nullptr; }
    return result;
}
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const int requested = std::atoi(argv[1]);
    mode = requested == 8 ? 0 : requested;
    releaseguard::native_asset_key key{};
    if (std::fread(key.data(), 1, key.size(), stdin) != key.size()) return 3;
    if (mode == 9) key[0] ^= 1;
    bool opened = ''' + namespace + '''::initialize_native_code(key);
    if (requested == 8) {
        if (!opened) return 4;
        mode = 3;
        opened = ''' + namespace + '''::initialize_native_code(key);
    }
    OPENSSL_cleanse(key.data(), key.size());
    if (opened != (requested == 0 || requested == 7)) return 5;
    ''' + namespace + '''::clear_native_code();
    if (''' + self.bundle[2]["ready_symbol"] + ''' != 0) return 6;
''' + "\n".join(null_checks) + '''
    if (active || violations) return 7;
    std::printf("%u %u\\n", released, unwiped);
    return 0;
}
''')
        app = self.folder / "memory-failures"
        wraps = ["-Wl,--wrap=" + name for name in ("mmap", "mprotect", "mlock", "madvise", "munmap")]
        self.run_tool([self.cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
                       self.folder / "protected.o", self.folder / "releaseguard_native_code.cpp",
                       source, *wraps, "-lcrypto", "-o", app])
        for mode in range(10):
            with self.subTest(failure=mode):
                result = subprocess.run([str(app), str(mode)], input=self.key,
                                        capture_output=True, timeout=30)
                released = 0 if mode == 1 else 2 if mode == 8 else 1
                expected = f"{released} {int(mode == 7)}\n".encode()
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b""))

    def test_legacy_array_storage_cannot_link_to_the_pointer_loader(self):
        details = self.bundle[2]
        current_prefix = details["ready_symbol"].removesuffix("_ready")
        old_prefix = "rg_native_code_" + legacy_tag(fixture()[0])
        declarations = [f"unsigned char {old_prefix}_ready = 0;"]
        for item in details["storage"]:
            ctype = "unsigned char" if item["kind"] == "bytecode" else "std::uint64_t"
            old_symbol = item["symbol"].replace(current_prefix, old_prefix, 1)
            declarations.append(f"{ctype} {old_symbol}[{item['elements']}] = {{}};")
        source = self.folder / "legacy-storage.cpp"
        source.write_text('#include <cstdint>\nextern "C" {\n' + "\n".join(declarations)
                          + '\n}\nint main() { return 0; }\n')
        result = subprocess.run([self.cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
                                 str(source), str(self.folder / "releaseguard_native_code.cpp"),
                                 "-lcrypto", "-o", str(self.folder / "mixed-format")],
                                capture_output=True, timeout=120)
        self.assertNotEqual(result.returncode, 0, "Mixed storage ABIs linked successfully")
        self.assertIn(details["ready_symbol"].encode(), result.stderr)

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
