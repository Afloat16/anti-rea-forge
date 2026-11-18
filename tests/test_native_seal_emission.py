"""Owned LLVM controls for bytes outside the sealed global inventory."""

from __future__ import annotations

import copy
import ctypes
import hashlib
import os
from pathlib import Path
import re
import secrets
import shutil
import struct
import subprocess
import tempfile
import unittest

from releaseguard.core import GuardError
from releaseguard.native_code_seal import seal_virtualized_ir
from tests.test_native_code_seal import CODE, CONTEXT, DESCRIPTORS, WORDS, fixture, with_runtime_helpers


MARKER = b"RG-OWNED-EMISSION-MARKER"


def llvm_string(data):
    return '"' + "".join(f"\\{value:02X}" for value in data) + '"'


def attach_header(source, function, attachment):
    header = next(line for line in source.splitlines()
                  if line.startswith("define ") and "@" + function + "(" in line)
    assert header.endswith(" {")
    return source.replace(header, header[:-2] + " " + attachment + " {", 1)


def emitted_byte_fixtures(source):
    """Use valid x86-64 prologues and assembly that writes a separate section."""
    variants = {}
    for location, function in (("wrapper", "rg_compute"), ("runtime", "vm_runtime"),
                               ("helper", "runtime_leaf")):
        base = with_runtime_helpers(source) if location == "helper" else source
        for kind in ("prefix", "prologue"):
            # A short jump skips the marker, preserving the prologue's call
            # semantics; an arbitrary string at the entrypoint would not.
            data = bytes((0xEB, len(MARKER))) + MARKER if kind == "prologue" else MARKER
            attachment = f"{kind} [{len(data)} x i8] c" + llvm_string(data)
            variants[kind + "-" + location] = attach_header(base, function, attachment)

    assembly = (b'.pushsection .rg_owned_emission,"a",@progbits\n.byte '
                + ",".join(str(value) for value in MARKER).encode() + b"\n.popsection")
    instruction = "  call void asm sideeffect " + llvm_string(assembly) + ', ""()\n'
    variants["inline-runtime"] = source.replace("descriptor.ready:\n",
                                                "descriptor.ready:\n" + instruction, 1)
    helper = with_runtime_helpers(source)
    entry = "define private i64 @runtime_leaf(i64 %value) {\nentry:\n"
    variants["inline-helper"] = helper.replace(entry, entry + instruction, 1)
    for name, prefix in (("module", "module asm "), ("module-split", "module\nasm "),
                         ("module-same-line", "declare void @unused() module asm ")):
        variants[name] = source + "\n" + prefix + llvm_string(assembly) + "\n"
    return variants


def keyword_identifier_fixture(source):
    source = with_runtime_helpers(source)
    source = source.replace("@runtime_helper", "@asm").replace("@runtime_leaf", "@prologue")
    source = source.replace("%x", "%prefix").replace("entry:", "asm:", 1)
    source = attach_header(source, "rg_compute", '"rg.note"="prefix prologue asm" !asm !91')
    return ('source_filename = "prefix prologue asm"\n' + source
            + '\ndeclare void @prefix()\n!91 = !{!"prefix prologue asm"}\n'
              '; prefix prologue asm are harmless in comments too\n')


class NativeSealEmissionValidation(unittest.TestCase):
    def test_all_attached_data_and_assembly_paths_are_rejected(self):
        source, coverage = fixture()
        for name, text in emitted_byte_fixtures(source).items():
            with self.subTest(path=name):
                expected = "prefix or prologue" if name.startswith(("prefix", "prologue")) else "assembly"
                with self.assertRaisesRegex(GuardError, expected):
                    seal_virtualized_ir(text, coverage, bytes(range(32)), **CONTEXT)

    def test_identifiers_labels_comments_and_quoted_values_are_accepted(self):
        source, coverage = fixture()
        rewritten, _, details = seal_virtualized_ir(
            keyword_identifier_fixture(source), coverage, bytes(range(32)), **CONTEXT)
        self.assertIn("@asm(", rewritten)
        self.assertIn("@prologue(", rewritten)
        self.assertIn("%prefix", rewritten)
        self.assertIn("asm:", rewritten)
        self.assertEqual([row["name"] for row in details["guarded_wrappers"]], ["rg_compute"])


class NativeSealEmissionCompiled(unittest.TestCase):
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
        temporary = tempfile.TemporaryDirectory(prefix="native-seal-emission-")
        cls.addClassCleanup(temporary.cleanup)
        cls.work = Path(temporary.name)

    def run_tool(self, *arguments):
        result = subprocess.run(list(map(str, arguments)), capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stderr, b"", result.stderr.decode(errors="replace"))

    def compile_ir(self, name, source):
        original = self.work / (name + ".ll")
        verified = self.work / (name + "-verified.ll")
        artifact = self.work / (name + ".o")
        original.write_text(source, encoding="utf-8")
        self.run_tool(self.llvm / "opt", "-S", "-passes=verify", "-verify-each",
                      original, "-o", verified)
        self.run_tool(self.llvm / "llc", "-O=2", "-relocation-model=pic", "-filetype=obj",
                      verified, "-o", artifact)
        return verified.read_text(encoding="utf-8"), artifact

    def test_real_object_emission_is_rejected_for_each_path(self):
        source, coverage = fixture()
        for name, text in emitted_byte_fixtures(source).items():
            with self.subTest(path=name):
                canonical, artifact = self.compile_ir(name, text)
                self.assertIn(MARKER, artifact.read_bytes())
                expected = "prefix or prologue" if name.startswith(("prefix", "prologue")) else "assembly"
                # Raw spellings exercise the direct API; canonical text is
                # the representation consumed after the normal CLI's opt.
                for spelling in (text, canonical):
                    with self.assertRaisesRegex(GuardError, expected):
                        seal_virtualized_ir(spelling, coverage, bytes(range(32)), **CONTEXT)

    def test_real_keyword_identifiers_compile_and_preserve_guarded_execution(self):
        source, coverage = fixture()
        canonical, _ = self.compile_ir("keyword-identifiers", keyword_identifier_fixture(source))
        definition = re.search(r"^@descriptors = (.+)$", canonical, re.MULTILINE)[1]
        values = [int(value) & ((1 << 64) - 1) for value in re.findall(r"\bi64 (-?[0-9]+)", definition)]
        self.assertEqual(struct.pack("<8Q", *values), DESCRIPTORS)
        coverage = copy.deepcopy(coverage)
        # Coverage in production is observed after canonicalization; LLVM
        # prints the same descriptor bits as signed decimal i64 constants.
        coverage[0]["vm_coverage"]["descriptor_globals"][0]["ir_sha256"] = hashlib.sha256(
            definition.encode()).hexdigest()
        key = secrets.token_bytes(32)
        rewritten, files, details = seal_virtualized_ir(canonical, coverage, key, **CONTEXT)
        _, artifact = self.compile_ir("keyword-identifiers-sealed", rewritten)
        for name, data in files.items():
            (self.work / name).write_bytes(data)
        namespace = details["cpp_namespace"]
        shim = self.work / "shim.cpp"
        shim.write_text('''#include "releaseguard_native_code.hpp"
extern "C" bool rg_initialize(const unsigned char* input) {
    releaseguard::native_asset_key key{};
    std::memcpy(key.data(), input, key.size());
    const bool result = ''' + namespace + '''::initialize_native_code(key);
    OPENSSL_cleanse(key.data(), key.size());
    return result;
}
extern "C" void rg_clear() { ''' + namespace + '''::clear_native_code(); }
''', encoding="utf-8")
        library = self.work / "keyword-identifiers.so"
        self.run_tool(self.cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                      artifact, self.work / "releaseguard_native_code.cpp", shim, "-lcrypto", "-o", library)
        loaded = ctypes.CDLL(str(library))
        loaded.rg_initialize.argtypes = [ctypes.c_char_p]
        loaded.rg_initialize.restype = ctypes.c_bool
        loaded.rg_clear.argtypes = []
        loaded.rg_clear.restype = None
        loaded.rg_compute.argtypes = [ctypes.c_uint32]
        loaded.rg_compute.restype = ctypes.c_uint32
        self.addCleanup(loaded.rg_clear)
        self.assertEqual(loaded.rg_compute(41), 0)
        self.assertTrue(loaded.rg_initialize(key))
        self.assertEqual(loaded.rg_compute(41), ((41 ^ WORDS[0]) + CODE[0]) & 0xffffffff)
        loaded.rg_clear()
        self.assertEqual(loaded.rg_compute(41), 0)


if __name__ == "__main__":
    unittest.main()
