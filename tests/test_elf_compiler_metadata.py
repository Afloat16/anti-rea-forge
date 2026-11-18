"""Real Clang producer + llvm-dis recovery, with matched ELF runtime controls."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from releaseguard.core import GuardError
from releaseguard.distribution import scan_release
from releaseguard.elf import audit_elf
from releaseguard import split_elf
from tests.test_asar import asar, zip_archive


SOURCE = Path(__file__).resolve().parents[1] / "benchmarks/embedded_llvm/owned_strategy.c"
PRIVATE_NAMES = ("owned_private_margin_calculation", "owned_private_quantity",
                 "owned_private_scaled", "owned_private_total")


class RealElfCompilerMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        required = os.environ.get("RELEASEGUARD_REQUIRE_LLVM_METADATA") == "1"
        llvm = os.environ.get("RELEASEGUARD_LLVM_BIN")
        cls.clang = str(Path(llvm) / "clang") if llvm else shutil.which("clang")
        cls.dis = str(Path(llvm) / "llvm-dis") if llvm else shutil.which("llvm-dis")
        reason = None
        if (not sys.platform.startswith("linux") or not cls.clang or not cls.dis
                or not all(shutil.which(name) for name in ("gcc", "objcopy", "nm", "readelf"))):
            reason = "Real embedded IR controls need Linux Clang, llvm-dis, GCC and GNU binutils"
        if not reason:
            for tool, signature in ((cls.clang, b"clang"), (cls.dis, b"LLVM"), ("objcopy", b"GNU objcopy")):
                try:
                    result = subprocess.run([tool, "--version"], capture_output=True, timeout=30)
                    if result.returncode or signature not in result.stdout:
                        reason = "Real embedded IR control tool unavailable: " + tool
                        break
                except OSError:
                    reason = "Real embedded IR control tool unavailable: " + tool
                    break
        if reason:
            if required:
                raise AssertionError(reason)
            raise unittest.SkipTest(reason)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned compiler metadata ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.source = self.work / SOURCE.name
        self.source.write_bytes(SOURCE.read_bytes())
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="utf-8")

    def run_tool(self, *args):
        result = subprocess.run([str(arg) for arg in args], cwd=self.work,
                                env={**os.environ, "TMPDIR": str(self.work)},
                                capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0,
                         f"Command: {args!r}\n{result.stdout!r}\n{result.stderr!r}")
        return result.stdout

    def build(self, label="owned", embed=True):
        obj, binary = self.work / (label + ".o"), self.work / label
        flags = ["-O0", "-g0", "-fno-discard-value-names"]
        if embed:
            flags.append("-fembed-bitcode=all")
        self.run_tool(self.clang, *flags, "-c", self.source, "-o", obj)
        self.run_tool("gcc", obj, "-o", binary)
        self.assert_runtime(binary)
        return binary

    def assert_runtime(self, binary):
        codes = [subprocess.run([str(binary), *["owned"] * n], cwd=self.work,
                                capture_output=True, timeout=10).returncode for n in range(3)]
        self.assertEqual(codes, [48, 85, 122])

    def section(self, binary, name, label):
        output = self.work / (label + ".section")
        self.run_tool("objcopy", "--dump-section", name + "=" + str(output),
                      binary, self.work / (label + ".inspection"))
        return output

    def assert_ir(self, bitcode, label):
        text = self.work / (label + ".ll")
        self.run_tool(self.dis, bitcode, "-o", text)
        ir = text.read_text(encoding="utf-8")
        for name in PRIVATE_NAMES:
            self.assertIn(name, ir)
        self.assertIn(str(self.source), ir)
        self.assertIn("mul nsw i32", ir)
        self.assertIn(", 37", ir)
        self.assertIn("add nsw i32", ir)
        self.assertIn(", 11", ir)

    def test_real_clang_ir_survives_strip_and_recovers_without_debug_symbols(self):
        binary = self.build()
        public = self.work / "stripped"
        public.mkdir()
        stripped = public / "renamed.data"
        self.run_tool("objcopy", "--strip-all", binary, stripped)
        report = audit_elf(stripped)
        self.assertFalse(any(report["evidence"].values()))
        self.assertEqual(set(report["compiler_metadata_sections"]), {".llvmbc", ".llvmcmd"})
        before = stripped.read_bytes()
        self.assert_ir(self.section(stripped, ".llvmbc", "stripped-bitcode"), "stripped-ir")
        gate = scan_release(public, self.policy)
        self.assertFalse(gate["ok"])
        self.assertEqual({finding["code"] for finding in gate["findings"]}, {"native_compiler_metadata"})
        self.assertTrue(gate["checks"]["native_metadata_scan_completed"])
        self.assertEqual(stripped.read_bytes(), before)
        self.assert_runtime(stripped)

    def test_real_clang_raw_and_wrapped_bitcode_are_unverifiable_even_when_renamed_or_nested(self):
        # The Darwin target produces a real bitcode wrapper, without linking
        # or running any Mach-O. Only the native ELF tests claim execution.
        cases = (("raw", [], b"BC\xc0\xde"),
                 ("wrapper", ["--target=x86_64-apple-macosx10.13"], b"\xde\xc0\x17\x0b"))
        root = self.work / "raw-release"
        root.mkdir()
        target = root / "renamed.data"
        for label, flags, magic in cases:
            bitcode = self.work / (label + ".bc")
            self.run_tool(self.clang, *flags, "-O0", "-g0", "-fno-discard-value-names",
                          "-emit-llvm", "-c", self.source, "-o", bitcode)
            payload = bitcode.read_bytes()
            self.assertTrue(payload.startswith(magic))
            self.assert_ir(bitcode, label + "-raw-ir")
            variants = ((payload, []), (zip_archive("module.data", payload), ["module.data"]),
                        (asar([("module.data", payload)]), ["module.data"]),
                        (zip_archive("nested.data", asar([("module.data", payload)])),
                         ["nested.data", "module.data"]))
            for wrapped, members in variants:
                with self.subTest(format=label, members=members):
                    target.write_bytes(wrapped)
                    report = scan_release(root, self.policy)
                    self.assertFalse(report["ok"])
                    self.assertFalse(report["checks"]["native_metadata_scan_completed"])
                    self.assertEqual(len(report["findings"]), 1)
                    finding = report["findings"][0]
                    self.assertEqual(finding["code"], "native_metadata_unverifiable")
                    self.assertEqual(finding["reason"], "unsupported_standalone_metadata")
                    self.assertEqual(finding.get("archive_members", []), members)
                    self.assertEqual(target.read_bytes(), wrapped)

    def test_split_preserves_exact_ir_and_commands_privately_and_keeps_load_image(self):
        binary = self.build()
        original = binary.read_bytes()
        payloads = {name: self.section(binary, name, "original" + name).read_bytes()
                    for name in (".llvmbc", ".llvmcmd")}
        self.assertTrue(all(payloads.values()))
        public, private = self.work / "public", self.work / "private"
        result = split_elf.split_elf_debug(binary, public, private)
        self.assertTrue(result["ok"])
        released, sidecar = Path(result["public_elf"]), Path(result["private_debug"])
        self.assertFalse(audit_elf(released)["compiler_metadata_present"])
        self.assertTrue(scan_release(public, self.policy)["ok"])
        for name, payload in payloads.items():
            self.assertEqual(self.section(sidecar, name, "private" + name).read_bytes(), payload)
        self.assert_ir(self.section(sidecar, ".llvmbc", "private-bitcode"), "private-ir")
        self.assertEqual(binary.read_bytes(), original)
        split_elf._check_load_image(original, released.read_bytes())
        self.assertEqual(self.section(binary, ".text", "original-text").read_bytes(),
                         self.section(released, ".text", "public-text").read_bytes())
        self.assertEqual(self.run_tool("nm", "-D", binary), self.run_tool("nm", "-D", released))
        self.assert_runtime(released)
        for name in payloads:
            restored = self.work / ("restored-" + name[1:])
            restored.mkdir()
            metadata = self.section(sidecar, name, "restore" + name)
            restored_binary = restored / "app"
            self.run_tool("objcopy", "--add-section", name + "=" + str(metadata), released, restored_binary)
            self.assert_runtime(restored_binary)
            self.assertFalse(scan_release(restored, self.policy)["ok"])
            if name == ".llvmbc":
                self.assert_ir(self.section(restored_binary, name, "restored-bitcode"), "restored-ir")

    def test_build_without_embedded_ir_remains_a_working_allowed_control(self):
        binary = self.build(embed=False)
        result = split_elf.split_elf_debug(binary, self.work / "public", self.work / "private")
        released = Path(result["public_elf"])
        self.assertFalse(audit_elf(binary)["compiler_metadata_present"])
        self.assertFalse(audit_elf(released)["compiler_metadata_present"])
        self.assertTrue(scan_release(released.parent, self.policy)["ok"])
        self.assert_runtime(released)

    def test_split_rejects_allocated_compiler_metadata_without_outputs(self):
        binary = self.build()
        allocated = self.work / "allocated"
        self.run_tool("objcopy", "--set-section-flags", ".llvmbc=alloc,readonly", binary, allocated)
        original = allocated.read_bytes()
        public, private = self.work / "public", self.work / "private"
        with self.assertRaisesRegex(GuardError, "compiler metadata"):
            split_elf.split_elf_debug(allocated, public, private)
        self.assertFalse(public.exists())
        self.assertFalse(private.exists())
        self.assertEqual(allocated.read_bytes(), original)

    def test_split_rejects_missing_or_changed_private_compiler_bytes(self):
        binary = self.build()
        real_objcopy = split_elf._objcopy
        for name in (".llvmbc", ".llvmcmd"):
            for changed in (False, True):
                public = self.work / ("public-" + name + str(changed))
                private = self.work / ("private-" + name + str(changed))

                def lose_private_data(tool, *args):
                    result = real_objcopy(tool, *args)
                    if "--only-keep-debug" in args:
                        sidecar = Path(args[-1])
                        damaged = self.work / "damaged.debug"
                        if changed:
                            payload = self.section(sidecar, name, "damage").read_bytes()
                            replacement = self.work / "changed.section"
                            replacement.write_bytes(bytes((payload[0] ^ 1,)) + payload[1:])
                            self.run_tool("objcopy", "--update-section", name + "=" + str(replacement), sidecar, damaged)
                        else:
                            self.run_tool("objcopy", "--remove-section=" + name, sidecar, damaged)
                        damaged.replace(sidecar)
                    return result

                with self.subTest(name=name, changed=changed), patch.object(split_elf, "_objcopy", side_effect=lose_private_data):
                    with self.assertRaisesRegex(GuardError, "private ELF compiler metadata"):
                        split_elf.split_elf_debug(binary, public, private)
                self.assertFalse(public.exists())
                self.assertFalse(private.exists())


if __name__ == "__main__":
    unittest.main()
