"""CTF/BTF type information is private metadata even after static symbols vanish."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from releaseguard.core import GuardError
from releaseguard.distribution import scan_release
from releaseguard.elf import audit_elf, audit_elf_stream
from releaseguard import split_elf
from tests.test_asar import asar, zip_archive
from tests.test_elf import make_elf


TYPE_SECTIONS = (".ctf", ".SUNW_ctf", ".BTF", ".BTF.ext", ".BTF.base", ".gdb_index")
PRIVATE_TYPE = "owned_internal_pricing_record"
PRIVATE_FIELD = "owned_sensitive_rate"
SOURCE = f"""struct {PRIVATE_TYPE} {{ int {PRIVATE_FIELD}; int private_amount; }};
static struct {PRIVATE_TYPE} internal_table = {{37, 19}};
__attribute__((noinline)) int owned_public_entry(int x) {{
    return x * internal_table.{PRIVATE_FIELD} + internal_table.private_amount;
}}
int main(void) {{ return owned_public_entry(3) == 130 ? 0 : 1; }}
"""


class ElfTypeMetadataTests(unittest.TestCase):
    def test_type_and_index_sections_are_debug_metadata_in_all_elf_layouts(self):
        for bits in (32, 64):
            for endian in ("little", "big"):
                for name in TYPE_SECTIONS:
                    with self.subTest(bits=bits, endian=endian, section=name):
                        data = make_elf(bits=bits, endian=endian, entries=[(name, 1)])
                        report = audit_elf_stream(io.BytesIO(data), len(data))
                        self.assertEqual(report["evidence"], {
                            "debug_sections_present": True, "symbol_table_present": False})

    def test_precise_names_do_not_block_runtime_or_lookalike_sections(self):
        for name in (".ctf_public", ".BTF_ids", ".BTF.extended", ".gnu_debuglink", ".dynstr"):
            with self.subTest(section=name):
                data = make_elf(entries=[(name, 1)])
                self.assertFalse(audit_elf_stream(io.BytesIO(data), len(data))["evidence"]["debug_sections_present"])
        for name in TYPE_SECTIONS:
            data = make_elf(entries=[(name, 0)])
            self.assertFalse(audit_elf_stream(io.BytesIO(data), len(data))["evidence"]["debug_sections_present"])

    def test_release_gate_checks_type_metadata_inside_renamed_zip_and_asar_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "release"
            root.mkdir()
            policy = base / "policy.json"
            policy.write_text('{"version":1}', encoding="utf-8")
            target = root / "renamed.data"
            for name in TYPE_SECTIONS:
                data = bytes(make_elf(entries=[(name, 1)]))
                for wrapper in (lambda value: zip_archive("module.data", value),
                                lambda value: asar([("module.data", value)])):
                    with self.subTest(section=name, wrapper=wrapper):
                        target.write_bytes(wrapper(data))
                        report = scan_release(root, policy)
                        self.assertFalse(report["ok"])
                        self.assertEqual(report["findings"], [{
                            "code": "native_debug_metadata", "path": target.name,
                            "archive_members": ["module.data"], "format": "elf"}])


class RealElfTypeMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        required = os.environ.get("RELEASEGUARD_REQUIRE_ELF_TYPE_METADATA") == "1"
        names = ("gcc", "strip", "objcopy", "readelf", "nm")
        if not sys.platform.startswith("linux") or not all(shutil.which(name) for name in names):
            if required:
                raise AssertionError("Mandatory CTF/BTF controls need Linux GCC and GNU binutils")
            raise unittest.SkipTest("Real CTF/BTF controls need Linux GCC and GNU binutils")
        for name in names[1:]:
            result = subprocess.run([name, "--version"], capture_output=True, text=True, timeout=30)
            if result.returncode or "GNU" not in result.stdout:
                if required:
                    raise AssertionError("Mandatory CTF/BTF controls need GNU " + name)
                raise unittest.SkipTest("Real CTF/BTF controls need GNU " + name)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned type metadata ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.source = self.work / "owned.c"
        self.source.write_text(SOURCE, encoding="ascii")
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="utf-8")

    def run_tool(self, *args):
        result = subprocess.run([str(arg) for arg in args], cwd=self.work,
                                capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0,
                         f"Command: {args!r}\n{result.stdout!r}\n{result.stderr!r}")
        return result.stdout

    def build(self, label):
        binary = self.work / label
        self.run_tool("gcc", "-O0", "-fno-inline", "-rdynamic", "-g" + label,
                      self.source, "-o", binary)
        self.run_tool(binary)
        return binary

    def section(self, binary, name, label):
        output = self.work / (label + ".section")
        # Explicit output copy keeps inspection from rewriting the input file.
        self.run_tool("objcopy", "--dump-section", name + "=" + str(output),
                      binary, self.work / (label + ".inspection"))
        return output.read_bytes()

    def assert_private_types(self, binary, section, label):
        payload = self.section(binary, section, label)
        if section == ".ctf":
            decoded = self.run_tool("readelf", "--ctf=.ctf", binary)
            self.assertTrue(PRIVATE_TYPE.encode() in decoded)
            self.assertTrue(PRIVATE_FIELD.encode() in decoded)
        else:
            # Independently inspect the real BTF string region (kernel BTF v1
            # header), rather than counting a type name anywhere in the ELF.
            magic, version, flags, header, _, _, strings, length = struct.unpack_from("<HBB5I", payload)
            self.assertEqual((magic, version, flags), (0xEB9F, 1, 0))
            self.assertGreaterEqual(header, 24)
            self.assertLessEqual(header + strings + length, len(payload))
            names = payload[header + strings:header + strings + length].split(b"\0")
            self.assertIn(PRIVATE_TYPE.encode(), names)
            self.assertIn(PRIVATE_FIELD.encode(), names)
        return payload

    def test_gcc_metadata_survives_strip_and_is_blocked_without_static_symbols(self):
        for label, section in (("ctf", ".ctf"), ("btf", ".BTF")):
            with self.subTest(format=label):
                binary = self.build(label)
                root = self.work / (label + "-release")
                root.mkdir()
                stripped = root / "module.data"
                # Keep this known section explicitly so the control remains
                # useful if a future GNU strip starts removing CTF/BTF itself.
                self.run_tool("strip", "--strip-all", "--keep-section=" + section,
                              "-o", stripped, binary)
                self.assert_private_types(stripped, section, label + "-stripped")
                self.assertFalse(audit_elf(stripped)["evidence"]["symbol_table_present"])
                before = hashlib.sha256(stripped.read_bytes()).hexdigest()
                report = scan_release(root, self.policy)
                self.assertFalse(report["ok"])
                self.assertEqual({item["code"] for item in report["findings"]}, {"native_debug_metadata"})
                self.assertEqual(hashlib.sha256(stripped.read_bytes()).hexdigest(), before)
                self.run_tool(stripped)

    def test_split_preserves_exact_private_type_bytes_and_public_program(self):
        for label, section in (("ctf", ".ctf"), ("btf", ".BTF")):
            with self.subTest(format=label):
                binary = self.build(label)
                original = binary.read_bytes()
                private_payload = self.assert_private_types(binary, section, label + "-original")
                public, private = self.work / (label + "-public"), self.work / (label + "-private")
                result = split_elf.split_elf_debug(binary, public, private, [PRIVATE_TYPE, PRIVATE_FIELD])
                self.assertTrue(result["ok"])
                released, debug = Path(result["public_elf"]), Path(result["private_debug"])
                self.assertEqual(self.assert_private_types(debug, section, label + "-private"), private_payload)
                self.assertNotIn(section, audit_elf(released)["sections"])
                self.assertEqual(binary.read_bytes(), original)
                self.assertNotIn(PRIVATE_TYPE.encode(), released.read_bytes())
                self.assertNotIn(PRIVATE_FIELD.encode(), released.read_bytes())
                self.assertTrue(scan_release(public, self.policy)["ok"])
                self.assertEqual(self.run_tool("nm", "-D", released), self.run_tool("nm", "-D", binary))
                self.assertEqual(self.section(released, ".text", label + "-public-text"),
                                 self.section(binary, ".text", label + "-original-text"))
                self.run_tool(released)

    def test_split_rejects_type_section_loss_without_leaving_outputs(self):
        binary = self.build("btf")
        real_objcopy = split_elf._objcopy

        def lose_private_section(tool, *args):
            result = real_objcopy(tool, *args)
            if "--only-keep-debug" in args:
                sidecar = Path(args[-1])
                temporary = self.work / "damaged.debug"
                self.run_tool("objcopy", "--remove-section=.BTF", sidecar, temporary)
                temporary.replace(sidecar)
            return result

        public, private = self.work / "public", self.work / "private"
        with patch.object(split_elf, "_objcopy", side_effect=lose_private_section):
            with self.assertRaisesRegex(GuardError, "type metadata"):
                split_elf.split_elf_debug(binary, public, private)
        self.assertFalse(public.exists())
        self.assertFalse(private.exists())

    def test_split_rejects_allocated_type_metadata(self):
        binary = self.build("btf")
        allocated = self.work / "allocated"
        self.run_tool("objcopy", "--set-section-flags", ".BTF=alloc,readonly", binary, allocated)
        public, private = self.work / "public", self.work / "private"
        with self.assertRaisesRegex(GuardError, "type metadata"):
            split_elf.split_elf_debug(allocated, public, private)
        self.assertFalse(public.exists())
        self.assertFalse(private.exists())


if __name__ == "__main__":
    unittest.main()
