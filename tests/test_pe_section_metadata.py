"""PE debug sections must not depend on Microsoft's separate debug directory."""

from __future__ import annotations

import io
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from releaseguard import pe
from releaseguard.distribution import scan_release
from releaseguard.native import gate
from tests.test_asar import asar, zip_archive
from tests.test_pe import make_debug_pe, make_pe


def named_pe(name: bytes, *, plus=True, long_name=False, symbol_count=0):
    data = make_pe(plus=plus)
    section = 0x98 + (240 if plus else 224)
    if long_name:
        data[section:section + 8] = b"/4\0\0\0\0\0\0"
        struct.pack_into("<II", data, 0x8C, 0x440, symbol_count)
        table = struct.pack("<I", len(name) + 5) + name + b"\0"
        start = 0x440 + 18 * symbol_count
        data.extend(bytes(max(0, start + len(table) - len(data))))
        data[start:start + len(table)] = table
    else:
        if len(name) > 8:
            raise ValueError("inline fixture name exceeds eight bytes")
        data[section:section + 8] = name.ljust(8, b"\0")
    return data


class PESectionMetadataTests(unittest.TestCase):
    def inspect(self, data):
        return pe.audit_pe_stream(io.BytesIO(data), len(data))

    def test_inline_and_truncated_debug_sections_need_no_debug_directory(self):
        for plus in (False, True):
            for name in (b".debug", b".debug_i", b".debug$S", b".zdebug", b".zdebug_",
                         b".stab", b".stabstr", b".gnu_deb"):
                with self.subTest(plus=plus, name=name):
                    report = self.inspect(named_pe(name, plus=plus))
                    self.assertFalse(report["evidence"]["debug_directory_present"])
                    self.assertFalse(report["evidence"]["coff_symbols_present"])
                    self.assertTrue(report["evidence"]["debug_metadata_present"])
                    self.assertEqual(report["debug_sections"], [name.decode()])

    def test_gnu_long_debug_names_are_resolved_with_or_without_symbol_records(self):
        for plus in (False, True):
            for count in (0, 1):
                for name in (b".debug_info", b".zdebug_info", b".gnu_debugdata"):
                    with self.subTest(plus=plus, count=count, name=name):
                        report = self.inspect(named_pe(name, plus=plus, long_name=True,
                                                       symbol_count=count))
                        self.assertTrue(report["evidence"]["debug_metadata_present"])
                        self.assertEqual(report["evidence"]["coff_symbols_present"], bool(count))
                        self.assertEqual(report["debug_sections"], [name.decode()])

    def test_ordinary_inline_and_gnu_long_names_remain_allowed(self):
        for name, long_name in ((b".text", False), (b".rdata", False), (b".pdata", False),
                                (b".long_public_section", True), (b".gnu_debuglink", True)):
            with self.subTest(name=name):
                report = self.inspect(named_pe(name, long_name=long_name))
                self.assertFalse(report["evidence"]["debug_metadata_present"])
                self.assertFalse(report["evidence"]["coff_symbols_present"])
                self.assertEqual(report["debug_sections"], [])

    def test_benign_debug_directory_cannot_mask_debug_sections(self):
        for kind, payload in ((16, b""), (20, struct.pack("<I", 1))):
            data = make_debug_pe([(kind, payload)])
            data[0x98 + 240:0x98 + 248] = b".debug_i"
            with self.subTest(kind=kind):
                report = self.inspect(data)
                self.assertTrue(report["evidence"]["debug_metadata_present"])
                self.assertFalse(any("检测到调试目录" in text for text in report["warnings"]))

    def test_unresolved_or_unsupported_long_name_aliases_are_rejected(self):
        for alias in (b"/", b"/0", b"/3", b"/999999", b"/-4", b"/x", b"//AAAAAA"):
            data = named_pe(b".debug_info", long_name=True)
            data[0x98 + 240:0x98 + 248] = alias.ljust(8, b"\0")
            with self.subTest(alias=alias), self.assertRaises(ValueError):
                self.inspect(data)
        data = named_pe(b".debug_info", long_name=True)
        struct.pack_into("<II", data, 0x8C, 0, 0)
        with self.assertRaises(ValueError):
            self.inspect(data)

    def test_noncanonical_nul_padding_cannot_hide_an_alternate_section_name(self):
        for name in (b".tex\0bad", b"/4\0junk\0"):
            data = make_pe(plus=True)
            data[0x98 + 240:0x98 + 248] = name
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.inspect(data)

    def test_string_table_ranges_lengths_and_termination_are_bounded(self):
        cases = []
        for size in (0, 3, pe._MAX_STRING_TABLE_BYTES + 1, 0xFFFFFFFF):
            data = named_pe(b".debug_info", long_name=True)
            struct.pack_into("<I", data, 0x440, size)
            cases.append(data)
        data = named_pe(b".debug_info", long_name=True)
        struct.pack_into("<I", data, 0x440, len(data) - 0x440 + 1)
        cases.append(data)
        data = named_pe(b".debug_info", long_name=True)
        data[0x440 + 4 + len(b".debug_info")] = ord("x")
        cases.append(data)
        data = named_pe(b".debug_info", long_name=True)
        struct.pack_into("<I", data, 0x8C, len(data) - 2)
        cases.append(data)
        for index, data in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.inspect(data)

    def test_string_table_must_not_overlap_headers_or_section_payloads(self):
        for offset in (0x100, 0x200, 0x3FC):
            data = named_pe(b".debug_info", long_name=True)
            table = data[0x440:0x440 + len(b".debug_info") + 5]
            data[offset:offset + len(table)] = table
            struct.pack_into("<I", data, 0x8C, offset)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.inspect(data)

    def test_section_name_budget_and_read_bounds(self):
        at_limit = named_pe(b"x" * pe._MAX_SECTION_NAME_BYTES, long_name=True)
        self.assertFalse(self.inspect(at_limit)["evidence"]["debug_metadata_present"])
        with self.assertRaises(ValueError):
            self.inspect(named_pe(b"x" * (pe._MAX_SECTION_NAME_BYTES + 1), long_name=True))
        reads = []

        class BoundedReader(io.BytesIO):
            def read(self, size=-1):
                reads.append(size)
                return super().read(size)

        pe.audit_pe_stream(BoundedReader(at_limit), len(at_limit))
        self.assertTrue(all(0 <= size <= pe._MAX_STRING_TABLE_BYTES for size in reads))
        self.assertLess(sum(reads), 8192)

    def test_disclosure_is_rejected_for_renamed_files_and_supported_containers(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            root = work / "release"
            root.mkdir()
            policy = work / "policy.json"
            policy.write_text('{"version":1}', encoding="utf-8")
            path = root / "renamed.data"
            for long_name in (False, True):
                data = bytes(named_pe(b".debug_info" if long_name else b".debug_i",
                                      long_name=long_name))
                for wrapped, members in ((data, []), (zip_archive("native.bin", data), ["native.bin"]),
                                         (asar([("native.bin", data)]), ["native.bin"])):
                    with self.subTest(long_name=long_name, members=members):
                        path.write_bytes(wrapped)
                        report = scan_release(root, policy)
                        self.assertFalse(report["ok"])
                        finding = next(f for f in report["findings"] if f["code"] == "native_debug_metadata")
                        self.assertEqual(finding.get("archive_members", []), members)
                        self.assertEqual(finding["format"], "pe")
                        self.assertTrue(report["checks"]["native_metadata_scan_completed"])

    def test_native_gate_inherits_section_metadata_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            root = work / "release"
            root.mkdir()
            path = root / "owned.exe"
            path.write_bytes(named_pe(b".stab"))
            policy = work / "policy.json"
            policy.write_text('{"version":1}', encoding="utf-8")
            report = gate(path, policy, root=root)
            self.assertFalse(report["ok"])
            self.assertTrue(any(f["code"] == "debug_metadata_present" for f in report["findings"]))


class GNUPESectionControls(unittest.TestCase):
    def test_real_objcopy_emits_and_removes_debug_sections_without_debug_directory(self):
        required = os.environ.get("RELEASEGUARD_REQUIRE_PE_BINUTILS") == "1"
        objcopy, objdump = shutil.which("objcopy"), shutil.which("objdump")
        if not sys.platform.startswith("linux") or not objcopy or not objdump:
            if required:
                self.fail("Mandatory GNU PE controls need Linux objcopy and objdump")
            self.skipTest("GNU PE controls need Linux objcopy and objdump")

        def run(*args):
            result = subprocess.run([str(arg) for arg in args], capture_output=True,
                                    text=True, check=True, timeout=30)
            return result.stdout

        if "GNU objcopy" not in run(objcopy, "--version"):
            if required:
                self.fail("Mandatory GNU PE controls need GNU objcopy")
            self.skipTest("objcopy is not GNU binutils")
        with tempfile.TemporaryDirectory(prefix="owned GNU PE ") as temporary:
            work = Path(temporary)
            original = work / "original.exe"
            # A project-owned image exercises real PE rewriting and inspection;
            # this control does not execute the synthetic Windows program.
            data = make_pe(plus=True)
            struct.pack_into("<II", data, 0x98 + 32, 0x1000, 0x200)
            struct.pack_into("<Q", data, 0x98 + 24, 0x140000000)
            struct.pack_into("<I", data, 0x98 + 16, 0x1000)
            struct.pack_into("<I", data, 0x98 + 240 + 36, 0x60000020)
            original.write_bytes(data)
            debug = work / "private.bin"
            marker = b"owned-private-debug-section"
            debug.write_bytes(marker)
            for long_names, expected in (("disable", ".debug_i"), ("enable", ".debug_info")):
                exposed, clean = work / (long_names + ".exe"), work / (long_names + "-clean.exe")
                run(objcopy, "--long-section-names=" + long_names,
                    "--add-section", ".debug_info=" + str(debug), original, exposed)
                sections = run(objdump, "-h", exposed)
                self.assertIn(expected, sections)
                self.assertIn(marker, exposed.read_bytes())
                report = pe.audit_pe(exposed)
                self.assertFalse(report["evidence"]["debug_directory_present"])
                self.assertTrue(report["evidence"]["debug_metadata_present"])
                self.assertEqual(report["debug_sections"], [expected])
                run(objcopy, "--remove-section=" + expected, exposed, clean)
                self.assertNotIn(marker, clean.read_bytes())
                self.assertNotIn(expected, run(objdump, "-h", clean))
                self.assertFalse(pe.audit_pe(clean)["evidence"]["debug_metadata_present"])


if __name__ == "__main__":
    unittest.main()
