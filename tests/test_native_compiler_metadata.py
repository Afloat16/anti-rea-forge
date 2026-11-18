"""Structural controls for compiler IR, independent of native debug symbols.

These are format fixtures, not claims of Windows/macOS compiler or runtime
success. Real Clang/GNU ELF producer and llvm-dis controls live separately.
"""

from __future__ import annotations

import io
from pathlib import Path
import struct
import tempfile
import unittest

from releaseguard.core import GuardError
from releaseguard.distribution import scan_release
from releaseguard.elf import audit_elf_stream
from releaseguard.macho import audit_macho_stream
from releaseguard.pe import audit_pe_stream
from releaseguard.split_elf import _compiler_metadata
from tests.test_asar import asar, zip_archive
from tests.test_elf import make_elf
from tests.test_macho import make_fat, make_macho
from tests.test_pe_section_metadata import named_pe


ELF_NAMES = (".llvmbc", ".llvmcmd", ".llvm.lto")
MACHO_NAMES = (b"__bitcode", b"__cmdline", b"__bundle")


class NativeCompilerMetadataTests(unittest.TestCase):
    def inspect(self, inspector, data):
        return inspector(io.BytesIO(data), len(data))

    def test_elf_names_in_both_classes_and_byte_orders_are_separate_from_debug(self):
        for bits in (32, 64):
            for endian in ("little", "big"):
                for name in ELF_NAMES:
                    with self.subTest(bits=bits, endian=endian, name=name):
                        data = make_elf(bits=bits, endian=endian, entries=[(name, 1)])
                        report = self.inspect(audit_elf_stream, data)
                        self.assertTrue(report["compiler_metadata_present"])
                        self.assertEqual(report["compiler_metadata_sections"], [name])
                        self.assertFalse(any(report["evidence"].values()))

    def test_elf_inactive_sections_and_lookalikes_are_not_compiler_metadata(self):
        for name in (*ELF_NAMES, ".llvmbc_public", ".llvmcmdline", ".llvm.lto.info",
                     ".llvm_addrsig", ".llvm.call-graph-profile", ".text"):
            data = make_elf(entries=[(name, 0 if name in ELF_NAMES else 1)])
            with self.subTest(name=name):
                report = self.inspect(audit_elf_stream, data)
                self.assertFalse(report["compiler_metadata_present"])
                self.assertEqual(report["compiler_metadata_sections"], [])
        report = self.inspect(audit_elf_stream, make_elf(no_sections=True))
        self.assertFalse(report["compiler_metadata_present"])

    def test_pe_inline_and_coff_string_table_names_are_independent_of_debug_directory(self):
        for plus in (False, True):
            for long_name in (False, True):
                for name in (b".llvmbc", b".llvmcmd"):
                    with self.subTest(plus=plus, long_name=long_name, name=name):
                        report = self.inspect(audit_pe_stream, named_pe(name, plus=plus, long_name=long_name))
                        self.assertTrue(report["compiler_metadata_present"])
                        self.assertEqual(report["compiler_metadata_sections"], [name.decode()])
                        self.assertFalse(report["evidence"]["debug_metadata_present"])
                        self.assertFalse(report["evidence"]["coff_symbols_present"])
        for name in (b".llvmbcx", b".llvmcm", b".llvmcmd_public", b".llvm_addrsig", b".pdata"):
            with self.subTest(name=name):
                report = self.inspect(audit_pe_stream, named_pe(name, long_name=len(name) > 8))
                self.assertFalse(report["compiler_metadata_present"])

    def test_macho_exact_segment_and_section_pairs_in_all_thin_layouts(self):
        for bits in (32, 64):
            for endian in ("<", ">"):
                for name in MACHO_NAMES:
                    with self.subTest(bits=bits, endian=endian, name=name):
                        data = make_macho(bits=bits, endian=endian, segment_name=b"__LLVM", section_name=name)
                        report = self.inspect(audit_macho_stream, data)
                        expected = ["__LLVM," + name.decode()]
                        self.assertTrue(report["compiler_metadata_present"])
                        self.assertEqual(report["compiler_metadata_sections"], expected)
                        self.assertEqual(report["architectures"][0]["compiler_metadata_sections"], expected)
                        self.assertFalse(any(report["evidence"].values()))
        for segment, section in ((b"__TEXT", b"__bitcode"), (b"__DATA", b"__cmdline"),
                                 (b"__LLVM", b"__bitcode_extra"), (b"__LLVM2", b"__bundle"),
                                 (b"__LLVM", b"__other"), (b"__LLVM", b"__asm")):
            with self.subTest(segment=segment, section=section):
                report = self.inspect(audit_macho_stream, make_macho(segment_name=segment, section_name=section))
                self.assertFalse(report["compiler_metadata_present"])

    def test_macho_fat_checks_compiler_metadata_in_every_slice(self):
        clean = make_macho()
        embedded = make_macho(cpu=0x0100000C, subtype=0, segment_name=b"__LLVM", section_name=b"__bundle")
        for bits in (32, 64):
            for slices in ((clean, embedded), (embedded, clean)):
                with self.subTest(bits=bits, order=slices[0] == clean):
                    report = self.inspect(audit_macho_stream, make_fat(slices, bits=bits))
                    self.assertTrue(report["compiler_metadata_present"])
                    self.assertEqual(report["compiler_metadata_sections"], ["__LLVM,__bundle"])
                    self.assertEqual(sum(row["compiler_metadata_present"] for row in report["architectures"]), 1)

    def test_split_fingerprints_only_eligible_compiler_sections(self):
        for bits in (32, 64):
            for endian in ("little", "big"):
                prefix = "<" if endian == "little" else ">"
                stride = 40 if bits == 32 else 64
                layout = prefix + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ")
                for name in ELF_NAMES:
                    data = make_elf(bits=bits, endian=endian, entries=[(name, 1)])
                    at = 0x400 + 2 * stride
                    original = struct.unpack_from(layout, data, at)
                    # Empty flags and SHF_EXCLUDE are supported; neither maps
                    # the compiler records into the process image.
                    for flags in (0, 0x80000000):
                        fields = list(original)
                        fields[2] = flags
                        struct.pack_into(layout, data, at, *fields)
                        with self.subTest(bits=bits, endian=endian, name=name, flags=flags):
                            self.inspect(audit_elf_stream, data)
                            self.assertEqual(set(_compiler_metadata(bytes(data))), {name})
                    for field, value in ((1, 8), (2, 2), (2, 4), (2, 0x800), (6, 1), (7, 1), (9, 4)):
                        fields = list(original)
                        fields[field] = value
                        struct.pack_into(layout, data, at, *fields)
                        with self.subTest(bits=bits, endian=endian, name=name, field=field, value=value):
                            self.inspect(audit_elf_stream, data)
                            with self.assertRaisesRegex(GuardError, "compiler metadata"):
                                _compiler_metadata(bytes(data))
        duplicate = make_elf(entries=[(".llvmbc", 1), (".llvmbc", 1)])
        self.inspect(audit_elf_stream, duplicate)
        with self.assertRaisesRegex(GuardError, "compiler metadata"):
            _compiler_metadata(bytes(duplicate))

    def test_split_rejects_program_mapped_ir_even_with_alloc_flag_cleared(self):
        for bits in (32, 64):
            for endian in ("little", "big"):
                prefix = "<" if endian == "little" else ">"
                is64 = bits == 64
                for kind in (1, 4):  # PT_LOAD and PT_NOTE both describe file-backed data.
                    data = make_elf(bits=bits, endian=endian, entries=[(".llvmbc", 1)])
                    phsize, header_size = (56, 64) if is64 else (32, 52)
                    struct.pack_into(prefix + ("Q" if is64 else "I"), data, 32 if is64 else 28, header_size)
                    struct.pack_into(prefix + "HH", data, header_size - 10, phsize, 1)
                    fields = (kind, 4, 0x200, 0, 0, 8, 8, 1) if is64 else (kind, 0x200, 0, 0, 8, 8, 4, 1)
                    struct.pack_into(prefix + ("IIQQQQQQ" if is64 else "8I"), data, header_size, *fields)
                    with self.subTest(bits=bits, endian=endian, segment=kind):
                        self.inspect(audit_elf_stream, data)
                        with self.assertRaisesRegex(GuardError, "overlaps a program segment"):
                            _compiler_metadata(bytes(data))

    def test_default_gate_checks_renamed_files_zip_asar_and_fat_members(self):
        payloads = [("elf", bytes(make_elf(entries=[(name, 1)]))) for name in ELF_NAMES]
        payloads += [("pe", bytes(named_pe(name))) for name in (b".llvmbc", b".llvmcmd")]
        payloads += [("macho", make_macho(segment_name=b"__LLVM", section_name=name)) for name in MACHO_NAMES]
        payloads.append(("macho", make_fat((make_macho(), make_macho(
            cpu=0x0100000C, subtype=0, segment_name=b"__LLVM", section_name=b"__bundle")))))
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            root = work / "release"
            root.mkdir()
            policy = work / "policy.json"
            policy.write_text('{"version":1}', encoding="utf-8")
            target = root / "renamed.data"
            for format_name, payload in payloads:
                for wrapped, members in ((payload, []), (zip_archive("module.data", payload), ["module.data"]),
                                         (asar([("module.data", payload)]), ["module.data"])):
                    with self.subTest(format=format_name, members=members):
                        target.write_bytes(wrapped)
                        report = scan_release(root, policy)
                        self.assertFalse(report["ok"])
                        finding = next(row for row in report["findings"] if row["code"] == "native_compiler_metadata")
                        self.assertEqual(finding["format"], format_name)
                        self.assertEqual(finding.get("archive_members", []), members)
                        self.assertTrue(report["checks"]["native_metadata_scan_completed"])
                        self.assertEqual(target.read_bytes(), wrapped)


if __name__ == "__main__":
    unittest.main()
