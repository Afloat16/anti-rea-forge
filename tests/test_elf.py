"""Synthetic cross-format and locally compiled ELF metadata tests."""

from __future__ import annotations

import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from releaseguard.elf import audit_elf


def make_elf(
    *,
    bits: int = 64,
    endian: str = "little",
    image_type: int = 2,
    machine: int | None = None,
    entries: list[tuple[str, int]] | None = None,
    no_sections: bool = False,
) -> bytearray:
    """Build a small ELF with section names and small, nonoverlapping data."""
    prefix = "<" if endian == "little" else ">"
    is64 = bits == 64
    header_size, section_size = (64, 64) if is64 else (52, 40)
    section_format = prefix + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
    header_format = prefix + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH")
    entries = entries if entries is not None else [(".text", 1)]
    count = 0 if no_sections else len(entries) + 2
    data = bytearray(0x400 + count * section_size)
    data[:7] = b"\x7fELF" + bytes((2 if is64 else 1, 1 if endian == "little" else 2, 1))
    struct.pack_into(
        header_format, data, 16,
        image_type, machine if machine is not None else (62 if is64 else 3),
        1, 0, 0, 0 if no_sections else 0x400, 0, header_size, 0, 0,
        0 if no_sections else section_size, count, 0 if no_sections else 1,
    )
    if no_sections:
        return data
    names = bytearray(b"\0.shstrtab\0")
    name_offsets = []
    for name, _ in entries:
        name_offsets.append(len(names))
        names.extend(name.encode("utf-8") + b"\0")
    data[0x100:0x100 + len(names)] = names
    struct.pack_into(section_format, data, 0x400 + section_size,
                     1, 3, 0, 0, 0x100, len(names), 0, 0, 1, 0)
    for index, ((_, section_type), name_offset) in enumerate(zip(entries, name_offsets), start=2):
        struct.pack_into(section_format, data, 0x400 + index * section_size,
                         name_offset, section_type, 0, 0, 0x200 + (index - 2) * 16,
                         8, 0, 0, 1, 0)
    return data


class ELFAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "sample.elf"

    def audit(self, data: bytes) -> dict:
        self.path.write_bytes(data)
        return audit_elf(self.path)

    def test_all_classes_and_byte_orders(self) -> None:
        for bits in (32, 64):
            for endian in ("little", "big"):
                with self.subTest(bits=bits, endian=endian):
                    report = self.audit(make_elf(bits=bits, endian=endian))
                    self.assertEqual(report["format"], f"ELF{bits}")
                    self.assertEqual(report["endian"], endian)
                    self.assertEqual(report["type"], "executable")
                    self.assertEqual(report["machine"], "x64" if bits == 64 else "x86")
                    self.assertEqual(report["sections"], ["", ".shstrtab", ".text"])
                    self.assertTrue(report["section_table_present"])
                    self.assertFalse(any(report["evidence"].values()))

    def test_shared_type_and_unknown_machine(self) -> None:
        report = self.audit(make_elf(image_type=3, machine=0x9999))
        self.assertEqual(report["type"], "shared")
        self.assertEqual(report["machine"], "unknown-0x9999")
        self.assertTrue(any("PIE" in note for note in report["notes"]))

    def test_recognizes_debug_and_compressed_debug_names(self) -> None:
        for name in (".debug_info", ".debug_line", ".zdebug_info", ".stab", ".stabstr", ".debug", ".gnu_debugdata"):
            with self.subTest(name=name):
                self.assertTrue(self.audit(make_elf(entries=[(name, 1)]))["evidence"]["debug_sections_present"])

    def test_symtab_uses_type_and_excludes_dynamic_symbols(self) -> None:
        self.assertTrue(self.audit(make_elf(entries=[(".renamed", 2)]))["evidence"]["symbol_table_present"])
        self.assertFalse(self.audit(make_elf(entries=[(".symtab", 11)]))["evidence"]["symbol_table_present"])

    def test_inactive_null_section_does_not_count_as_debug(self) -> None:
        self.assertFalse(self.audit(make_elf(entries=[(".debug_info", 0)]))["evidence"]["debug_sections_present"])

    def test_noninitial_null_section_undefined_fields_are_ignored(self) -> None:
        data = make_elf(entries=[(".ignored", 0)])
        struct.pack_into("<IIQQQQIIQQ", data, 0x400 + 2 * 64,
                         0xFFFFFFFF, 0, 1, 1, 0xFFFFFFFFFFFFFFFF,
                         0xFFFFFFFFFFFFFFFF, 1, 1, 3, 1)
        report = self.audit(data)
        self.assertEqual(report["sections"][-1], "")
        self.assertFalse(any(report["evidence"].values()))

    def test_noninitial_null_section_names_ignored_without_name_table(self) -> None:
        data = make_elf(entries=[(".ignored", 0)])
        struct.pack_into("<H", data, 62, 0)
        struct.pack_into("<I", data, 0x400 + 64, 0)
        struct.pack_into("<I", data, 0x400 + 2 * 64, 0xFFFFFFFF)
        self.assertFalse(self.audit(data)["section_names_available"])

    def test_no_section_table_is_accepted_with_scope_note(self) -> None:
        report = self.audit(make_elf(no_sections=True))
        self.assertEqual(report["sections"], [])
        self.assertFalse(report["section_table_present"])
        self.assertFalse(report["section_names_available"])
        self.assertFalse(any(report["evidence"].values()))
        self.assertTrue(any("未提供 section 表" in note for note in report["notes"]))

    def test_missing_name_table_still_detects_symtab_by_type(self) -> None:
        data = make_elf(entries=[(".symtab", 2)])
        struct.pack_into("<H", data, 62, 0)
        for index in (1, 2):
            struct.pack_into("<I", data, 0x400 + index * 64, 0)
        report = self.audit(data)
        self.assertTrue(report["evidence"]["symbol_table_present"])
        self.assertTrue(report["section_table_present"])
        self.assertFalse(report["section_names_available"])
        self.assertTrue(any("未提供 section 名称表" in note for note in report["notes"]))

    def test_nobits_does_not_require_file_data(self) -> None:
        data = make_elf(entries=[(".bss", 8)])
        struct.pack_into("<QQ", data, 0x400 + 2 * 64 + 24, 0xFFFFFFFFFFFFF000, 0xFFFFFFFFFFFFF000)
        self.assertIn(".bss", self.audit(data)["sections"])

    def test_string_path_and_read_only_behavior(self) -> None:
        data = make_elf()
        self.path.write_bytes(data)
        audit_elf(str(self.path))
        self.assertEqual(self.path.read_bytes(), data)

    def test_missing_file_propagates_oserror(self) -> None:
        with self.assertRaises(OSError):
            audit_elf(self.path)

    def test_rejects_truncated_or_nonelf_input(self) -> None:
        for data in (b"", b"\x7fELF", b"MZ" + bytes(80), make_elf()[:40]):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                self.audit(data)

    def test_rejects_unsupported_identification(self) -> None:
        for offset, value in ((4, 0), (4, 3), (5, 0), (5, 3), (6, 0), (6, 2)):
            data = make_elf()
            data[offset] = value
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                self.audit(data)

    def test_rejects_nonrelease_elf_types(self) -> None:
        for image_type in (0, 1, 4, 0xFFFF):
            with self.subTest(image_type=image_type), self.assertRaisesRegex(ValueError, "暂不支持"):
                self.audit(make_elf(image_type=image_type))

    def test_rejects_unknown_version_and_header_sizes(self) -> None:
        for offset, value, fmt in ((20, 2, "<I"), (52, 0, "<H"), (52, 65, "<H")):
            data = make_elf()
            struct.pack_into(fmt, data, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                self.audit(data)

    def test_rejects_extended_numbering(self) -> None:
        for offset in (56, 60, 62):
            data = make_elf()
            struct.pack_into("<H", data, offset, 0 if offset == 60 else 0xFFFF)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, "扩展"):
                self.audit(data)

    def test_rejects_section_count_resource_limit(self) -> None:
        data = make_elf()
        struct.pack_into("<H", data, 60, 8193)
        with self.assertRaisesRegex(ValueError, "上限"):
            self.audit(data)

    def test_accepts_section_count_at_resource_limit(self) -> None:
        data = make_elf(entries=[])
        data.extend(bytes((8192 - 2) * 64))
        struct.pack_into("<H", data, 60, 8192)
        self.assertEqual(len(self.audit(data)["sections"]), 8192)

    def test_rejects_invalid_section_table_size_and_range(self) -> None:
        for offset, value, fmt in ((58, 0, "<H"), (58, 65, "<H"), (40, 0, "<Q"), (40, 63, "<Q"), (40, 0xFFFFFFFFFFFFFFF0, "<Q")):
            data = make_elf()
            struct.pack_into(fmt, data, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                self.audit(data)

    def test_rejects_invalid_name_table_index_and_type(self) -> None:
        for offset, value, fmt in ((62, 3, "<H"), (0x400 + 64 + 4, 8, "<I")):
            data = make_elf()
            struct.pack_into(fmt, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.audit(data)

    def test_rejects_nonzero_initial_section(self) -> None:
        data = make_elf()
        struct.pack_into("<I", data, 0x400 + 4, 1)
        with self.assertRaises(ValueError):
            self.audit(data)

    def test_rejects_bad_section_data_ranges_and_overlaps(self) -> None:
        for offset, size in ((0x1000, 8), (0xFFFFFFFFFFFFFFF0, 32), (0, 8), (0x410, 8), (0x100, 8)):
            data = make_elf()
            struct.pack_into("<QQ", data, 0x400 + 2 * 64 + 24, offset, size)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.audit(data)

    def test_rejects_non_power_of_two_section_alignment(self) -> None:
        data = make_elf()
        struct.pack_into("<Q", data, 0x400 + 2 * 64 + 48, 3)
        with self.assertRaises(ValueError):
            self.audit(data)

    def test_rejects_compressed_name_table(self) -> None:
        data = make_elf()
        struct.pack_into("<Q", data, 0x400 + 64 + 8, 0x800)
        with self.assertRaisesRegex(ValueError, "暂不支持"):
            self.audit(data)

    def test_rejects_name_table_over_read_limit(self) -> None:
        data = make_elf()
        # Move the section table past a physically present large name table.
        table = bytes(data[0x400:])
        data = data[:0x400] + bytearray(1024 * 1024) + table
        new_table = 0x400 + 1024 * 1024
        struct.pack_into("<Q", data, 40, new_table)
        struct.pack_into("<Q", data, new_table + 64 + 32, 1024 * 1024 + 1)
        struct.pack_into("<Q", data, new_table + 2 * 64 + 24, new_table - 0x20)
        with self.assertRaisesRegex(ValueError, "读取上限"):
            self.audit(data)

    def test_accepts_name_table_at_read_limit(self) -> None:
        data = make_elf()
        table = bytes(data[0x400:])
        data = data[:0x400] + bytearray(1024 * 1024) + table
        new_table = 0x400 + 1024 * 1024
        struct.pack_into("<Q", data, 40, new_table)
        struct.pack_into("<Q", data, new_table + 64 + 32, 1024 * 1024)
        struct.pack_into("<Q", data, new_table + 2 * 64 + 24, new_table - 0x20)
        self.assertIn(".text", self.audit(data)["sections"])

    def test_rejects_excessive_individual_name_length(self) -> None:
        data = make_elf(entries=[])
        data.extend(bytes(0x2000 - len(data)))
        table = bytes(data[0x400:0x480])
        data[0x100:0x100 + 4099] = b"\0" + b"A" * 4097 + b"\0"
        data[0x1800:0x1880] = table
        struct.pack_into("<Q", data, 40, 0x1800)
        struct.pack_into("<Q", data, 0x1800 + 64 + 32, 4099)
        with self.assertRaisesRegex(ValueError, "长度上限"):
            self.audit(data)

    def test_rejects_excessive_total_name_output(self) -> None:
        data = make_elf(entries=[])
        count, table_offset = 259, 0x2000
        data.extend(bytes(table_offset + count * 64 - len(data)))
        struct.pack_into("<Q", data, 40, table_offset)
        struct.pack_into("<H", data, 60, count)
        names = b"\0" + b"A" * 4096 + b"\0.shstrtab\0"
        data[0x100:0x100 + len(names)] = names
        struct.pack_into("<IIQQQQIIQQ", data, table_offset + 64,
                         4098, 3, 0, 0, 0x100, 4108, 0, 0, 1, 0)
        for index in range(2, count):
            struct.pack_into("<IIQQQQIIQQ", data, table_offset + index * 64,
                             1, 1, 0, 0, 0, 0, 0, 0, 1, 0)
        with self.assertRaisesRegex(ValueError, "输出上限"):
            self.audit(data)

    def test_section_names_can_reuse_string_suffixes(self) -> None:
        data = make_elf()
        struct.pack_into("<I", data, 0x400 + 2 * 64, 13)
        self.assertIn("ext", self.audit(data)["sections"])

    def test_gabi_compressed_debug_section_is_detected_by_name(self) -> None:
        data = make_elf(entries=[(".debug_info", 1)])
        struct.pack_into("<Q", data, 0x400 + 2 * 64 + 8, 0x800)
        self.assertTrue(self.audit(data)["evidence"]["debug_sections_present"])

    def test_rejects_invalid_or_unterminated_section_names(self) -> None:
        for change in ("index", "first", "last"):
            data = make_elf()
            if change == "index":
                struct.pack_into("<I", data, 0x400 + 2 * 64, 0xFFFFFF)
            elif change == "first":
                data[0x100] = 65
            else:
                name_size = struct.unpack_from("<Q", data, 0x400 + 64 + 32)[0]
                data[0x100 + name_size - 1] = 65
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.audit(data)

    def test_rejects_missing_name_table_with_nonzero_name_indices(self) -> None:
        data = make_elf()
        struct.pack_into("<H", data, 62, 0)
        with self.assertRaises(ValueError):
            self.audit(data)

    def test_rejects_program_header_resource_and_range_errors(self) -> None:
        for offset, count, entry_size in ((64, 4097, 56), (64, 1, 55), (0, 1, 56), (0x100000, 1, 56), (64, 0, 56)):
            data = make_elf()
            struct.pack_into("<Q", data, 32, offset)
            struct.pack_into("<HH", data, 54, entry_size, count)
            with self.subTest(offset=offset, count=count), self.assertRaises(ValueError):
                self.audit(data)

    def test_accepts_in_bounds_program_header_table(self) -> None:
        data = make_elf(no_sections=True)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 1)
        self.assertEqual(self.audit(data)["sections"], [])

    def test_never_requests_unbounded_or_section_payload_reads(self) -> None:
        data = make_elf()
        self.path.write_bytes(data)
        original_open = Path.open
        reads = []

        class Reader:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                self.stream.__enter__()
                return self

            def __exit__(self, *args):
                return self.stream.__exit__(*args)

            def fileno(self):
                return self.stream.fileno()

            def seek(self, offset):
                return self.stream.seek(offset)

            def read(self, size=-1):
                reads.append((self.stream.tell(), size))
                return self.stream.read(size)

        def tracked_open(path, *args, **kwargs):
            return Reader(original_open(path, *args, **kwargs))

        with patch.object(Path, "open", tracked_open):
            audit_elf(self.path)
        self.assertEqual(reads, [(0, 16), (16, 48), (0x400, 192), (0x100, 17)])
        self.assertTrue(all(0 <= size <= 1024 * 1024 for _, size in reads))

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("cc"),
                         "a Linux C compiler is needed for the real ELF fixture")
    def test_real_locally_compiled_debug_and_stripped_elf(self) -> None:
        root = Path(self.temp.name)
        source = root / "fixture.c"
        source.write_text("static int internal(int x) { return x + 1; }\nint main(void) { return internal(0); }\n", encoding="utf-8")
        debug, stripped = root / "debug", root / "stripped"
        for target, options in ((debug, ["-g", "-O0"]), (stripped, ["-s", "-O2"])):
            subprocess.run([shutil.which("cc"), str(source), *options, "-o", str(target)],
                           check=True, capture_output=True, timeout=30)
        before = audit_elf(debug)
        after = audit_elf(stripped)
        self.assertTrue(before["evidence"]["debug_sections_present"])
        self.assertTrue(before["evidence"]["symbol_table_present"])
        self.assertFalse(after["evidence"]["debug_sections_present"])
        self.assertFalse(after["evidence"]["symbol_table_present"])
        self.assertTrue(after["section_names_available"])


if __name__ == "__main__":
    unittest.main()
