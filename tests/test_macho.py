"""Owned Mach-O and Java controls for portable release metadata checks."""

from __future__ import annotations

import io
import json
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from releaseguard import macho
from releaseguard.distribution import scan_release
from tests.test_asar import asar
from tests.test_distribution import archive


def make_macho(*, bits=64, endian="<", cpu=None, subtype=3, debug=False,
               symbols=None, with_symtab=True, extra=b"", file_type=6,
               section_name=b"__text", section_flags=0, segment_name=b"__TEXT"):
    """Minimal owned image with a section and a fully indexed nlist table."""
    if cpu is None:
        cpu = 7 if bits == 32 else 0x01000007
    if symbols is None:
        symbols = [(b"_public_api", 0xF, 1), (b"_puts", 1, 0)]
    header_size, segment_size, section_size, symbol_size = (
        (28, 56, 68, 12) if bits == 32 else (32, 72, 80, 16))
    command_bytes = (segment_size + section_size) * (2 if debug else 1)
    command_bytes += (24 if with_symtab else 0) + len(extra)
    text_offset = header_size + command_bytes
    text = b"\x90" * 16
    dwarf = b"\0" * 8 if debug else b""
    payload_end = text_offset + len(text) + len(dwarf)
    symoff = (payload_end + 7) & ~7
    strings = bytearray(b"\0")
    entries = bytearray()
    for name, kind, section in symbols:
        name_index = len(strings) if name else 0
        if name:
            strings.extend(name + b"\0")
        entries.extend(struct.pack(endian + ("IBBHI" if bits == 32 else "IBBHQ"),
                                   name_index, kind, section, 0, 0))
    stroff = symoff + len(entries)
    commands = bytearray()

    def segment(name, section, offset, length, flags, address):
        command = 1 if bits == 32 else 0x19
        layout = "II16sIIIIiiII" if bits == 32 else "II16sQQQQiiII"
        result = struct.pack(endian + layout, command, segment_size + section_size,
                             name, address, length, offset, length, 7, 5, 1, 0)
        layout = "16s16sIIIIIIIII" if bits == 32 else "16s16sQQIIIIIIII"
        fields = (section, name, address, length, offset, 0, 0, 0, flags, 0, 0)
        return result + struct.pack(endian + layout, *(fields if bits == 32 else fields + (0,)))

    commands.extend(segment(segment_name, section_name, text_offset, len(text), section_flags, 4096))
    if debug:
        commands.extend(segment(b"__DWARF", b"__debug_info", text_offset + len(text), len(dwarf), 0x02000000, 8192))
    if with_symtab:
        commands.extend(struct.pack(endian + "6I", 2, 24, symoff, len(symbols), stroff, len(strings)))
    commands.extend(extra)
    ncmds = (2 if debug else 1) + int(with_symtab)
    position = 0
    while position < len(extra):
        ncmds += 1
        length = struct.unpack_from(endian + "I", extra, position + 4)[0]
        if length < 8:
            raise ValueError("Invalid test load command")
        position += length
    header = struct.pack(endian + "7I", 0xFEEDFACE if bits == 32 else 0xFEEDFACF,
                         cpu, subtype, file_type, ncmds, command_bytes, 0)
    if bits == 64:
        header += b"\0" * 4
    body = header + commands + text + dwarf
    if not with_symtab:
        return bytes(body)
    return bytes(body + b"\0" * (symoff - len(body)) + entries + strings)


def command_offset(data, wanted):
    endian, bits = macho._THIN_MAGICS[data[:4]]
    offset = 28 if bits == 32 else 32
    count = struct.unpack_from(endian + "I", data, 16)[0]
    for _ in range(count):
        cmd, size = struct.unpack_from(endian + "II", data, offset)
        if cmd == wanted:
            return offset
        offset += size
    raise AssertionError("Fixture command is absent")


def replace_u32(data, offset, value, endian="<"):
    result = bytearray(data)
    struct.pack_into(endian + "I", result, offset, value)
    return bytes(result)


def make_fat(images, *, bits=32, align=6):
    stride = 20 if bits == 32 else 32
    directory_end = 8 + len(images) * stride
    body = bytearray(b"\0" * directory_end)
    entries = []
    for data in images:
        endian, _ = macho._THIN_MAGICS[data[:4]]
        cpu, subtype = struct.unpack_from(endian + "II", data, 4)
        offset = (len(body) + (1 << align) - 1) & ~((1 << align) - 1)
        body.extend(b"\0" * (offset - len(body)))
        body.extend(data)
        fields = (cpu, subtype, offset, len(data), align)
        entries.append(struct.pack(">5I", *fields) if bits == 32
                       else struct.pack(">IIQQII", *fields, 0))
    body[:directory_end] = struct.pack(">II", 0xCAFEBABE if bits == 32 else 0xCAFEBABF, len(images)) + b"".join(entries)
    return bytes(body)


def java_class(*, major=65, minor=0, padding=0):
    # A class with no members is legal. Unknown attributes are permitted by the
    # JVM; the large attribute defeats any classifier using only short headers.
    pool = (b"\x01\x00\x07Fixture" + b"\x07\x00\x01"
            + b"\x01\x00\x10java/lang/Object" + b"\x07\x00\x03"
            + b"\x01\x00\x03Pad")
    header = struct.pack(">IHHH", 0xCAFEBABE, minor, major, 6)
    body = struct.pack(">7H", 0x21, 2, 4, 0, 0, 0, int(bool(padding)))
    if padding:
        body += struct.pack(">HI", 5, padding) + b"\0" * padding
    return header + pool + body


class MachOReaderTests(unittest.TestCase):
    def inspect(self, data):
        stream = io.BytesIO(data)
        result = macho.audit_macho_stream(stream, len(data))
        self.assertFalse(stream.closed)
        return result

    def rejected(self, data):
        with self.assertRaises(ValueError):
            self.inspect(data)

    def test_thin_width_and_byte_order_matrix_preserves_public_binding_symbols(self):
        for bits in (32, 64):
            for endian in ("<", ">"):
                with self.subTest(bits=bits, endian=endian):
                    report = self.inspect(make_macho(bits=bits, endian=endian))
                    self.assertEqual(report["container"], "thin")
                    self.assertEqual(report["slice_count"], 1)
                    item = report["architectures"][0]
                    self.assertEqual(item["class"], bits)
                    self.assertEqual(item["byte_order"], "little" if endian == "<" else "big")
                    self.assertEqual(item["public_symbols"], 2)
                    self.assertEqual(report["evidence"], {
                        "debug_metadata_present": False, "private_symbols_present": False})

    def test_dwarf_sections_and_stabs_are_independent_debug_evidence(self):
        cases = [make_macho(debug=True),
                 make_macho(section_name=b"__zdebug_info"),
                 make_macho(section_name=b"opaque", section_flags=0x02000000),
                 make_macho(segment_name=b"__DWARF"),
                 make_macho(symbols=[(b"/owned/private/source.c", 0x64, 0)]),
                 make_macho(extra=struct.pack("<4I", 3, 16, 0, 0))]
        for data in cases:
            with self.subTest(magic=data[:4], length=len(data)):
                report = self.inspect(data)
                self.assertTrue(report["evidence"]["debug_metadata_present"])
                self.assertNotIn("private/source.c", json.dumps(report))

    def test_named_local_and_private_external_symbols_are_reported(self):
        for kind, section in ((0xE, 1), (0x1F, 1), (2, 0)):
            with self.subTest(kind=kind):
                report = self.inspect(make_macho(symbols=[(b"_private_pricing", kind, section)]))
                self.assertTrue(report["evidence"]["private_symbols_present"])
                self.assertEqual(report["architectures"][0]["private_symbols"], 1)
                self.assertNotIn("_private_pricing", json.dumps(report))

    def test_empty_local_names_and_empty_symbol_table_do_not_disclose_names(self):
        for symbols in ([], [(b"", 2, 0)]):
            with self.subTest(symbols=symbols):
                report = self.inspect(make_macho(symbols=symbols))
                self.assertFalse(report["evidence"]["private_symbols_present"])

    def test_missing_metadata_unknown_commands_and_unsupported_filetypes_fail_closed(self):
        for data in (make_macho(with_symtab=False),
                     make_macho(extra=struct.pack("<2I", 0x12345678, 8)),
                     make_macho(file_type=12),
                     make_macho(file_type=4),
                     replace_u32(make_macho(), 24, 0x80000000)):
            self.rejected(data)

    def test_active_encryption_and_arbitrary_note_payloads_are_unverifiable(self):
        for command in (struct.pack("<6I", 0x2C, 24, 0, 0, 1, 0),
                        struct.pack("<II16sQQ", 0x31, 40, b"unknown", 0, 0)):
            self.rejected(make_macho(extra=command))
        report = self.inspect(make_macho(extra=struct.pack("<6I", 0x2C, 24, 0, 0, 0, 0)))
        self.assertTrue(report["metadata_complete"])

    def test_load_command_counts_sizes_alignment_and_truncation_are_bounded(self):
        original = make_macho()
        cases = [original[:3], original[:31], original[:-1],
                 replace_u32(original, 16, 0), replace_u32(original, 16, 4097),
                 replace_u32(original, 20, 0xFFFFFFFF),
                 replace_u32(original, 36, 4),
                 replace_u32(original, 36, 151),
                 replace_u32(original, 28, 1),
                 replace_u32(original, 16, 1)]
        for data in cases:
            self.rejected(data)

    def test_section_and_relocation_ranges_cannot_escape_segment_or_slice(self):
        data = make_macho()
        section = 32 + 72
        cases = [replace_u32(data, section + 48, len(data) + 10),
                 replace_u32(data, section + 48, 0),
                 replace_u32(data, section + 56, len(data) - 4),
                 replace_u32(replace_u32(data, section + 56, len(data) - 4), section + 60, 1),
                 replace_u32(data, section + 52, 64)]
        # A zero relocation count makes the offset irrelevant only when bounded.
        for index, bad in enumerate(cases):
            if index == 2:
                self.inspect(bad)
            else:
                self.rejected(bad)

    def test_dsym_address_only_sections_are_not_read_as_header_bytes(self):
        data = make_macho(file_type=10, debug=True)
        shadow = replace_u32(data, 32 + 72 + 48, 0)
        self.assertTrue(self.inspect(shadow)["evidence"]["debug_metadata_present"])
        self.rejected(replace_u32(shadow, 12, 6))
        # dSYM itself is debug metadata, even if only its address map remains.
        self.assertTrue(self.inspect(make_macho(file_type=10))["evidence"]["debug_metadata_present"])

    def test_object_section_alignment_is_relative_to_its_packed_segment(self):
        for bits in (32, 64):
            for endian in ("<", ">"):
                with self.subTest(bits=bits, endian=endian):
                    # clang's object writer adds an unpadded header/command
                    # prefix to aligned section-data offsets, not the reverse.
                    build = struct.pack(endian + "6I", 0x32, 24, 1, 0x000D0000, 0, 0)
                    data = make_macho(bits=bits, endian=endian, file_type=1, extra=build)
                    section = (28 + 56) if bits == 32 else (32 + 72)
                    offset_field = section + (40 if bits == 32 else 48)
                    offset = struct.unpack_from(endian + "I", data, offset_field)[0]
                    self.assertEqual(offset % 16, 8)
                    data = replace_u32(data, offset_field + 4, 4, endian)
                    self.assertTrue(self.inspect(data)["metadata_complete"])
                    # Linked-image alignment and all file/segment bounds remain
                    # enforced; the exception is specific to MH_OBJECT layout.
                    self.rejected(replace_u32(data, 12, 6, endian))
                    self.rejected(replace_u32(data, offset_field, len(data), endian))

    def test_symbol_string_and_section_indices_are_checked(self):
        data = make_macho()
        command = command_offset(data, 2)
        symoff, count, stroff, strsize = struct.unpack_from("<4I", data, command + 8)
        cases = [replace_u32(data, command + 8, len(data)),
                 replace_u32(data, command + 12, 262145),
                 replace_u32(data, command + 16, symoff),
                 replace_u32(data, symoff, strsize),
                 data[:-1] + b"X"]
        bad = bytearray(data)
        bad[symoff + 5] = 2
        cases.append(bytes(bad))
        bad = bytearray(data)
        bad[symoff + 4] = 0x5
        cases.append(bytes(bad))
        for bad in cases:
            self.rejected(bad)

    def test_indirect_symbol_second_name_is_slice_bounded(self):
        data = make_macho(symbols=[(b"_alias", 0xB, 0)])
        symoff = struct.unpack_from("<I", data, command_offset(data, 2) + 8)[0]
        bad = bytearray(data)
        struct.pack_into("<Q", bad, symoff + 8, len(data))
        self.rejected(bytes(bad))

    def test_duplicate_symbol_commands_are_rejected(self):
        self.rejected(make_macho(extra=struct.pack("<6I", 2, 24, 0, 0, 0, 0)))

    def test_dynamic_symbol_groups_and_auxiliary_tables_are_slice_bounded(self):
        groups = [0, 0, 0, 1, 1, 1] + [0] * 12
        command = struct.pack("<20I", 0xB, 80, *groups)
        self.assertFalse(any(self.inspect(make_macho(extra=command))["evidence"].values()))
        bad = groups[:]
        bad[4] = 0
        self.rejected(make_macho(extra=struct.pack("<20I", 0xB, 80, *bad)))
        bad = groups[:]
        bad[12:14] = [0, 1]
        self.rejected(make_macho(extra=struct.pack("<20I", 0xB, 80, *bad)))

    def test_zero_fill_sections_have_no_file_backed_payload(self):
        for kind in (1, 0xC, 0x12):
            with self.subTest(kind=kind):
                data = make_macho(section_flags=kind)
                data = replace_u32(data, 32 + 72 + 48, 0)
                self.assertTrue(self.inspect(data)["metadata_complete"])

    def test_metadata_read_and_symbol_budgets_fail_closed(self):
        data = make_macho()
        with patch.object(macho, "_MAX_READ_BYTES", 32):
            self.rejected(data)
        with patch.object(macho, "_MAX_SYMBOLS", 1):
            self.rejected(data)
        with patch.object(macho, "_MAX_STRING_BYTES", 1):
            self.rejected(data)

    def test_every_fat32_and_fat64_slice_is_audited(self):
        clean = make_macho()
        exposed = make_macho(cpu=0x0100000C, subtype=0, debug=True,
                             symbols=[(b"_private", 0xE, 1)])
        for bits in (32, 64):
            with self.subTest(bits=bits):
                report = self.inspect(make_fat([clean, exposed], bits=bits))
                self.assertEqual(report["container"], "fat" + str(bits))
                self.assertEqual(report["slice_count"], 2)
                self.assertTrue(report["evidence"]["debug_metadata_present"])
                self.assertTrue(report["evidence"]["private_symbols_present"])
                self.assertFalse(report["architectures"][0]["evidence"]["private_symbols_present"])
                self.assertTrue(report["architectures"][1]["evidence"]["private_symbols_present"])

    def test_fat_slices_can_mix_thin_widths_and_endianness(self):
        images = [make_macho(bits=32, endian=">", cpu=18),
                  make_macho(bits=64, endian="<", cpu=0x0100000C, subtype=0)]
        self.assertEqual(self.inspect(make_fat(images))["slice_count"], 2)

    def test_fat_directory_ranges_architecture_identity_and_padding_are_validated(self):
        original = make_fat([make_macho(), make_macho(cpu=0x0100000C, subtype=0)])
        first_offset = struct.unpack_from(">I", original, 16)[0]
        cases = [replace_u32(original, 4, 0, ">"),
                 replace_u32(original, 4, 0xFFFFFFFF, ">"),
                 replace_u32(original, 16, 8, ">"),
                 replace_u32(original, 20, len(original), ">"),
                 replace_u32(original, 24, 64, ">"),
                 replace_u32(original, 8, 18, ">"),
                 replace_u32(original, 36, first_offset, ">"),
                 replace_u32(original, first_offset, 0xCAFEBABE, ">"),
                 original + b"hidden",
                 b"\xbe\xba\xfe\xca" + original[4:]]
        duplicate = bytearray(original)
        duplicate[28:36] = original[8:16]
        cases.append(bytes(duplicate))
        padding = bytearray(original)
        padding[48] = 1
        cases.append(bytes(padding))
        fat64 = make_fat([make_macho()], bits=64)
        cases.append(replace_u32(fat64, 36, 1, ">"))
        for data in cases:
            self.rejected(data)

    def test_malformed_fat_never_downgrades_after_any_complete_native_header(self):
        original = make_fat([make_macho(), make_macho(cpu=0x0100000C, subtype=0, debug=True)])
        cases = []
        for index in (0, 1):
            entry = 8 + index * 20
            offset = struct.unpack_from(">I", original, entry + 8)[0]
            cases.extend([
                replace_u32(original, entry + 12, 0, ">"),  # empty slice
                replace_u32(original, entry + 8, len(original) + 1, ">"),
                replace_u32(original, entry, 18, ">"),  # CPU/header mismatch
                replace_u32(original, entry + 16, 63, ">"),
                replace_u32(original, offset, 0, ">"),  # corrupt one magic
            ])
        for data in cases:
            with self.subTest(header=data[:48]):
                with patch.object(macho, "_java_class", side_effect=AssertionError("Java downgrade attempted")) as java:
                    self.rejected(data)
                    java.assert_not_called()

    def test_bad_slice_size_cannot_hide_its_own_complete_native_header(self):
        original = make_fat([make_macho(debug=True)])
        for size in (0, 4, len(original) + 1):
            data = replace_u32(original, 20, size, ">")
            with self.subTest(size=size):
                with patch.object(macho, "_java_class", side_effect=AssertionError("Java downgrade attempted")) as java:
                    self.rejected(data)
                    java.assert_not_called()

    def test_fat_slice_cannot_borrow_another_slice_symbol_table(self):
        data = bytearray(make_fat([make_macho(), make_macho(cpu=0x0100000C, subtype=0)]))
        offset, size = struct.unpack_from(">II", data, 16)
        symbol_command = command_offset(bytes(data[offset:offset + size]), 2)
        struct.pack_into("<I", data, offset + symbol_command + 8, size + 16)
        self.rejected(bytes(data))

    def test_fat_audit_or_probe_budget_is_not_a_java_escape_hatch(self):
        data = make_fat([make_macho(), make_macho(cpu=0x0100000C, subtype=0)])
        with patch.object(macho, "_MAX_FAT_ARCHES", 1):
            self.rejected(data)
            self.assertIsNone(self.inspect(java_class(major=65, padding=3000)))
        with patch.object(macho, "_MAX_FAT_PROBE_ARCHES", 1):
            self.rejected(data)
        # A structurally valid fat wrapper wins before Java is ever attempted.
        with patch.object(macho, "_java_class", side_effect=AssertionError("Java fallback used")):
            self.inspect(data)

    def test_java_versions_preview_headers_and_large_attributes_are_not_macho(self):
        for major, minor in ((45, 3), (52, 0), (65, 0), (69, 65535), (73, 0)):
            for padding in (0, 3000):
                with self.subTest(major=major, minor=minor, padding=padding):
                    self.assertIsNone(self.inspect(java_class(major=major, minor=minor, padding=padding)))

    def test_truncated_malformed_or_over_budget_java_candidates_are_not_clean(self):
        data = java_class(padding=3000)
        malformed = [data[:8], data[:-1], data + b"\0",
                     data[:10] + b"\xFF" + data[11:],
                     data[:9] + b"\0" + data[10:]]
        for item in malformed:
            self.rejected(item)
        with patch.object(macho, "_MAX_JAVA_BYTES", 32):
            self.rejected(data)
        with patch.object(macho, "_MAX_JAVA_ITEMS", 1):
            self.rejected(data)

    def test_java_constant_pool_references_and_modified_utf8_are_verified(self):
        data = java_class()
        # First Class entry follows the seven-byte Utf8 entry.
        class_index = 10 + 1 + 2 + 7
        wrong_ref = bytearray(data)
        struct.pack_into(">H", wrong_ref, class_index + 1, 2)
        self.rejected(bytes(wrong_ref))
        invalid_utf8 = bytearray(data)
        invalid_utf8[13] = 0
        self.rejected(bytes(invalid_utf8))

    def test_path_wrapper_matches_stream_and_does_not_modify_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "owned.blob"
            data = make_macho(debug=True)
            path.write_bytes(data)
            self.assertEqual(macho.audit_macho(path), self.inspect(data))
            self.assertEqual(path.read_bytes(), data)


class MachOPortableTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "dist"
        self.root.mkdir()
        self.policy = self.base / "policy.json"
        self.policy.write_text('{"version":1}', encoding="utf-8")

    def scan(self, data):
        (self.root / "renamed.blob").write_bytes(data)
        return scan_release(self.root, self.policy)

    def test_arbitrary_suffix_receives_native_debug_and_private_symbol_findings(self):
        data = make_macho(debug=True, symbols=[(b"_private_formula", 0xE, 1)])
        report = self.scan(data)
        self.assertEqual({item["code"] for item in report["findings"]},
                         {"native_debug_metadata", "native_symbol_table"})
        self.assertTrue(all(item["format"] == "macho" for item in report["findings"]))
        self.assertEqual(report["checks"]["native_files_checked"], 1)
        self.assertTrue(report["checks"]["native_metadata_scan_completed"])
        self.assertNotIn("_private_formula", json.dumps(report))
        self.assertEqual((self.root / "renamed.blob").read_bytes(), data)

    def test_clean_macho_and_proven_java_have_distinct_native_counts(self):
        report = self.scan(make_macho())
        self.assertTrue(report["ok"], report["findings"])
        self.assertEqual(report["checks"]["native_files_checked"], 1)
        report = self.scan(java_class(padding=3000))
        self.assertTrue(report["ok"], report["findings"])
        self.assertEqual(report["checks"]["native_files_checked"], 0)

    def test_corrupt_or_unavailable_metadata_is_an_explicit_failed_check(self):
        for data in (make_macho(with_symtab=False), make_macho()[:-1], b"\xca\xfe\xba\xbe"):
            report = self.scan(data)
            self.assertEqual(report["findings"], [{
                "code": "native_metadata_unverifiable", "path": "renamed.blob",
                "format": "macho", "reason": "invalid_or_unsupported_metadata",
            }])
            self.assertFalse(report["checks"]["native_metadata_scan_completed"])

    def test_macho_and_java_members_share_zip_asar_recursion_without_extraction(self):
        data = archive([("app.asar", asar([
            ("resources/java.bin", java_class(padding=3000)),
            ("native/payload.data", make_macho(debug=True)),
        ]))])
        report = self.scan(data)
        self.assertEqual(report["checks"]["native_files_checked"], 1)
        finding = next(item for item in report["findings"] if item["code"] == "native_debug_metadata")
        self.assertEqual(finding["archive_members"], ["app.asar", "native/payload.data"])
        self.assertEqual([item.name for item in self.root.iterdir()], ["renamed.blob"])

    def test_explicitly_disabled_native_check_is_reported(self):
        self.policy.write_text('{"version":1,"check_native_metadata":false}', encoding="utf-8")
        report = self.scan(make_macho(debug=True))
        self.assertTrue(report["ok"])
        self.assertFalse(report["checks"]["native_metadata_checked"])
        self.assertEqual(report["checks"]["native_files_checked"], 0)


@unittest.skipUnless(shutil.which("javac"), "javac is required for the real Java class/JAR control")
class RealJavaCompatibilityTests(unittest.TestCase):
    def test_real_javac_class_and_jar_do_not_collide_with_macho_magic(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            source = base / "OwnedFixture.java"
            source.write_text(
                "public class OwnedFixture {\n"
                "  static final long LARGE = 1234567890123L;\n"
                "  static final double NUMBER = 1.25;\n"
                "  public static String value(int n) {\n"
                "    java.util.function.IntUnaryOperator op = x -> x + 2;\n"
                '    return "value=" + op.applyAsInt(n);\n'
                "  }\n}\n", encoding="utf-8")
            classes = base / "classes"
            classes.mkdir()
            subprocess.run([shutil.which("javac"), "-g", "-d", str(classes), str(source)],
                           check=True, capture_output=True, text=True, timeout=60)
            contents = [(str(path.relative_to(classes)).replace("\\", "/"), path.read_bytes())
                        for path in sorted(classes.rglob("*.class"))]
            self.assertTrue(contents)
            for name, data in contents:
                with self.subTest(name=name):
                    self.assertIsNone(macho.audit_macho_stream(io.BytesIO(data), len(data)))
            release = base / "release"
            release.mkdir()
            (release / "OwnedFixture.class").write_bytes(contents[0][1])
            (release / "owned.jar").write_bytes(archive(contents))
            policy = base / "policy.json"
            policy.write_text('{"version":1}', encoding="utf-8")
            report = scan_release(release, policy)
            self.assertTrue(report["ok"], report["findings"])
            self.assertEqual(report["checks"]["native_files_checked"], 0)
            self.assertEqual(report["checks"]["archives_scanned"], 1)




if __name__ == "__main__":
    unittest.main()
