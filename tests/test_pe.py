"""Synthetic PE images exercise bounded parsing without executing binaries."""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from releaseguard.pe import audit_pe


def make_pe(
    *,
    plus: bool = False,
    dll: bool = False,
    flags: int = 0,
    directories: dict[int, tuple[int, int]] | None = None,
    directory_count: int = 16,
    machine: int | None = None,
) -> bytearray:
    """Create one initialized section and optional table/certificate evidence."""
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    directory_base = 112 if plus else 96
    optional_size = directory_base + directory_count * 8
    struct.pack_into(
        "<HHIIIHH", data, 0x84,
        machine if machine is not None else (0x8664 if plus else 0x14C),
        1, 0, 0, 0, optional_size, 0x0002 | (0x2000 if dll else 0),
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B if plus else 0x10B)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<H", data, optional + 70, flags)
    struct.pack_into("<I", data, optional + directory_base - 4, directory_count)
    for index, (address, size) in (directories or {}).items():
        struct.pack_into("<II", data, optional + directory_base + index * 8, address, size)
    section = optional + optional_size
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    return data


class PEAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "sample.exe"

    def audit(self, data: bytes) -> dict:
        self.path.write_bytes(data)
        return audit_pe(self.path)

    def test_minimal_pe32_exe(self) -> None:
        report = self.audit(make_pe())
        self.assertEqual((report["machine"], report["format"], report["kind"]), ("x86", "PE32", "exe"))
        self.assertFalse(report["managed"])
        self.assertFalse(any(report["flags"].values()))
        self.assertFalse(any(report["evidence"].values()))
        self.assertTrue(report["warnings"])

    def test_pe32_plus_dll_with_all_evidence(self) -> None:
        data = make_pe(plus=True, dll=True, flags=0x4160, directories={
            4: (0x400, 0x20), 5: (0x1000, 12), 6: (0x1020, 28),
            10: (0x1040, 64), 14: (0x1080, 72),
        })
        struct.pack_into("<II", data, 0x8C, 0x440, 1)
        report = self.audit(data)
        self.assertEqual((report["machine"], report["format"], report["kind"]), ("x64", "PE32+", "dll"))
        self.assertTrue(report["managed"])
        self.assertTrue(all(report["flags"].values()))
        self.assertTrue(all(report["evidence"].values()))
        self.assertTrue(any("未验证 Authenticode" in value for value in report["notes"]))

    def test_complete_static_evidence_can_have_no_warnings(self) -> None:
        report = self.audit(make_pe(plus=True, flags=0x4160, directories={
            4: (0x400, 0x20), 5: (0x1000, 12), 10: (0x1040, 64),
        }))
        self.assertEqual(report["warnings"], [])
        self.assertEqual(len(report["notes"]), 3)
        self.assertTrue(any("静态头部" in item for item in report["notes"]))
        self.assertTrue(any("Guard 表" in item for item in report["notes"]))
        self.assertTrue(any("未验证 Authenticode" in item for item in report["notes"]))

    def test_actionable_warnings_remain_separate_from_notes(self) -> None:
        report = self.audit(make_pe(directories={6: (0x1020, 28), 14: (0x1080, 72)}))
        for text in ("DYNAMIC_BASE", "NX_COMPAT", "GUARD_CF", "调试目录", "CLR 目录", "未检测到嵌入式证书表"):
            self.assertTrue(any(text in item for item in report["warnings"]))
        self.assertEqual(len(report["notes"]), 1)

    def test_pe32_managed_exe(self) -> None:
        self.assertTrue(self.audit(make_pe(directories={14: (0x1000, 72)}))["managed"])

    def test_directory_count_can_be_zero(self) -> None:
        report = self.audit(make_pe(directory_count=0))
        self.assertFalse(report["managed"])
        self.assertFalse(any(report["evidence"].values()))

    def test_unknown_machine_is_reported(self) -> None:
        self.assertEqual(self.audit(make_pe(machine=0x9999))["machine"], "unknown-0x9999")

    def test_security_directory_uses_file_offset(self) -> None:
        report = self.audit(make_pe(directories={4: (0x400, 16)}))
        self.assertTrue(report["evidence"]["certificate_table_present"])

    def test_missing_cfg_metadata_is_warning(self) -> None:
        report = self.audit(make_pe(flags=0x4000))
        self.assertTrue(report["flags"]["guard_cf"])
        self.assertFalse(report["evidence"]["load_config_present"])
        self.assertTrue(any("Load Config" in item for item in report["warnings"]))

    def test_high_entropy_on_pe32_is_warning(self) -> None:
        report = self.audit(make_pe(flags=0x20))
        self.assertTrue(any("PE32 设置了 HIGH_ENTROPY_VA" in item for item in report["warnings"]))

    def test_accepts_string_path_and_does_not_modify_image(self) -> None:
        data = make_pe()
        self.path.write_bytes(data)
        audit_pe(str(self.path))
        self.assertEqual(self.path.read_bytes(), data)

    def test_missing_file_propagates_oserror(self) -> None:
        with self.assertRaises(OSError):
            audit_pe(self.path)

    def test_rejects_short_file_bad_magic_and_pe_signature(self) -> None:
        cases = [b"", b"MZ", bytes(64)]
        bad = make_pe()
        bad[0x80] = 0
        cases.append(bad)
        for data in cases:
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                self.audit(data)

    def test_rejects_pe_header_overlap_or_outside_file(self) -> None:
        for offset in (0, 63, 0xFFFFFFF0):
            data = make_pe()
            struct.pack_into("<I", data, 0x3C, offset)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.audit(data)

    def test_rejects_invalid_section_counts(self) -> None:
        for count in (0, 97, 65535):
            data = make_pe()
            struct.pack_into("<H", data, 0x86, count)
            with self.subTest(count=count), self.assertRaises(ValueError):
                self.audit(data)

    def test_rejects_non_image_and_unsupported_optional_magic(self) -> None:
        for offset, value in ((0x96, 0), (0x98, 0x107)):
            data = make_pe()
            struct.pack_into("<H", data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.audit(data)

    def test_rejects_short_or_truncated_optional_header(self) -> None:
        for size in (0, 1, 90, 65535):
            data = make_pe()
            struct.pack_into("<H", data, 0x94, size)
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.audit(data)

    def test_rejects_directory_count_outside_optional_header(self) -> None:
        data = make_pe()
        struct.pack_into("<I", data, 0x98 + 92, 0xFFFFFFFF)
        with self.assertRaises(ValueError):
            self.audit(data)

    def test_rejects_size_of_headers_outside_file_or_before_section_table(self) -> None:
        for size in (0x100, 0x10000):
            data = make_pe()
            struct.pack_into("<I", data, 0x98 + 60, size)
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.audit(data)

    def test_rejects_section_raw_data_outside_file_or_in_headers(self) -> None:
        for raw_offset, raw_size in ((0x100, 0x200), (0x500, 0x200), (0xFFFFFFFF, 1)):
            data = make_pe()
            struct.pack_into("<II", data, 0x98 + 224 + 16, raw_size, raw_offset)
            with self.subTest(offset=raw_offset), self.assertRaises(ValueError):
                self.audit(data)

    def test_rejects_virtual_range_overflow(self) -> None:
        data = make_pe()
        struct.pack_into("<I", data, 0x98 + 224 + 12, 0xFFFFFF00)
        with self.assertRaises(ValueError):
            self.audit(data)

    def test_rejects_unmapped_or_incomplete_audited_directories(self) -> None:
        for index in (5, 6, 10, 14):
            for entry in ((0x3000, 12), (0, 12), (0x1000, 0), (0x11F0, 0x20), (0xFFFFFFF0, 0x40)):
                with self.subTest(index=index, entry=entry), self.assertRaises(ValueError):
                    self.audit(make_pe(directories={index: entry}))

    def test_rejects_directory_data_in_virtual_only_section_tail(self) -> None:
        data = make_pe(directories={14: (0x1200, 72)})
        struct.pack_into("<I", data, 0x98 + 224 + 8, 0x400)
        with self.assertRaises(ValueError):
            self.audit(data)

    def test_rejects_unaligned_or_out_of_bounds_certificate_table(self) -> None:
        for entry in ((0x401, 16), (0x5F8, 16), (0, 16)):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                self.audit(make_pe(directories={4: entry}))

    def test_rejects_invalid_coff_symbol_range(self) -> None:
        for address, count in ((0, 1), (0x400, 0), (0x100, 1), (0x5FF, 1), (0x400, 0xFFFFFFFF)):
            data = make_pe()
            struct.pack_into("<II", data, 0x8C, address, count)
            with self.subTest(address=address, count=count), self.assertRaises(ValueError):
                self.audit(data)

    def test_never_requests_unbounded_or_payload_reads(self) -> None:
        self.path.write_bytes(make_pe())
        original_open = Path.open
        sizes = []

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
                sizes.append(size)
                return self.stream.read(size)

        def tracked_open(path, *args, **kwargs):
            return Reader(original_open(path, *args, **kwargs))

        with patch.object(Path, "open", tracked_open):
            audit_pe(self.path)
        self.assertEqual(sizes, [64, 24, 224, 40])
        self.assertTrue(all(0 <= size <= 65535 for size in sizes))


if __name__ == "__main__":
    unittest.main()
