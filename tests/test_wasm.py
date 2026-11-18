"""Owned WebAssembly fixtures and conservative section-envelope regressions."""

from __future__ import annotations

import io
import json
import unittest
from unittest.mock import patch

from releaseguard import wasm


HEADER = b"\0asm\1\0\0\0"
PRIVATE_FUNCTION = "owned_private_margin_formula"
PRIVATE_MODULE = "owned_private_pricing_module"
PRIVATE_LOCAL = "owned_private_quantity"


def uleb(value: int) -> bytes:
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result) + bytes((value,))


def string(value: str) -> bytes:
    data = value.encode("utf-8")
    return uleb(len(data)) + data


def section(section_id: int, data: bytes) -> bytes:
    return bytes((section_id,)) + uleb(len(data)) + data


def custom(name: str, payload: bytes = b"") -> bytes:
    return section(0, string(name) + payload)


def owned_core() -> bytes:
    # One owned function quote(i32)->i32: quantity * 7 + 3.
    body = bytes.fromhex("00200041076c41036a0b")
    return (HEADER + section(1, bytes.fromhex("0160017f017f"))
            + section(3, b"\1\0") + section(7, b"\1" + string("quote") + b"\0\0")
            + section(10, b"\1" + uleb(len(body)) + body))


def owned_names() -> bytes:
    module = section(0, string(PRIVATE_MODULE))
    functions = section(1, b"\1\0" + string(PRIVATE_FUNCTION))
    locals_ = section(2, b"\1\0\1\0" + string(PRIVATE_LOCAL))
    return custom("name", module + functions + locals_)


def owned_module() -> bytes:
    # These DWARF-custom payloads are deliberate synthetic markers, not a claim
    # to encode a valid DWARF compilation unit. Engines ignore custom payloads.
    return (owned_core() + owned_names()
            + custom(".debug_info", b"owned-private-source.c\0")
            + custom(".debug_line", b"owned-private-line-marker\0")
            + custom("sourceMappingURL", string("private-source-map.json"))
            + custom("external_debug_info", string("private-original.wasm"))
            + custom("public_notice", b"Copyright: owned fixture"))


class WasmMetadataTests(unittest.TestCase):
    def audit(self, data):
        handle = io.BytesIO(data)
        report = wasm.audit_wasm_stream(handle, len(data))
        self.assertFalse(handle.closed)
        self.assertEqual(handle.getvalue(), data)
        return report

    def test_owned_module_reports_fixed_categories_without_private_text(self):
        report = self.audit(owned_module())
        self.assertEqual(report["evidence"], {"debug_metadata_present": True, "private_symbols_present": True})
        self.assertEqual(report["private_sections"], {
            "dwarf": 2, "external-debug-info": 1, "name": 1, "source-map-url": 1})
        self.assertEqual(report["sections_checked"], 10)
        self.assertEqual(report["custom_sections_checked"], 6)
        self.assertFalse(report["checks"]["full_module_validation_performed"])
        for value in (PRIVATE_FUNCTION, PRIVATE_LOCAL, PRIVATE_MODULE, "owned-private-source.c", "public_notice"):
            self.assertNotIn(value, json.dumps(report))

    def test_code_exports_and_unknown_customs_are_not_claimed_private(self):
        # Runtime/link metadata is retained, not removed on a debug-name guess.
        data = owned_core() + b"".join(custom(name, b"public") for name in (
            "producers", "target_features", "build_id", "linking", "reloc.CODE",
            "dylink.0", "copyright", "namex", "Name", ".debug", "other_private_annotation"))
        report = self.audit(data)
        self.assertFalse(any(report["evidence"].values()))
        self.assertEqual(report["private_sections"], {})
        self.assertEqual(report["custom_sections_checked"], 11)

    def test_empty_core_module_and_customs_between_standard_sections(self):
        self.assertEqual(self.audit(HEADER)["sections_checked"], 0)
        core = owned_core()
        data = core[:8] + custom("public_notice") + core[8:] + custom("public_notice", b"second")
        self.assertEqual(self.audit(data)["sections_checked"], 6)

    def test_padded_u32_encodings_remain_accepted_and_unchanged(self):
        # The core format permits an unsigned integer to occupy up to ceil(N/7)
        # bytes; valid padding is not an overflow or a different section.
        data = HEADER + b"\0\x89\x80\x80\x80\0\x84\x80\x80\x80\0name"
        report = self.audit(data)
        self.assertTrue(report["evidence"]["private_symbols_present"])

    def test_recognized_debug_customs_are_detected_even_with_no_payload(self):
        for name, kind in (("name", "name"), (".debug_info", "dwarf"), (".zdebug_line", "dwarf"),
                           ("sourceMappingURL", "source-map-url"), ("external_debug_info", "external-debug-info")):
            with self.subTest(name=name):
                self.assertEqual(self.audit(HEADER + custom(name))["private_sections"], {kind: 1})

    def test_supported_order_includes_tag_and_data_count(self):
        order = (1, 2, 3, 4, 5, 13, 6, 7, 8, 9, 12, 10, 11)
        self.assertEqual(self.audit(HEADER + b"".join(section(i, b"\0") for i in order))["sections_checked"], 13)
        # Only envelopes are being tested here, not section payload semantics.
        for order in ((10, 12), (6, 13), (3, 2), (1, 1)):
            with self.subTest(order=order), self.assertRaises(ValueError):
                self.audit(HEADER + b"".join(section(i, b"\0") for i in order))

    def test_bad_headers_components_and_unsupported_sections_fail(self):
        for data in (b"", b"\0asm", HEADER[:7], b"\0asm\x0d\0\1\0", b"bad!\1\0\0\0",
                     HEADER + section(14, b"\0"), HEADER + section(255, b"\0")):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.audit(data)

    def test_invalid_sizes_overflow_and_truncated_leb_fail(self):
        for tail in (b"\0", b"\0\x80", b"\0\xff\xff\xff\xff\x10", b"\0\x80\x80\x80\x80\x80\0",
                     b"\1\0", b"\1\5\0", b"\0\1\2", b"\0\5\x80\x80\x80\x80\x80"):
            with self.subTest(tail=tail), self.assertRaises(ValueError):
                self.audit(HEADER + tail)

    def test_custom_name_utf8_nul_and_duplicate_private_names_fail(self):
        for data in (HEADER + section(0, b"\1\xff"), HEADER + custom("name\0suffix"),
                     HEADER + custom("name") + custom("name"),
                     HEADER + custom(".debug_info") + custom(".debug_info")):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.audit(data)
        self.assertFalse(any(self.audit(HEADER + custom("\u516c\u5f00\u63cf\u8ff0"))["evidence"].values()))

    def test_name_and_section_budgets_fail_without_payload_reads(self):
        cases = (("_MAX_SECTIONS", 2, HEADER + custom("a") * 3),
                 ("_MAX_CUSTOM_NAME_BYTES", 3, HEADER + custom("long")),
                 ("_MAX_TOTAL_NAME_BYTES", 5, HEADER + custom("abc") + custom("def")))
        for field, maximum, data in cases:
            with self.subTest(field=field), patch.object(wasm, field, maximum), self.assertRaises(ValueError):
                self.audit(data)

    def test_inspector_never_reads_custom_payload_or_code_body(self):
        data = owned_core() + custom("opaque", b"x" * (2 << 20))

        class BoundedReads(io.BytesIO):
            def read(self, size=-1):
                if size < 0 or size > 4096:
                    raise AssertionError("Unbounded or payload-sized metadata read")
                return super().read(size)

        self.assertEqual(wasm.audit_wasm_stream(BoundedReads(data), len(data))["custom_sections_checked"], 1)

    def test_reported_size_and_short_reader_cannot_hide_truncation(self):
        for size in (-1, True, 4.0, "8"):
            with self.subTest(size=size), self.assertRaises(ValueError):
                wasm.audit_wasm_stream(io.BytesIO(HEADER), size)
        data = HEADER + custom("name")
        with self.assertRaises(ValueError):
            wasm.audit_wasm_stream(io.BytesIO(data[:-1]), len(data))


if __name__ == "__main__":
    unittest.main()
