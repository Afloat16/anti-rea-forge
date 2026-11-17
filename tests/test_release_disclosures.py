"""Release-wide metadata disclosure controls for ordinary tool-readable inputs."""

from __future__ import annotations

import codecs
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from releaseguard import distribution
from releaseguard.core import GuardError
from releaseguard.elf import audit_elf, audit_elf_stream
from releaseguard.pe import audit_pe, audit_pe_stream
from tests.test_distribution import archive
from tests.test_elf import make_elf
from tests.test_pe import make_debug_pe, make_pe


def source_map() -> bytes:
    # Standard JSON escaping changes bytes, not the field exposed to a map reader.
    return (b'{"ver\\u0073ion":3,"sources":["private.ts"],"names":[],"mappings":"AAAA",'
            b'"sourcesCont\\u0065nt":["export const internal = 73981;"]}')


class ReleaseDisclosureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "dist"
        self.root.mkdir()
        self.policy = self.base / "policy.json"
        self.configure()

    def configure(self, **options):
        self.policy.write_text(json.dumps({"version": 1, **options}), encoding="utf-8")

    def put(self, data, name="artifact.bin"):
        (self.root / name).write_bytes(data)

    def scan(self):
        return distribution.scan_release(self.root, self.policy)

    def test_renamed_json_map_with_escaped_keys_is_detected_without_content_echo(self):
        self.put(source_map())
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertEqual(report["findings"], [
            {"code": "source_map_structure", "path": "artifact.bin", "kind": "flat"},
        ])
        self.assertNotIn("internal = 73981", json.dumps(report))
        self.assertTrue(report["checks"]["source_map_structures_checked"])
        self.assertTrue(report["checks"]["source_map_scan_completed"])

    def test_source_map_metadata_without_embedded_source_is_also_detected(self):
        self.put(b'{"version":3,"sources":["/private/build/file.ts"],"names":[],"mappings":""}')
        self.assertEqual(self.scan()["findings"][0]["code"], "source_map_structure")

    def test_equivalent_numeric_version_spellings_are_recognized(self):
        for version in (b"3.0", b"3e0", b"3.00e+0", b"30e-1", b"300000000000000000e-17"):
            with self.subTest(version=version):
                self.put(source_map().replace(b'ion":3,', b'ion":' + version + b','))
                report = self.scan()
                self.assertFalse(report["ok"])
                self.assertEqual(report["findings"][0]["code"], "source_map_structure")

    def test_boolean_versions_are_not_treated_as_numeric_map_versions(self):
        for version in (b"true", b"false"):
            with self.subTest(version=version):
                self.put(source_map().replace(b'ion":3,', b'ion":' + version + b','))
                self.assertTrue(self.scan()["ok"])

    def test_nonfinite_json_numbers_are_unverifiable(self):
        for version in (b"NaN", b"Infinity", b"-Infinity", b"1e999", b"-1e999"):
            with self.subTest(version=version):
                self.put(source_map().replace(b'ion":3,', b'ion":' + version + b','))
                report = self.scan()
                self.assertFalse(report["ok"])
                self.assertEqual(report["findings"][0]["code"], "source_map_unverifiable")
                self.assertFalse(report["checks"]["source_map_scan_completed"])

    def test_json_maps_support_boms_wide_encodings_and_xssi(self):
        text = source_map().decode("ascii")
        cases = [text.encode(encoding) for encoding in distribution._ENCODINGS]
        cases += [bom + text.encode(encoding) for bom, encoding in (
            (codecs.BOM_UTF8, "utf-8"), (codecs.BOM_UTF16_LE, "utf-16-le"),
            (codecs.BOM_UTF16_BE, "utf-16-be"), (codecs.BOM_UTF32_LE, "utf-32-le"),
            (codecs.BOM_UTF32_BE, "utf-32-be"),
        )]
        cases += [b")]}'\n" + source_map(), codecs.BOM_UTF8 + b")]}'\n" + source_map()]
        for data in cases:
            with self.subTest(prefix=data[:8]):
                self.put(data)
                self.assertIn("source_map_structure", {f["code"] for f in self.scan()["findings"]})

    def test_indexed_map_and_inline_sections_are_recognized(self):
        doc = {"version": 3, "sections": [{"offset": {"line": 0, "column": 0},
                                          "map": json.loads(source_map())}]}
        self.put(json.dumps(doc).replace("sourcesContent", "sourcesCont\\u0065nt").encode())
        findings = self.scan()["findings"]
        self.assertEqual({f["kind"] for f in findings if f["code"] == "source_map_structure"},
                         {"flat", "indexed"})

    def test_nested_zip_runs_the_same_structural_check_with_exact_member_chain(self):
        self.put(archive([("inner.zip", archive([("renamed.data", source_map())]))]), "bundle.zip")
        report = self.scan()
        self.assertTrue(any(f["code"] == "source_map_structure"
                            and f["archive_members"] == ["inner.zip", "renamed.data"]
                            for f in report["findings"]))
        self.assertEqual([p.name for p in self.root.iterdir()], ["bundle.zip"])

    def test_ordinary_json_and_javascript_blocks_do_not_become_source_maps(self):
        for data in (b'{"version":3,"sources":"public endpoint","mappings":false}',
                     b'{ const value = 42; }', b'{"configuration":{"version":1}}'):
            with self.subTest(data=data):
                self.put(data)
                self.assertTrue(self.scan()["ok"])

    def test_source_map_checks_can_be_explicitly_disabled(self):
        self.configure(check_source_maps=False)
        self.put(source_map())
        report = self.scan()
        self.assertTrue(report["ok"])
        self.assertFalse(report["checks"]["source_map_structures_checked"])

    def test_json_beyond_semantic_budget_is_unverifiable_even_after_long_padding(self):
        for prefix in (b"", b" " * 8192):
            with self.subTest(padding=len(prefix)):
                self.put(prefix + source_map())
                with patch.object(distribution, "MAX_DOCUMENT_BYTES", 32):
                    report = self.scan()
                self.assertFalse(report["ok"])
                self.assertEqual(report["findings"][0]["reason"], "json_byte_limit")
                self.assertFalse(report["checks"]["source_map_scan_completed"])

    def test_non_json_large_payload_is_not_reported_as_an_unparsed_map(self):
        self.put(b"\x01" + b"x" * 8192)
        with patch.object(distribution, "MAX_DOCUMENT_BYTES", 32):
            self.assertTrue(self.scan()["ok"])

    def test_ambiguous_json_is_unverifiable_without_echoing_fields(self):
        self.put(b'{"private-field":1,"private-field":2}')
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertEqual(report["findings"][0]["code"], "source_map_unverifiable")
        self.assertNotIn("private-field", json.dumps(report))

    def test_json_node_and_nesting_limits_fail_closed(self):
        cases = [({"items": list(range(12))}, "_MAX_JSON_NODES", 8),
                 ({"one": {"two": {"three": {}}}}, "_MAX_JSON_DEPTH", 2),
                 ({str(i): 0 for i in range(12)}, "_MAX_JSON_NODES", 8)]
        for document, field, limit in cases:
            with self.subTest(field=field, document=document):
                self.put(json.dumps(document).encode())
                with patch.object(distribution, field, limit):
                    report = self.scan()
                self.assertEqual(report["findings"][0]["reason"], "json_structure_limit")
                self.assertFalse(report["checks"]["source_map_scan_completed"])

    def test_long_xssi_prefix_does_not_silently_skip_inspection(self):
        self.put(b")]}'" + b" " * 4096 + b"\n" + source_map())
        report = self.scan()
        self.assertEqual(report["findings"][0]["reason"], "json_prefix_limit")
        self.assertFalse(report["ok"])

    def test_all_native_payloads_are_checked_regardless_of_extension(self):
        self.put(make_elf(entries=[(".debug_info", 1), (".renamed", 2)]), "linux.data")
        self.put(make_debug_pe([(2, b"RSDS-private-path")]), "windows.data")
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"]["native_files_checked"], 2)
        self.assertEqual({(f["path"], f["code"], f["format"]) for f in report["findings"]}, {
            ("linux.data", "native_debug_metadata", "elf"),
            ("linux.data", "native_symbol_table", "elf"),
            ("windows.data", "native_debug_metadata", "pe"),
        })
        self.assertNotIn("private-path", json.dumps(report))

    def test_pe_coff_symbols_are_checked_in_nested_zip_members(self):
        data = make_pe(plus=True)
        struct.pack_into("<II", data, 0x8C, 0x440, 1)
        self.put(archive([("inner.zip", archive([("library.data", data)]))]), "bundle.zip")
        report = self.scan()
        finding = next(f for f in report["findings"] if f["code"] == "native_symbol_table")
        self.assertEqual(finding["archive_members"], ["inner.zip", "library.data"])
        self.assertEqual(report["checks"]["native_files_checked"], 1)

    def test_public_dynamic_symbols_and_nondebug_pe_records_are_allowed(self):
        self.put(make_elf(entries=[(".dynsym", 11)]), "library.so")
        self.put(make_debug_pe([(16, b""), (20, struct.pack("<I", 1))]), "app.exe")
        report = self.scan()
        self.assertTrue(report["ok"])
        self.assertEqual(report["checks"]["native_files_checked"], 2)
        self.assertTrue(report["checks"]["native_metadata_scan_completed"])

    def test_missing_elf_section_table_cannot_be_mistaken_for_stripped(self):
        self.put(make_elf(no_sections=True))
        report = self.scan()
        self.assertEqual(report["findings"], [{"code": "native_metadata_unverifiable",
                                             "path": "artifact.bin", "format": "elf",
                                             "reason": "section_table_missing"}])
        self.assertFalse(report["checks"]["native_metadata_scan_completed"])

    def test_missing_elf_section_names_fail_closed_but_still_report_known_symbols(self):
        data = make_elf(entries=[(".symtab", 2)])
        struct.pack_into("<H", data, 62, 0)
        for index in (1, 2):
            struct.pack_into("<I", data, 0x400 + index * 64, 0)
        self.put(data)
        report = self.scan()
        self.assertEqual({f["code"] for f in report["findings"]},
                         {"native_metadata_unverifiable", "native_symbol_table"})
        self.assertTrue(any(f.get("reason") == "section_names_missing" for f in report["findings"]))

    def test_malformed_recognized_native_formats_are_unverifiable(self):
        for data in (b"MZmalformed", b"\x7fELFmalformed"):
            with self.subTest(prefix=data[:4]):
                self.put(data)
                report = self.scan()
                self.assertFalse(report["ok"])
                self.assertEqual(report["findings"][0]["code"], "native_metadata_unverifiable")
                self.assertFalse(report["checks"]["native_metadata_scan_completed"])

    def test_native_metadata_policy_can_be_explicitly_disabled(self):
        self.configure(check_native_metadata=False)
        self.put(make_elf(entries=[(".debug_info", 1), (".symtab", 2)]))
        report = self.scan()
        self.assertTrue(report["ok"])
        self.assertFalse(report["checks"]["native_metadata_checked"])
        self.assertEqual(report["checks"]["native_files_checked"], 0)

    def test_native_metadata_option_rejects_nonboolean_values(self):
        self.put(b"ordinary")
        for value in (0, 1, None, "false"):
            with self.subTest(value=value):
                self.configure(check_native_metadata=value)
                with self.assertRaises(GuardError):
                    self.scan()

    def test_stream_parsers_match_path_results_and_do_not_close_the_stream(self):
        for data, path_reader, stream_reader in (
            (make_elf(entries=[(".debug_info", 1)]), audit_elf, audit_elf_stream),
            (make_debug_pe([(2, b"RSDS")]), audit_pe, audit_pe_stream),
        ):
            with self.subTest(reader=stream_reader.__name__):
                path = self.base / "native.fixture"
                path.write_bytes(data)
                stream = io.BytesIO(data)
                stream.seek(5)
                self.assertEqual(path_reader(path), stream_reader(stream, len(data)))
                self.assertFalse(stream.closed)
                with self.assertRaises(ValueError):
                    stream_reader(stream, len(data) // 2)
                for invalid in (True, -1, "100"):
                    with self.assertRaises(ValueError):
                        stream_reader(stream, invalid)


if __name__ == "__main__":
    unittest.main()
