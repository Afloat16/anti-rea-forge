"""Semantic map inspection across Unicode prefixes and JSON root containers."""

from __future__ import annotations

import codecs
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from releaseguard import distribution
from tests.test_asar import asar, zip_archive


ENCODINGS = (("utf-8", codecs.BOM_UTF8), ("utf-16-le", codecs.BOM_UTF16_LE),
             ("utf-16-be", codecs.BOM_UTF16_BE), ("utf-32-le", codecs.BOM_UTF32_LE),
             ("utf-32-be", codecs.BOM_UTF32_BE))
OWNED_SOURCE = "const owned_private_pricing_rate = 73981;"
MAP = ('{"ver\\u0073ion":3,"sources":["owned.ts"],"names":[],"mappings":"AAAA",'
       '"sourcesCont\\u0065nt":[' + json.dumps(OWNED_SOURCE) + "]}")


class SourceMapEncodingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned source map encodings ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "release"
        self.root.mkdir()
        self.target = self.root / "renamed.data"
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="utf-8")

    def scan(self, payload):
        self.target.write_bytes(payload)
        report = distribution.scan_release(self.root, self.policy)
        self.assertEqual(self.target.read_bytes(), payload)
        self.assertNotIn(OWNED_SOURCE, json.dumps(report))
        return report

    def test_xssi_maps_in_each_encoding_with_and_without_bom(self):
        for encoding, bom in ENCODINGS:
            for prefix in (b"", bom):
                with self.subTest(encoding=encoding, bom=bool(prefix)):
                    text = ")]}'\r\n" + MAP
                    payload = prefix + text.encode(encoding)
                    decoded = payload.decode(encoding).lstrip("\ufeff").split("\n", 1)[1]
                    self.assertEqual(json.loads(decoded)["sourcesContent"], [OWNED_SOURCE])
                    report = self.scan(payload)
                    self.assertFalse(report["ok"])
                    self.assertEqual(report["findings"], [{
                        "code": "source_map_structure", "path": self.target.name, "kind": "flat"}])

    def test_root_arrays_apply_the_same_map_search_as_arrays_in_objects(self):
        for encoding, bom in ENCODINGS:
            for document in ("[" + MAP + "]", '[null,[{"map":' + MAP + "}]]"):
                with self.subTest(encoding=encoding, document=document[:8]):
                    report = self.scan(bom + document.encode(encoding))
                    self.assertFalse(report["ok"])
                    self.assertEqual(report["findings"][0]["code"], "source_map_structure")

    def test_unicode_map_inside_zip_and_asar_is_inspected_by_the_same_rules(self):
        for encoding, bom in ENCODINGS:
            payload = bom + (")]}'\n[" + MAP + "]").encode(encoding)
            for wrapper in (lambda value: zip_archive("sources.data", value),
                            lambda value: asar([("sources.data", value)])):
                with self.subTest(encoding=encoding, wrapper=wrapper):
                    report = self.scan(wrapper(payload))
                    self.assertEqual(report["findings"], [{
                        "code": "source_map_structure", "path": self.target.name, "kind": "flat",
                        "archive_members": ["sources.data"]}])

    def test_wide_prefix_limit_and_json_byte_budget_fail_closed(self):
        for encoding, bom in ENCODINGS:
            with self.subTest(encoding=encoding):
                report = self.scan(bom + (")]}'" + " " * 4096 + "\n" + MAP).encode(encoding))
                self.assertFalse(report["ok"])
                self.assertFalse(report["checks"]["source_map_scan_completed"])
                self.assertEqual(report["findings"][0]["reason"], "json_prefix_limit")
                with patch.object(distribution, "MAX_DOCUMENT_BYTES", 32):
                    report = self.scan(bom + (" " * 8192 + "[" + MAP + "]").encode(encoding))
                self.assertFalse(report["ok"])
                self.assertEqual(report["findings"][0]["reason"], "json_byte_limit")

    def test_root_array_structure_budgets_and_duplicate_keys_are_enforced(self):
        for document, field, limit in (("[" + ",".join("0" for _ in range(20)) + "]", "_MAX_JSON_NODES", 8),
                                       ("[[[[]]]]", "_MAX_JSON_DEPTH", 2)):
            with self.subTest(field=field):
                with patch.object(distribution, field, limit):
                    report = self.scan(document.encode())
                self.assertEqual(report["findings"][0]["reason"], "json_structure_limit")
        report = self.scan(b'[{"private-field":1,"private-field":2}]')
        self.assertEqual(report["findings"][0]["reason"], "ambiguous_or_overdeep_json")
        self.assertNotIn("private-field", json.dumps(report))

    def test_whitespace_crossing_read_boundaries_and_unicode_xssi_text(self):
        for encoding, bom in ENCODINGS:
            for text in (" " * 8191 + MAP, ")]}' ignored owned text \u4e2d\u6587\n " + MAP):
                with self.subTest(encoding=encoding, prefix=text[:8]):
                    report = self.scan(bom + text.encode(encoding))
                    self.assertEqual(report["findings"][0]["code"], "source_map_structure")

    def test_newline_bytes_inside_wide_characters_are_not_xssi_delimiters(self):
        false_newlines = {"utf-16-le": "\u0a00\x00", "utf-16-be": "\x00\u0a00",
                          "utf-32-le": "\U000a0000\x00", "utf-32-be": "\x00\U000a0000"}
        for encoding, bom in ENCODINGS[1:]:
            with self.subTest(encoding=encoding):
                prefix = ")]}'" + false_newlines[encoding]
                self.assertEqual(self.scan(bom + (prefix + "\n" + MAP).encode(encoding))["findings"][0]["code"],
                                 "source_map_structure")
                report = self.scan(bom + (prefix + " " * 4096 + "\n" + MAP).encode(encoding))
                self.assertFalse(report["ok"])
                self.assertEqual(report["findings"][0]["reason"], "json_prefix_limit")

    def test_ordinary_arrays_and_nonjson_scripts_remain_compatible(self):
        for text in ('[1,"public",{"version":1}]', "[publicCall(), 1]", "{ const x = 3; }"):
            for encoding, bom in ENCODINGS:
                with self.subTest(text=text, encoding=encoding):
                    self.assertTrue(self.scan(bom + text.encode(encoding))["ok"])

    def test_source_map_checks_can_still_be_explicitly_disabled(self):
        self.policy.write_text('{"version":1,"check_source_maps":false}', encoding="utf-8")
        report = self.scan(codecs.BOM_UTF16_LE + (")]}'\n[" + MAP + "]").encode("utf-16-le"))
        self.assertTrue(report["ok"])
        self.assertFalse(report["checks"]["source_map_structures_checked"])


if __name__ == "__main__":
    unittest.main()
