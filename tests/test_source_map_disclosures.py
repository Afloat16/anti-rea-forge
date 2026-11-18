"""Original text stays disclosed even when its source-map mappings are invalid."""

from __future__ import annotations

import codecs
import json
from pathlib import Path
import tempfile
import unittest

from releaseguard.distribution import scan_release
from releaseguard.split_maps import split_source_maps
from tests.test_asar import asar, zip_archive


SOURCE = "// owned source-only canary rg_partial_map_7d1982\nexport const unpublishedRate = 79;\n"
ENCODINGS = (("utf-8", codecs.BOM_UTF8), ("utf-16-le", codecs.BOM_UTF16_LE),
             ("utf-16-be", codecs.BOM_UTF16_BE), ("utf-32-le", codecs.BOM_UTF32_LE),
             ("utf-32-be", codecs.BOM_UTF32_BE))


def encoded(document) -> str:
    return json.dumps(document, ensure_ascii=False).replace("sourcesContent", "sourcesCont\\u0065nt")


class SourceMapDisclosureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned incomplete map ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.release = self.work / "release"
        self.release.mkdir()
        self.target = self.release / "renamed.data"
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="ascii")

    def scan(self, payload: bytes):
        self.target.write_bytes(payload)
        report = scan_release(self.release, self.policy)
        self.assertEqual(self.target.read_bytes(), payload)
        self.assertNotIn(SOURCE, json.dumps(report))
        return report

    def assert_content_detected(self, report):
        self.assertFalse(report["ok"])
        self.assertTrue(report["checks"]["source_map_scan_completed"])
        self.assertTrue(any(row["code"] == "source_map_marker"
                            and row.get("representation") == "json-decoded-key"
                            for row in report["findings"]), report["findings"])

    def test_missing_or_invalid_mappings_do_not_hide_recoverable_original_text(self):
        for mappings in (None, 17, [], {}, False):
            document = {"version": 3, "sources": ["owned.ts"], "sourcesContent": [SOURCE]}
            if mappings is not None:
                document["mappings"] = mappings
            with self.subTest(mappings=mappings):
                payload = encoded(document).encode()
                # Independent ordinary decoding establishes the actual disclosure.
                self.assertEqual(json.loads(payload)["sourcesContent"], [SOURCE])
                self.assert_content_detected(self.scan(payload))

    def test_a_version_or_sources_field_is_not_needed_to_recover_embedded_text(self):
        for extra in ({}, {"version": 2}, {"version": "3"}, {"sources": "owned.ts"}):
            with self.subTest(extra=extra):
                document = {**extra, "sourcesContent": [SOURCE]}
                payload = encoded(document).encode()
                self.assertEqual(json.loads(payload)["sourcesContent"][0], SOURCE)
                self.assert_content_detected(self.scan(payload))

    def test_escaped_content_key_has_the_same_conservative_meaning_as_a_raw_key(self):
        for value in (None, [], "", 17, [None], [SOURCE]):
            with self.subTest(value=value):
                document = {"sourcesContent": value}
                ordinary = self.scan(json.dumps(document).encode())
                self.assertFalse(ordinary["ok"])
                self.assert_content_detected(self.scan(encoded(document).encode()))

    def test_nested_json_objects_and_arrays_receive_the_same_decoded_key_check(self):
        for document in ([{"sourcesContent": [SOURCE]}],
                         {"build": [None, {"debug": {"sourcesContent": [SOURCE]}}]}):
            with self.subTest(container=type(document).__name__):
                self.assert_content_detected(self.scan(encoded(document).encode()))

    def test_wide_encodings_and_xssi_keep_the_decoded_key_visible(self):
        text = encoded({"sourcesContent": [SOURCE]})
        for encoding, bom in ENCODINGS:
            for prefix in (b"", bom):
                with self.subTest(encoding=encoding, bom=bool(prefix)):
                    payload = prefix + (")]}'\n" + text).encode(encoding)
                    self.assert_content_detected(self.scan(payload))

    def test_supported_archives_do_not_restore_the_escaped_key_gap(self):
        payload = encoded({"sourcesContent": [SOURCE]}).encode()
        for wrapped, chain in (
            (zip_archive("sources.data", payload), ["sources.data"]),
            (asar([("sources.data", payload)]), ["sources.data"]),
            (zip_archive("app.asar", asar([("sources.data", payload)])), ["app.asar", "sources.data"]),
        ):
            with self.subTest(chain=chain):
                report = self.scan(wrapped)
                self.assert_content_detected(report)
                findings = [row for row in report["findings"] if row["code"] == "source_map_marker"]
                self.assertTrue(any(row.get("archive_members") == chain for row in findings))

    def test_disabling_source_map_checks_does_not_disable_private_key_checks(self):
        self.policy.write_text('{"version":1,"check_source_maps":false}', encoding="ascii")
        report = self.scan(encoded({"sourcesContent": [SOURCE]}).encode())
        self.assertTrue(report["ok"])
        self.assertTrue(report["checks"]["structured_secrets_checked"])
        report = self.scan(encoded({"sourcesContent": [SOURCE], "issuer": "-----BEGIN PRIVATE KEY-----"}).encode())
        self.assertFalse(report["ok"])
        self.assertNotIn("source_map_marker", {row["code"] for row in report["findings"]})
        self.assertIn("private_key_marker", {row["code"] for row in report["findings"]})

    def test_ordinary_json_without_the_private_source_key_remains_allowed(self):
        for document in ({"sources": ["public.js"], "content": "public"},
                         {"version": 3, "source": {"contents": ["public"]}},
                         ["public", {"sources_count": 2}]):
            with self.subTest(document=document):
                self.assertTrue(self.scan(json.dumps(document).encode())["ok"])

    def test_public_split_refuses_an_additional_incomplete_escaped_map(self):
        (self.release / "app.js").write_text("export const rate=1;", encoding="ascii")
        complete = {"version": 3, "sources": ["owned.ts"], "sourcesContent": [SOURCE],
                    "names": [], "mappings": "AAAA"}
        (self.release / "app.js.map").write_text(json.dumps(complete), encoding="utf-8")
        self.target.write_text(encoded({"version": 3, "sources": ["owned.ts"],
                                        "sourcesContent": [SOURCE]}), encoding="utf-8")
        public, private = self.work / "public", self.work / "private"
        report = split_source_maps(self.release, public, private)
        self.assertFalse(report["ok"])
        self.assertFalse(public.exists())
        self.assertFalse(private.exists())
        self.assertNotIn(SOURCE, json.dumps(report))


if __name__ == "__main__":
    unittest.main()
