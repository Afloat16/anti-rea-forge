"""The production publication gate must enforce bounded content containment."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard.distribution import scan_release
from releaseguard.project import prepare_release
from tests.test_private_inputs import packed_asar, zipped


class PrivateContentScanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="private-content-publication-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "public"
        self.root.mkdir()
        self.private = self.base / "private-source.mjs"
        self.source = (b"// Owned service implementation for complete-content matching.\n"
                       b"export function quote(x) { return x * 37 + 19; }\n")
        self.private.write_bytes(self.source)
        self.policy = self.base / "policy.json"
        self.policy.write_text('{"version":1}', encoding="ascii")

    def scan(self, references=None):
        return scan_release(self.root, self.policy, private_input_files=
                            [self.private] if references is None else references)

    def findings(self, report, code="private_input_exposure"):
        return [finding for finding in report["findings"] if finding["code"] == code]

    def test_prefix_suffix_and_bundle_copies_are_positive_without_reference_metadata(self):
        for prefix, suffix in ((b"// build header\n", b""), (b"", b"\n"),
                               (b"export const publicVersion=4;\n", b"export const end=1;\n")):
            with self.subTest(prefix=bool(prefix), suffix=bool(suffix)):
                target = self.root / "bundle.mjs"
                data = prefix + self.source + suffix
                target.write_bytes(data)
                report = self.scan()
                self.assertFalse(report["ok"])
                self.assertTrue(report["checks"]["private_input_scan_completed"])
                self.assertEqual(report["checks"]["private_input_profile"], "exact-content/v1")
                self.assertEqual(self.findings(report), [{"code": "private_input_exposure",
                    "path": "bundle.mjs", "rule_index": 0, "representation": "contained-bytes"}])
                self.assertEqual(target.read_bytes(), data)
                rendered = json.dumps(report)
                for secret in (str(self.private), self.private.name, self.source.decode(),
                               hashlib.sha256(self.source).hexdigest()):
                    self.assertNotIn(secret, rendered)

    def test_archive_members_use_the_same_complete_content_profile(self):
        body = b"// bundled\n" + self.source + b"\n// footer\n"
        cases = (
            ("package.zip", zipped("bundle.mjs", body), ["bundle.mjs"]),
            ("nested.zip", zipped("inner.zip", zipped("bundle.mjs", body)),
             ["inner.zip", "bundle.mjs"]),
            ("application.asar", packed_asar(body), ["renamed.dat"]),
            ("asar.zip", zipped("application.asar", packed_asar(body)),
             ["application.asar", "renamed.dat"]),
        )
        for name, payload, members in cases:
            with self.subTest(name=name):
                target = self.root / name
                target.write_bytes(payload)
                report = self.scan()
                self.assertFalse(report["ok"])
                self.assertTrue(report["checks"]["archive_scan_completed"])
                self.assertTrue(report["checks"]["private_input_scan_completed"])
                self.assertTrue(any(item.get("archive_members") == members
                                    and item.get("representation") == "contained-bytes"
                                    for item in self.findings(report)))
                target.unlink()

    def test_unpacked_asar_sibling_inside_zip_is_checked_at_its_own_location(self):
        body = b"// wrapper\n" + self.source
        with zipfile.ZipFile(self.root / "package.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("app.asar", packed_asar(body, unpacked=True))
            archive.writestr("app.asar.unpacked/renamed.dat", body)
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"]["asar_unpacked_members_checked"], 1)
        self.assertTrue(any(item.get("archive_members") == ["app.asar.unpacked/renamed.dat"]
                            for item in self.findings(report)))

    def test_exact_copies_are_not_duplicated_and_duplicate_rules_keep_their_indexes(self):
        (self.root / "copy.data").write_bytes(self.source)
        report = self.scan([self.private, self.private])
        self.assertEqual(self.findings(report), [
            {"code": "private_input_exposure", "path": "copy.data", "rule_index": 0},
            {"code": "private_input_exposure", "path": "copy.data", "rule_index": 1},
        ])
        self.assertEqual(report["checks"]["private_input_candidate_checks"], 0)
        self.assertEqual(report["checks"]["private_input_verification_bytes"], 0)

    def test_short_declared_references_are_checked_instead_of_silently_skipped(self):
        self.private.write_bytes(b"X")
        (self.root / "public.data").write_bytes(b"ordinary X content")
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertTrue(report["checks"]["private_input_scan_completed"])
        self.assertEqual(len(self.findings(report)), 1)
        self.assertEqual(report["checks"]["private_input_candidate_checks"], 1)
        self.assertEqual(report["checks"]["private_input_verification_bytes"], 0)

    def test_no_references_and_semantic_rewrites_do_not_claim_an_active_content_boundary(self):
        (self.root / "public.mjs").write_bytes(self.source.replace(b"x * 37", b"37 * x"))
        report = self.scan()
        self.assertTrue(report["ok"])
        unconfigured = self.scan([])
        self.assertTrue(unconfigured["ok"])
        self.assertEqual(unconfigured["checks"]["private_inputs_checked"], 0)
        self.assertIsNone(unconfigured["checks"]["private_input_profile"])
        self.assertEqual(unconfigured["checks"]["private_input_payloads_checked"], 0)

    def test_candidate_budget_is_global_and_other_rules_continue_after_incomplete_inspection(self):
        common = b"A" * 64
        self.private.write_bytes(common + b"private suffix")
        (self.root / "a.data").write_bytes(common + b"ordinary public suffix")
        (self.root / "b.data").write_bytes(common + b"another public suffix")
        (self.root / "c.data").write_bytes(self.private.read_bytes())
        self.policy.write_text('{"version":1,"forbid_literals":["another public suffix"]}', encoding="ascii")
        with patch("releaseguard.private_inputs.MAX_PRIVATE_CONTENT_CANDIDATES", 1):
            report = self.scan()
        self.assertFalse(report["ok"])
        self.assertTrue(report["checks"]["scan_completed"])
        self.assertFalse(report["checks"]["private_input_scan_completed"])
        self.assertTrue(report["checks"]["structured_secret_scan_completed"])
        self.assertEqual(report["checks"]["private_input_candidate_checks"], 1)
        self.assertEqual(report["checks"]["private_input_payloads_checked"], 2)
        self.assertEqual(self.findings(report, "private_input_unverifiable"), [{
            "code": "private_input_unverifiable", "path": "b.data",
            "reason": "private_content_candidate_limit"}])
        self.assertEqual(self.findings(report)[0]["path"], "c.data")
        self.assertEqual(len(self.findings(report, "forbidden_literal")), 1)

    def test_verification_budget_refusal_prevents_signed_output(self):
        (self.root / "bundle.mjs").write_bytes(b"// wrapper\n" + self.source)
        config = self.base / "project.json"
        config.write_text(json.dumps({"version": 1, "product": "owned-v14", "root": "public",
            "policy": "policy.json", "private_input_files": [self.private.name]}), encoding="utf-8")
        destination = self.base / "evidence"
        with patch("releaseguard.private_inputs.MAX_PRIVATE_CONTENT_VERIFY_BYTES", len(self.source) - 1):
            result = prepare_release(config, Ed25519PrivateKey.generate(), "1.4.0", destination)
        self.assertFalse(result["ok"])
        self.assertFalse(result["prepared"])
        self.assertFalse(result["scan"]["checks"]["private_input_scan_completed"])
        self.assertEqual(self.findings(result["scan"], "private_input_unverifiable")[0]["reason"],
                         "private_content_verification_limit")
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
