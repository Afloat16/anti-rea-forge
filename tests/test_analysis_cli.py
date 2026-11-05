"""Real command-line setup, release preparation and analysis admission."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from releaseguard.core import generate_keys


class AnalysisCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="analysis CLI ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.release = self.work / "dist"
        self.release.mkdir()
        (self.release / "app.js").write_text("export const answer = 42;", encoding="utf-8")
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        self.env["RELEASEGUARD_PASSPHRASE"] = "synthetic-cli-test-passphrase"
        self.private = self.work / "issuer-private.pem"
        self.public = self.work / "issuer-public.pem"
        generate_keys(self.private, self.public, self.env["RELEASEGUARD_PASSPHRASE"].encode())

    def invoke(self, *args, expected=0, cwd=None):
        result = subprocess.run(
            [sys.executable, "-m", "releaseguard", *map(str, args)],
            cwd=cwd or self.work, env=self.env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        if expected in (0, 3):
            self.assertEqual(result.stderr, "")
            return json.loads(result.stdout)
        self.assertEqual(result.stdout, "")
        return json.loads(result.stderr)

    def prepare(self):
        self.invoke("project-init", "--root", self.release, "--product", "demo")
        return self.invoke("prepare", "--private", self.private, "--release", "1",
                           "--out", self.work / "evidence")

    def issue(self, *extra, expected=0):
        return self.invoke(
            "analysis-grant-issue", "--manifest", self.work / "evidence/manifest.json",
            "--private", self.private, "--product", "demo", "--release", "1",
            "--subject", "analyst-01", "--audience", "local-gateway",
            "--operation", "inspect", "--out", self.work / "grant.json", *extra, expected=expected,
        )

    def check(self, *extra, expected=0):
        return self.invoke(
            "analysis-check", "--manifest", self.work / "evidence/manifest.json",
            "--root", self.release, "--public", self.public,
            "--product", "demo", "--release", "1", "--subject", "analyst-01",
            "--audience", "local-gateway", "--operation", "inspect", *extra, expected=expected,
        )

    def test_three_step_build_flow_and_scoped_authorization(self):
        result = self.prepare()
        self.assertTrue(result["prepared"])
        self.assertTrue(self.invoke("check")["ok"])
        missing = self.check(expected=3)
        self.assertEqual(missing["reason"], "grant_required")
        self.assertFalse(missing["checks"]["release_integrity"])
        self.issue()
        report = self.check("--grant", self.work / "grant.json")
        self.assertTrue(report["authorized"])
        self.assertEqual(report["decision"], "allow")
        self.assertTrue(all(report["checks"].values()))
        self.assertIsNotNone(report["validity"])
        self.assertEqual(set(path.name for path in self.release.iterdir()), {"app.js"})

    def test_saved_config_works_from_another_working_directory(self):
        self.prepare()
        self.assertTrue(self.invoke("check", "--config", self.work / ".releaseguard/project.json",
                                    cwd=self.release)["ok"])

    def test_build_findings_do_not_issue_a_manifest(self):
        self.invoke("project-init", "--root", self.release, "--product", "demo")
        (self.release / "app.map").write_text("{}", encoding="utf-8")
        report = self.invoke("prepare", "--private", self.private, "--release", "1",
                             "--out", self.work / "evidence", expected=3)
        self.assertFalse(report["prepared"])
        self.assertFalse((self.work / "evidence").exists())

    def test_private_key_inside_release_is_rejected(self):
        self.invoke("project-init", "--root", self.release, "--product", "demo")
        target = self.release / "private.pem"
        target.write_bytes(self.private.read_bytes())
        report = self.invoke("prepare", "--private", target, "--release", "1",
                             "--out", self.work / "evidence", expected=2)
        self.assertIn("outside", report["error"])
        self.assertFalse((self.work / "evidence").exists())

    def test_wrong_scope_and_modified_release_are_denied(self):
        self.prepare()
        self.issue()
        denied = self.check("--grant", self.work / "grant.json", "--operation", "instrument", expected=3)
        self.assertEqual(denied["reason"], "operation_not_granted")
        (self.release / "app.js").write_text("export const answer = 43;", encoding="utf-8")
        denied = self.check("--grant", self.work / "grant.json", expected=3)
        self.assertEqual(denied["reason"], "release_mismatch")

    def test_malformed_grant_is_error_without_allow_output(self):
        self.prepare()
        (self.work / "grant.json").write_text('{"kind":"analysis-grant","kind":"license"}', encoding="utf-8")
        self.check("--grant", self.work / "grant.json", expected=2)

    def test_explicit_missing_grant_path_is_error(self):
        self.prepare()
        self.check("--grant", self.work / "missing.json", expected=2)

    def test_ttl_bounds_and_exclusive_creation(self):
        self.prepare()
        self.issue("--ttl", "86401", expected=2)
        self.assertFalse((self.work / "grant.json").exists())
        self.issue()
        original = (self.work / "grant.json").read_bytes()
        self.issue(expected=2)
        self.assertEqual((self.work / "grant.json").read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
