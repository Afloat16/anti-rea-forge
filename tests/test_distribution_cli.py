"""Exercise portable release checks at the installed command boundary."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


class DistributionCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="portable release ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.release = self.work / "release with spaces"
        self.release.mkdir()
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version": 1}', encoding="utf-8")
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")

    def run_scan(self, expected=0):
        process = subprocess.run(
            [sys.executable, "-m", "releaseguard", "scan-release", "--root", str(self.release),
             "--policy", str(self.policy)],
            env=self.env, cwd=self.work, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(process.returncode, expected, process.stdout + process.stderr)
        self.assertNotIn("Traceback", process.stderr)
        report = json.loads(process.stdout if expected in (0, 3) else process.stderr)
        return report, process

    def test_plain_javascript_and_python_release_needs_no_native_artifact(self):
        (self.release / "app.js").write_text("export const answer = 42;\n", encoding="utf-8")
        (self.release / "app.py").write_text("answer = 42\n", encoding="utf-8")
        report, process = self.run_scan()
        self.assertTrue(report["ok"])
        self.assertTrue(report["checks"]["scan_completed"])
        self.assertEqual(report["findings"], [])
        self.assertEqual(process.stderr, "")

    def test_violation_is_exit_three_without_echoing_sensitive_content(self):
        secret = "SYNTHETIC-PRIVATE-DATA-FOR-CLI-TEST-ONLY"
        self.policy.write_text(json.dumps({"version": 1, "forbid_literals": [secret]}), encoding="utf-8")
        (self.release / "app.js").write_text(f'const value = "{secret}";', encoding="utf-8")
        report, process = self.run_scan(expected=3)
        self.assertFalse(report["ok"])
        self.assertTrue(report["checks"]["scan_completed"])
        self.assertTrue(report["findings"])
        self.assertNotIn(secret, process.stdout + process.stderr)

    def test_source_map_in_a_compressed_package_blocks_release(self):
        source_map = {"version": 3, "sources": ["private.ts"], "names": [], "mappings": "",
                      "sourcesContent": ["const internal = 42;"]}
        with zipfile.ZipFile(self.release / "bundle.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("assets/debug.data", json.dumps(source_map))
        report, _ = self.run_scan(expected=3)
        self.assertFalse(report["ok"])
        self.assertTrue(report["findings"])

    def test_exhausted_budget_is_error_not_a_partial_pass(self):
        (self.release / "app.js").write_bytes(b"x" * 65)
        self.policy.write_text('{"version":1,"max_file_bytes":64}', encoding="utf-8")
        report, process = self.run_scan(expected=2)
        self.assertFalse(report["ok"])
        self.assertIn("error", report)
        self.assertEqual(process.stdout, "")

    def test_native_policy_cannot_silently_disable_portable_checks(self):
        (self.release / "app.js").write_text("export {};", encoding="utf-8")
        self.policy.write_text('{"version":1,"formats":["pe"]}', encoding="utf-8")
        report, process = self.run_scan(expected=2)
        self.assertFalse(report["ok"])
        self.assertEqual(process.stdout, "")

    def test_ambiguous_policy_is_rejected(self):
        (self.release / "app.js").write_text("export {};", encoding="utf-8")
        self.policy.write_text('{"version":1,"version":1}', encoding="utf-8")
        report, _ = self.run_scan(expected=2)
        self.assertFalse(report["ok"])

    def test_inspection_does_not_run_the_release(self):
        marker = self.work / "must-not-exist"
        (self.release / "app.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n", encoding="utf-8"
        )
        report, _ = self.run_scan()
        self.assertTrue(report["ok"])
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
