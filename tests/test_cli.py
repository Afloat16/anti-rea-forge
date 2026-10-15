"""Exercise the installed CLI boundary, not just its implementation functions."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    from tests.test_pe import make_pe
except ImportError:
    from test_pe import make_pe


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.env = os.environ.copy()
        source = str(Path(__file__).resolve().parents[1] / "src")
        self.env["PYTHONPATH"] = source
        self.env["RELEASEGUARD_PASSPHRASE"] = "temporary-test-passphrase-only"

    def run_cli(self, *args, expected=0):
        process = subprocess.run(
            [sys.executable, "-m", "releaseguard", *map(str, args)],
            cwd=self.work, env=self.env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(process.returncode, expected, process.stdout + process.stderr)
        self.assertNotIn("Traceback", process.stderr)
        return json.loads(process.stdout if expected in (0, 3) else process.stderr)

    def make_keys(self):
        self.run_cli("keygen", "--private", "issuer-private.pem", "--public", "issuer-public.pem")

    def test_release_and_license_lifecycle(self):
        self.make_keys()
        release = self.work / "application"
        release.mkdir()
        binary = release / "sample.dll"
        binary.write_bytes(b"test application content, not an executable")
        self.run_cli("manifest-sign", "--root", release, "--private", "issuer-private.pem",
                     "--product", "demo", "--release", "1.0.0", "--out", "manifest.json")
        report = self.run_cli("manifest-verify", "manifest.json", "--root", release,
                              "--public", "issuer-public.pem", "--product", "demo", "--release", "1.0.0")
        self.assertEqual(report["files_verified"], 1)
        binary.write_bytes(b"attacker replacement")
        self.assertFalse(self.run_cli("manifest-verify", "manifest.json", "--root", release,
                                     "--public", "issuer-public.pem", "--product", "demo", expected=2)["ok"])
        self.run_cli("license-issue", "--private", "issuer-private.pem", "--product", "demo",
                     "--subject", "customer-001", "--days", 2, "--feature", "export", "--out", "license.json")
        report = self.run_cli("license-verify", "license.json", "--public", "issuer-public.pem",
                              "--product", "demo", "--subject", "customer-001", "--require-feature", "export")
        self.assertEqual(report["claims"]["features"], ["export"])
        self.run_cli("license-verify", "license.json", "--public", "issuer-public.pem",
                     "--product", "other-app", expected=2)

    def test_existing_key_is_not_overwritten(self):
        self.make_keys()
        private = (self.work / "issuer-private.pem").read_bytes()
        self.run_cli("keygen", "--private", "issuer-private.pem", "--public", "other-public.pem", expected=2)
        self.assertEqual((self.work / "issuer-private.pem").read_bytes(), private)
        self.assertFalse((self.work / "other-public.pem").exists())

    def test_manifest_must_stay_outside_root(self):
        self.make_keys()
        root = self.work / "release"
        root.mkdir()
        (root / "main.exe").write_bytes(b"binary")
        self.run_cli("manifest-sign", "--root", root, "--private", "issuer-private.pem",
                     "--product", "demo", "--release", "1", "--out", root / "manifest.json", expected=2)
        self.assertFalse((root / "manifest.json").exists())

    def test_missing_passphrase_is_clear_error(self):
        del self.env["RELEASEGUARD_PASSPHRASE"]
        process = subprocess.run(
            [sys.executable, "-m", "releaseguard", "keygen", "--private", "private.pem", "--public", "public.pem"],
            cwd=self.work, env=self.env, input="", capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(process.returncode, 2)
        self.assertIn("RELEASEGUARD_PASSPHRASE", json.loads(process.stderr)["error"])
        self.assertFalse((self.work / "private.pem").exists())

    def test_malformed_pe_returns_error_without_traceback(self):
        (self.work / "bad.exe").write_bytes(b"MZ")
        self.assertFalse(self.run_cli("audit", "bad.exe", expected=2)["ok"])

    def test_strict_audit_failure_and_success_match_json(self):
        sample = self.work / "sample.exe"
        sample.write_bytes(make_pe())
        result = self.run_cli("audit", sample, "--strict", expected=3)
        self.assertFalse(result["ok"])
        self.assertFalse(result["policy_passed"])
        sample.write_bytes(make_pe(plus=True, flags=0x4160, directories={
            4: (0x400, 0x20), 5: (0x1000, 12), 10: (0x1040, 64),
        }))
        result = self.run_cli("audit", sample, "--strict")
        self.assertTrue(result["ok"])
        self.assertTrue(result["policy_passed"])

    def test_native_assets_and_gate_cli(self):
        initialized = self.run_cli("native-init", "--out", "generated", "--seed", "0123456789abcdef")
        self.assertTrue(initialized["ok"])
        self.assertTrue((self.work / "generated/include/releaseguard/literal.hpp").is_file())
        policy = self.work / "gate.json"
        policy.write_text(json.dumps({"version": 1, "forbid_literals": ["RG_CLI_PRIVATE_MARKER"]}))
        sample = self.work / "sample.exe"
        sample.write_bytes(make_pe())
        self.assertTrue(self.run_cli("gate", sample, "--policy", policy)["ok"])
        sample.write_bytes(make_pe() + b"RG_CLI_PRIVATE_MARKER")
        report = self.run_cli("gate", sample, "--policy", policy, expected=3)
        self.assertFalse(report["ok"])
        self.assertTrue(report["findings"])


if __name__ == "__main__":
    unittest.main()
