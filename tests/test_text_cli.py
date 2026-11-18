"""Exercise initialization and readable reports at the real CLI boundary."""

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from releaseguard.core import generate_keys, load_public_key, read_document, verify_manifest
from releaseguard.project import init_project


class TextCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="readable CLI ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "public files"
        self.root.mkdir()
        self.app = self.root / "client.js"
        self.app.write_bytes(b"export const operation = 'quote';\n")
        self.private = self.work / "confidential implementation.py"
        self.private_bytes = b"def quote(units):\n    return units * 117 + 23\n"
        self.private.write_bytes(self.private_bytes)
        self.key = self.work / "confidential asset.key"
        self.key.write_bytes(bytes(range(32)))
        self.config_dir = self.work / "guard config"
        self.config = self.config_dir / "project.json"
        self.policy = self.config_dir / "policy.json"
        self.env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                    "RELEASEGUARD_PASSPHRASE": "owned-readable-cli-test-passphrase"}

    def run_cli(self, *args, expected=0):
        result = subprocess.run([sys.executable, "-m", "releaseguard", *map(str, args)],
                                cwd=self.work, env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def initialize(self, *, private=False):
        return init_project(self.root, "owned-service", self.config_dir,
                            private_input_files=[self.private] if private else [])

    def issuer(self):
        private, public = self.work / "issuer-private.pem", self.work / "issuer-public.pem"
        generate_keys(private, public, self.env["RELEASEGUARD_PASSPHRASE"].encode())
        return private, public

    def test_initialization_accepts_repeatable_cwd_relative_inputs_and_saves_them_once(self):
        second = self.work / "second private.dat"
        second.write_bytes(b"owned private training material for the test fixture")
        second_key = self.work / "second.key"
        second_key.write_bytes(bytes(range(32, 64)))
        result = self.run_cli("project-init", "--root", self.root.name, "--product", "owned-service",
                              "--out", self.config_dir.name,
                              "--private-input-file", self.private.name, "--private-input-file", second.name,
                              "--asset-key-file", self.key.name, "--asset-key-file", second_key.name)
        self.assertTrue(json.loads(result.stdout)["ok"])
        document = json.loads(self.config.read_text())
        self.assertEqual(document["private_input_files"], ["../" + self.private.name, "../" + second.name])
        self.assertEqual(document["asset_key_files"], ["../" + self.key.name, "../" + second_key.name])
        report = json.loads(self.run_cli("check", "--config", self.config).stdout)
        self.assertEqual(report["checks"]["private_inputs_checked"], 2)
        self.assertEqual(report["checks"]["asset_keys_checked"], 2)
        (self.root / "renamed.bin").write_bytes(second.read_bytes())
        report = json.loads(self.run_cli("check", "--config", self.config, expected=3).stdout)
        self.assertTrue(any(f["code"] == "private_input_exposure" and f["rule_index"] == 1
                            for f in report["findings"]))

    def test_invalid_initial_reference_returns_json_error_and_writes_no_configuration(self):
        result = self.run_cli("project-init", "--root", self.root, "--product", "owned-service",
                              "--out", self.config_dir, "--private-input-file", self.work / "missing-private.py",
                              expected=2)
        self.assertEqual(result.stdout, "")
        self.assertFalse(json.loads(result.stderr)["ok"])
        self.assertNotIn("missing-private.py", result.stderr)
        self.assertFalse(self.config_dir.exists())

    def test_default_and_explicit_json_remain_byte_identical_for_check_and_scan(self):
        self.initialize(private=True)
        for copied in (False, True):
            if copied:
                (self.root / "renamed.bin").write_bytes(self.private_bytes)
            for args in (("check", "--config", self.config),
                         ("scan-release", "--root", self.root, "--policy", self.policy,
                          "--private-input-file", self.private)):
                with self.subTest(command=args[0], copied=copied):
                    code = 3 if copied else 0
                    default = self.run_cli(*args, expected=code)
                    explicit = self.run_cli(*args, "--format", "json", expected=code)
                    self.assertEqual(default.stdout, explicit.stdout)
                    self.assertEqual(default.stderr, explicit.stderr)

    def test_clean_text_report_identifies_unconfigured_references(self):
        self.initialize()
        result = self.run_cli("check", "--config", self.config, "--format", "text")
        self.assertEqual(result.stderr, "")
        self.assertIn("PASS (exit 0)", result.stdout)
        self.assertIn("Private inputs: 0 (not configured)", result.stdout)
        self.assertIn("Asset keys: 0 (not configured)", result.stdout)
        self.assertIn("project-init can save these references", result.stdout)
        self.assertIn("Findings: 0", result.stdout)

    def test_private_copy_is_actionable_without_echoing_private_reference_path_content_or_digest(self):
        self.initialize(private=True)
        (self.root / "renamed.bin").write_bytes(self.private_bytes)
        for args in (("check", "--config", self.config),
                     ("scan-release", "--root", self.root, "--policy", self.policy,
                      "--private-input-file", self.private)):
            with self.subTest(command=args[0]):
                result = self.run_cli(*args, "--format", "text", expected=3)
                self.assertEqual(result.stderr, "")
                self.assertIn("BLOCKED (exit 3)", result.stdout)
                self.assertIn('"private_input_exposure"', result.stdout)
                self.assertIn('File: "renamed.bin"', result.stdout)
                self.assertIn("rule_index=0", result.stdout)
                self.assertIn("Remove the private implementation", result.stdout)
                for private in (str(self.private), self.private.name, self.private_bytes.decode(),
                                hashlib.sha256(self.private_bytes).hexdigest()):
                    self.assertNotIn(private, result.stdout + result.stderr)

    def test_nested_archive_member_chain_and_source_map_next_step_are_visible(self):
        self.initialize()
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("hidden.map", '{"version":3,"sources":["private.ts"],"names":[],"mappings":"AAAA"}')
        with zipfile.ZipFile(self.root / "outer.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("bundle.zip", nested.getvalue())
        result = self.run_cli("check", "--config", self.config, "--format", "text", expected=3)
        self.assertIn('File: "outer.zip"', result.stdout)
        self.assertIn('Archive members: ["bundle.zip", "hidden.map"]', result.stdout)
        self.assertIn("split-source-maps", result.stdout)

    def test_unsupported_archive_preserves_incomplete_status(self):
        self.initialize()
        (self.root / "private.tar").write_bytes(b"unrecognized archive data")
        result = self.run_cli("check", "--config", self.config, "--format", "text", expected=3)
        self.assertIn("Archives: INCOMPLETE", result.stdout)
        self.assertIn('"unsupported_archive"', result.stdout)
        self.assertIn("supported inspected release layout", result.stdout)

    def test_missing_configured_private_input_returns_error_and_config_relative_guidance(self):
        self.initialize(private=True)
        self.private.unlink()
        result = self.run_cli("check", "--config", self.config, "--format", "text", expected=2)
        self.assertEqual(result.stdout, "")
        self.assertIn("ERROR (exit 2)", result.stderr)
        self.assertIn("Saved paths resolve relative to project.json", result.stderr)
        self.assertNotIn(self.private.name, result.stderr)

    def test_invalid_policy_keeps_error_on_stderr_in_both_formats(self):
        self.initialize()
        self.policy.write_text('{"version":1,"invalid_field":true}', encoding="utf-8")
        default = self.run_cli("scan-release", "--root", self.root, "--policy", self.policy, expected=2)
        explicit = self.run_cli("scan-release", "--root", self.root, "--policy", self.policy,
                                "--format", "json", expected=2)
        self.assertEqual(default.stdout, "")
        self.assertEqual(default.stderr, explicit.stderr)
        self.assertFalse(json.loads(default.stderr)["ok"])
        text = self.run_cli("scan-release", "--root", self.root, "--policy", self.policy,
                            "--format", "text", expected=2)
        self.assertEqual(text.stdout, "")
        self.assertIn("ERROR (exit 2)", text.stderr)
        self.assertIn("--root and --policy", text.stderr)

    def test_failed_text_prepare_creates_no_sidecars_and_default_json_is_unchanged(self):
        self.initialize(private=True)
        (self.root / "renamed.bin").write_bytes(self.private_bytes)
        issuer, _ = self.issuer()
        output = self.work / "release evidence"
        args = ("prepare", "--config", self.config, "--private", issuer, "--release", "1", "--out", output)
        default = self.run_cli(*args, expected=3)
        explicit = self.run_cli(*args, "--format", "json", expected=3)
        self.assertEqual(default.stdout, explicit.stdout)
        text = self.run_cli(*args, "--format", "text", expected=3)
        self.assertEqual(text.stderr, "")
        self.assertIn("Prepared: no; publication sidecars were not created", text.stdout)
        self.assertFalse(output.exists())

    def test_successful_text_prepare_retains_json_sidecars_and_verifiable_manifest(self):
        self.initialize(private=True)
        issuer, public = self.issuer()
        output = self.work / "release evidence"
        result = self.run_cli("prepare", "--config", self.config, "--private", issuer,
                              "--release", "1", "--out", output, "--format", "text")
        self.assertEqual(result.stderr, "")
        self.assertIn("Prepared: yes", result.stdout)
        summary = json.loads((output / "release-report.json").read_text())
        self.assertEqual(summary["checks"]["private_inputs_checked"], 1)
        manifest = read_document(output / "manifest.json")
        verified = verify_manifest(manifest, self.root, load_public_key(public), "owned-service", "1")
        self.assertEqual(len(verified["files"]), 1)
        self.assertNotIn(self.private.name, result.stdout)
        self.assertNotIn(issuer.name, result.stdout)


if __name__ == "__main__":
    unittest.main()
