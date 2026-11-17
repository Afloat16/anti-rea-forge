"""Known external keys must be checked before a release can be signed."""

import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard.core import GuardError, generate_keys
from releaseguard.project import check_project, init_project, load_project, prepare_release


class ProjectAssetKeyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="project key controls ")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "dist"
        self.root.mkdir()
        self.app = self.root / "app.bin"
        self.app.write_bytes(b"public program")
        self.key = secrets.token_bytes(32)
        self.key_file = self.base / "external.key"
        self.key_file.write_bytes(self.key)
        self.config_dir = self.base / "config"
        init_project(self.root, "owned-app", self.config_dir)
        self.config = self.config_dir / "project.json"
        self.out = self.base / "evidence"
        self.private = Ed25519PrivateKey.generate()

    def configure_keys(self, keys):
        document = json.loads(self.config.read_bytes())
        document["asset_key_files"] = keys
        self.config.write_text(json.dumps(document), encoding="utf-8")

    def assert_no_key(self, value):
        rendered = json.dumps(value).encode()
        for encoded in (self.key.hex().encode(), self.key.hex().upper().encode(), base64.b64encode(self.key)):
            self.assertNotIn(encoded, rendered)

    def test_configured_keys_resolve_from_config_and_are_checked_by_default(self):
        self.configure_keys(["../external.key"])
        self.assertEqual(load_project(self.config)["asset_key_files"], [self.config_dir / "../external.key"])
        report = check_project(self.config)
        self.assertTrue(report["ok"])
        self.assertEqual(report["checks"]["asset_keys_checked"], 1)
        self.app.write_bytes(self.key)
        report = check_project(self.config)
        self.assertFalse(report["ok"])
        self.assertTrue(any(finding["code"] == "asset_key_exposure" for finding in report["findings"]))
        self.assert_no_key(report)

    def test_leaked_configured_key_prevents_signing_and_sidecar_creation(self):
        self.configure_keys(["../external.key"])
        self.app.write_bytes(base64.b64encode(self.key))
        with patch("releaseguard.project.create_manifest") as signing:
            report = prepare_release(self.config, self.private, "1", self.out)
        signing.assert_not_called()
        self.assertFalse(report["prepared"])
        self.assertFalse(self.out.exists())
        self.assert_no_key(report)

    def test_explicit_keys_add_to_configured_keys_without_overriding_them(self):
        self.configure_keys(["../external.key"])
        other = self.base / "another.key"
        other.write_bytes(secrets.token_bytes(32))
        self.app.write_bytes(self.key)
        self.assertFalse(check_project(self.config, asset_key_files=[])["ok"])
        report = check_project(self.config, asset_key_files=[other])
        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"]["asset_keys_checked"], 2)
        self.assertFalse(prepare_release(self.config, self.private, "1", self.out,
                                        asset_key_files=[other])["prepared"])

    def test_clean_preparation_records_which_checks_ran_without_key_material(self):
        report = prepare_release(self.config, self.private, "1", self.out, asset_key_files=[self.key_file])
        self.assertTrue(report["prepared"])
        saved = json.loads((self.out / "release-report.json").read_bytes())
        self.assertEqual(saved["checks"]["asset_keys_checked"], 1)
        self.assertTrue(saved["checks"]["native_metadata_checked"])
        self.assert_no_key(saved)
        self.assert_no_key(report)

    def test_missing_invalid_and_over_budget_configured_keys_fail_before_signing(self):
        for keys in ("../external.key", [None], [""], ["../external.key"] * 17):
            with self.subTest(keys=keys):
                self.configure_keys(keys)
                with self.assertRaises(GuardError):
                    prepare_release(self.config, self.private, "1", self.out)
                self.assertFalse(self.out.exists())
        self.configure_keys(["../external.key"])
        with self.assertRaises(GuardError):
            check_project(self.config, asset_key_files=[self.key_file] * 16)
        self.key_file.unlink()
        with self.assertRaises(GuardError):
            prepare_release(self.config, self.private, "1", self.out)
        self.assertFalse(self.out.exists())

    def test_legacy_config_without_key_list_is_compatible(self):
        document = json.loads(self.config.read_bytes())
        document.pop("asset_key_files", None)
        self.config.write_text(json.dumps(document), encoding="utf-8")
        self.assertTrue(check_project(self.config)["ok"])
        self.assertEqual(check_project(self.config)["checks"]["asset_keys_checked"], 0)

    def test_real_cli_check_and_prepare_check_additional_external_keys(self):
        self.app.write_bytes(self.key.hex().encode())
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        env["RELEASEGUARD_PASSPHRASE"] = "owned-test-key-phrase"
        issuer = self.base / "issuer.pem"
        generate_keys(issuer, self.base / "public.pem", env["RELEASEGUARD_PASSPHRASE"].encode())
        for command, arguments in (
            ("check", []),
            ("prepare", ["--private", str(issuer), "--release", "1", "--out", str(self.out)]),
        ):
            result = subprocess.run(
                [sys.executable, "-m", "releaseguard", command, "--config", str(self.config),
                 "--asset-key-file", str(self.key_file), *arguments],
                cwd=self.base, env=env, capture_output=True, timeout=30,
            )
            self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
            self.assertEqual(result.stderr, b"")
            report = json.loads(result.stdout)
            self.assertFalse(report["ok"])
            self.assert_no_key(report)
            self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
