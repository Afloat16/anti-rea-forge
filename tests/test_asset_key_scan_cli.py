"""Known external-key scanning preserves CLI exit codes without echoing key values."""

import base64
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest
import zipfile


class AssetKeyScanCLI(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="asset key scan ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.release = self.work / "public assets"
        self.release.mkdir()
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="ascii")
        self.key_file = self.work / "external.key"
        self.key = secrets.token_bytes(32)
        self.key_file.write_bytes(self.key)
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        self.app = self.release / "app.bin"
        self.app.write_bytes(b"ordinary public application")

    def scan(self, expected=0, keys=None):
        selected = [self.key_file] if keys is None else keys
        arguments = [sys.executable, "-m", "releaseguard", "scan-release",
                     "--root", str(self.release), "--policy", str(self.policy)]
        for key in selected:
            arguments += ["--asset-key-file", str(key)]
        result = subprocess.run(arguments, cwd=self.work, env=self.env, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)
        report = json.loads(result.stdout if expected in (0, 3) else result.stderr)
        self.assertEqual(report["ok"], expected == 0)
        for encoded in (self.key, self.key.hex().encode(), self.key.hex().upper().encode(),
                        base64.b64encode(self.key), base64.urlsafe_b64encode(self.key).rstrip(b"=")):
            self.assertNotIn(encoded, result.stdout + result.stderr)
        return report

    def test_clean_release_passes_and_raw_key_exposure_is_exit_three(self):
        report = self.scan()
        self.assertEqual(report["checks"]["asset_keys_checked"], 1)
        self.app.write_bytes(b"prefix" + self.key + b"suffix")
        report = self.scan(expected=3)
        self.assertTrue(any(f["code"] == "asset_key_exposure" and f["path"] == "app.bin"
                            for f in report["findings"]))
        self.assertEqual(self.key_file.read_bytes(), self.key)

    def test_encodings_and_nested_zip_use_same_failure_code(self):
        patterns = (self.key.hex().encode(), self.key.hex().upper().encode(),
                    base64.b64encode(self.key), base64.urlsafe_b64encode(self.key).rstrip(b"="),
                    self.key.hex().encode("utf-32-be"))
        for pattern in patterns:
            with self.subTest(length=len(pattern)):
                self.app.write_bytes(pattern)
                self.scan(expected=3)
        self.app.write_bytes(b"clean")
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("key.bin", self.key)
        with zipfile.ZipFile(self.release / "package.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("inside.zip", inner.getvalue())
        report = self.scan(expected=3)
        self.assertTrue(any(f.get("archive_members") == ["inside.zip", "key.bin"]
                            and f["code"] == "asset_key_exposure" for f in report["findings"]))

    def test_multiple_keys_and_input_count_limit(self):
        another = self.work / "second.key"
        another.write_bytes(secrets.token_bytes(32))
        self.app.write_bytes(another.read_bytes())
        report = self.scan(expected=3, keys=[self.key_file, another])
        self.assertEqual(report["checks"]["asset_keys_checked"], 2)
        self.assertTrue(any(f["code"] == "asset_key_exposure" and f["rule_index"] == 1
                            for f in report["findings"]))
        self.scan(expected=2, keys=[self.key_file] * 17)

    def test_missing_short_long_and_linked_keys_fail_as_input_errors(self):
        for data in (b"", b"x" * 31, b"x" * 33):
            self.key_file.write_bytes(data)
            self.scan(expected=2)
        self.key_file.unlink()
        self.scan(expected=2)
        other = self.work / "actual.key"
        other.write_bytes(self.key)
        try:
            self.key_file.symlink_to(other)
        except (OSError, NotImplementedError):
            return
        self.scan(expected=2)

    def test_a_key_accidentally_placed_in_release_is_reported(self):
        self.app.write_bytes(self.key)
        self.scan(expected=3, keys=[self.app])
