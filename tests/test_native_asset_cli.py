"""Native asset export through the public CLI, including keyless use and refusals."""

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest


class NativeAssetCLI(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native asset cli ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.key = self.work / "external.key"
        self.payload = self.work / "source data.bin"
        self.envelope = self.work / "asset.json"
        self.output = self.work / "generated includes"
        self.payload.write_bytes(secrets.token_bytes(32))
        self.context = ["--product", "demo", "--release", "1", "--purpose", "data",
                        "--asset-id", "table"]
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        self.call("asset-keygen", "--out", self.key)
        self.call("asset-seal", self.payload, "--key-file", self.key, *self.context, "--out", self.envelope)

    def call(self, *args, expected=0):
        result = subprocess.run([sys.executable, "-m", "releaseguard", *map(str, args)],
                                cwd=self.work, env=self.env, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)
        report = json.loads(result.stdout if expected == 0 else result.stderr)
        self.assertEqual(report["ok"], expected == 0)
        if self.key.exists():
            self.assertNotIn(self.key.read_bytes(), result.stdout + result.stderr)
            self.assertNotIn(self.key.read_bytes().hex().encode(), result.stdout + result.stderr)
        return report

    def export(self, expected=0, context=None):
        return self.call("native-asset-export", self.envelope,
                         *(self.context if context is None else context), "--out", self.output,
                         expected=expected)

    def test_keygen_seal_export_requires_no_key_at_build_export(self):
        original = self.envelope.read_bytes()
        self.key.unlink()
        report = self.export()
        self.assertEqual(report["ciphertext_bytes"], 48)
        self.assertEqual(report["authentication"], "performed by the native opener with an external key")
        self.assertEqual(Path(report["public_header"]), self.output / "releaseguard_asset.hpp")
        self.assertEqual({str(p.relative_to(self.output)).replace(os.sep, "/")
                          for p in self.output.rglob("*") if p.is_file()},
                         {"releaseguard_asset.hpp", "releaseguard/sealed_asset.hpp"})
        self.assertEqual(self.envelope.read_bytes(), original)
        self.assertNotIn(self.payload.read_bytes(), (self.output / "releaseguard_asset.hpp").read_bytes())

    def test_context_over_native_hkdf_cap_and_invalid_context_fail_without_output(self):
        too_long = []
        for field in ("product", "release", "purpose", "asset-id"):
            too_long += ["--" + field, "😀" * 128]
        report = self.export(expected=2, context=too_long)
        self.assertIn("1024-byte", report["error"])
        self.assertFalse(self.output.exists())
        bad = list(self.context)
        bad[1] = " leading space"
        self.export(expected=2, context=bad)
        self.assertFalse(self.output.exists())

    def test_ambiguous_invalid_and_oversized_inputs_fail_without_output(self):
        for data in (b'{"format":"first","format":"second"}', b'{"format":null}', b"x" * (2 * 1024 * 1024 + 1)):
            with self.subTest(size=len(data)):
                self.envelope.write_bytes(data)
                self.export(expected=2)
                self.assertFalse(self.output.exists())

    def test_export_never_replaces_an_existing_directory_or_follows_an_input_link(self):
        self.output.mkdir()
        sentinel = self.output / "other"
        sentinel.write_bytes(b"existing data")
        self.export(expected=2)
        self.assertEqual(sentinel.read_bytes(), b"existing data")
        self.assertEqual(list(self.output.iterdir()), [sentinel])
        sentinel.unlink()
        self.output.rmdir()
        actual = self.envelope.rename(self.work / "actual.json")
        try:
            self.envelope.symlink_to(actual)
        except (OSError, NotImplementedError):
            return
        self.export(expected=2)
        self.assertFalse(self.output.exists())
        self.assertTrue(actual.is_file())
