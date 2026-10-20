"""Exercise cryptographic CLI operations across process and filesystem boundaries."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CryptoCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
        self.password = "synthetic-cli-password-ONLY"
        self.env["RELEASEGUARD_USER_PASSWORD"] = self.password
        self.context = ["--product", "demo", "--release", "1", "--purpose", "model", "--asset-id", "main"]

    def cli(self, *arguments, expected=0):
        result = subprocess.run([sys.executable, "-m", "releaseguard", *map(str, arguments)],
                                cwd=self.work, env=self.env, input="", capture_output=True,
                                text=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertNotIn(self.password, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        return json.loads(result.stderr if expected == 2 else result.stdout)

    def prepare_asset(self):
        (self.work / "model.bin").write_bytes(b"project-owned synthetic model payload\x00\xff")
        self.cli("asset-keygen", "--out", "asset.key")
        self.cli("asset-seal", "model.bin", "--key-file", "asset.key", *self.context,
                 "--out", "model.sealed.json")

    def test_password_cli_roundtrip_and_wrong_candidate(self):
        self.cli("password-create", "--out", "verifier.json")
        raw = (self.work / "verifier.json").read_text()
        self.assertNotIn(self.password, raw)
        self.assertTrue(self.cli("password-check", "verifier.json")["password_verified"])
        self.env["RELEASEGUARD_USER_PASSWORD"] = "different-synthetic-password"
        self.assertFalse(self.cli("password-check", "verifier.json", expected=3)["password_verified"])

    def test_password_input_does_not_reuse_issuer_passphrase(self):
        self.env.pop("RELEASEGUARD_USER_PASSWORD")
        self.env["RELEASEGUARD_PASSPHRASE"] = "issuer-secret-for-another-purpose"
        self.assertIn("RELEASEGUARD_USER_PASSWORD", self.cli("password-create", "--out", "v.json", expected=2)["error"])
        self.assertFalse((self.work / "v.json").exists())

    def test_malicious_password_record_is_rejected(self):
        (self.work / "verifier.json").write_text('{"format":"open-release-guard-password/v1","phc":"$argon2id$v=19$m=999999999,t=999,p=4$x$y"}')
        self.assertFalse(self.cli("password-check", "verifier.json", expected=2)["ok"])

    def test_password_and_key_outputs_never_overwrite(self):
        for command, name in (("password-create", "verifier.json"), ("asset-keygen", "asset.key")):
            self.cli(command, "--out", name)
            before = (self.work / name).read_bytes()
            self.cli(command, "--out", name, expected=2)
            self.assertEqual((self.work / name).read_bytes(), before)

    def test_asset_cli_roundtrip_and_private_output_mode(self):
        self.prepare_asset()
        self.cli("asset-open", "model.sealed.json", "--key-file", "asset.key", *self.context,
                 "--out", "decoded.bin")
        self.assertEqual((self.work / "decoded.bin").read_bytes(), (self.work / "model.bin").read_bytes())
        if os.name == "posix":
            self.assertEqual((self.work / "decoded.bin").stat().st_mode & 0o777, 0o600)

    def test_asset_wrong_key_creates_no_output(self):
        self.prepare_asset()
        self.cli("asset-keygen", "--out", "other.key")
        self.cli("asset-open", "model.sealed.json", "--key-file", "other.key", *self.context,
                 "--out", "decoded.bin", expected=2)
        self.assertFalse((self.work / "decoded.bin").exists())

    def test_asset_context_replay_and_ciphertext_tamper_leave_existing_output(self):
        self.prepare_asset()
        output = self.work / "decoded.bin"
        output.write_bytes(b"existing content")
        for field in ("--product", "--release", "--purpose", "--asset-id"):
            with self.subTest(field=field):
                changed = list(self.context)
                changed[changed.index(field) + 1] = "different"
                self.cli("asset-open", "model.sealed.json", "--key-file", "asset.key", *changed,
                         "--out", "decoded.bin", expected=2)
                self.assertEqual(output.read_bytes(), b"existing content")
        envelope = json.loads((self.work / "model.sealed.json").read_text())
        ciphertext = envelope["ciphertext"]
        envelope["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
        (self.work / "model.sealed.json").write_text(json.dumps(envelope))
        self.cli("asset-open", "model.sealed.json", "--key-file", "asset.key", *self.context,
                 "--out", "decoded.bin", expected=2)
        self.assertEqual(output.read_bytes(), b"existing content")

    def test_valid_decryption_does_not_overwrite(self):
        self.prepare_asset()
        output = self.work / "decoded.bin"
        output.write_bytes(b"keep me")
        self.cli("asset-open", "model.sealed.json", "--key-file", "asset.key", *self.context,
                 "--out", "decoded.bin", expected=2)
        self.assertEqual(output.read_bytes(), b"keep me")

    def test_duplicate_json_and_oversized_plaintext_are_rejected(self):
        self.cli("asset-keygen", "--out", "asset.key")
        (self.work / "bad.json").write_text('{"format":"one","format":"two"}')
        self.cli("asset-open", "bad.json", "--key-file", "asset.key", *self.context,
                 "--out", "decoded.bin", expected=2)
        (self.work / "big.bin").write_bytes(b"x" * (1024 * 1024 + 1))
        self.cli("asset-seal", "big.bin", "--key-file", "asset.key", *self.context,
                 "--out", "sealed.json", expected=2)
        self.assertFalse((self.work / "sealed.json").exists())

    @unittest.skipUnless(os.name == "posix", "FIFO and symlink fixture requires POSIX")
    def test_special_input_is_rejected_without_blocking(self):
        self.cli("asset-keygen", "--out", "asset.key")
        os.mkfifo(self.work / "pipe")
        self.cli("asset-seal", "pipe", "--key-file", "asset.key", *self.context,
                 "--out", "sealed.json", expected=2)
        (self.work / "real.bin").write_bytes(b"synthetic")
        (self.work / "link.bin").symlink_to(self.work / "real.bin")
        self.cli("asset-seal", "link.bin", "--key-file", "asset.key", *self.context,
                 "--out", "sealed.json", expected=2)


if __name__ == "__main__":
    unittest.main()
