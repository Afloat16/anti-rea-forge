"""Server authorization CLI across separate processes and persistent state."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CapabilityCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
                        RELEASEGUARD_PASSPHRASE="temporary-capability-cli-passphrase")
        self.context = ["--subject", "customer-001", "--audience", "export-service",
                        "--product", "demo", "--operation", "export"]
        (self.work / "request.bin").write_bytes(b"synthetic-owned-request\x00\xff")
        self.cli("keygen", "--private", "issuer-private.pem", "--public", "issuer-public.pem")

    def cli(self, *arguments, expected=0):
        result = subprocess.run([sys.executable, "-m", "releaseguard", *map(str, arguments)],
                                cwd=self.work, env=self.env, input="", capture_output=True,
                                text=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn(self.env["RELEASEGUARD_PASSPHRASE"], result.stdout + result.stderr)
        return json.loads(result.stderr if expected == 2 else result.stdout)

    def issue(self, *extra, expected=0):
        return self.cli("capability-issue", "--private", "issuer-private.pem", *self.context,
                        "--request", "request.bin", "--out", "capability.json", *extra,
                        expected=expected)

    def consume(self, *extra, expected=0):
        return self.cli("capability-consume", "capability.json", "--public", "issuer-public.pem",
                        "--store", "replay.db", *self.context, "--request", "request.bin", *extra,
                        expected=expected)

    def test_process_restart_preserves_replay_and_private_output_mode(self):
        self.cli("replay-store-init", "--out", "replay.db")
        self.issue()
        result = self.consume()
        self.assertEqual(result, {"ok": True, "capability_consumed": True})
        self.assertFalse(self.consume(expected=2)["ok"])
        if os.name == "posix":
            for name in ("replay.db", "capability.json"):
                self.assertEqual((self.work / name).stat().st_mode & 0o777, 0o600)

    def test_failed_request_and_subject_binding_do_not_consume(self):
        self.cli("replay-store-init", "--out", "replay.db")
        self.issue()
        self.consume("--subject", "other-customer", expected=2)
        original = (self.work / "request.bin").read_bytes()
        (self.work / "request.bin").write_bytes(original + b"changed")
        self.consume(expected=2)
        (self.work / "request.bin").write_bytes(original)
        self.assertTrue(self.consume()["capability_consumed"])

    def test_missing_or_deleted_store_is_never_recreated(self):
        self.issue()
        self.consume(expected=2)
        self.assertFalse((self.work / "replay.db").exists())
        self.cli("replay-store-init", "--out", "replay.db")
        self.consume()
        (self.work / "replay.db").unlink()
        self.consume(expected=2)
        self.assertFalse((self.work / "replay.db").exists())

    def test_init_and_token_outputs_never_replace_existing_state(self):
        self.cli("replay-store-init", "--out", "replay.db")
        before = (self.work / "replay.db").read_bytes()
        self.cli("replay-store-init", "--out", "replay.db", expected=2)
        self.assertEqual((self.work / "replay.db").read_bytes(), before)
        self.issue()
        token = (self.work / "capability.json").read_bytes()
        self.issue(expected=2)
        self.assertEqual((self.work / "capability.json").read_bytes(), token)

    def test_duplicate_token_json_and_corrupt_store_fail_without_traceback(self):
        self.cli("replay-store-init", "--out", "replay.db")
        self.issue()
        original = (self.work / "capability.json").read_bytes()
        (self.work / "capability.json").write_text('{"format":"x","format":"x"}')
        self.consume(expected=2)
        (self.work / "capability.json").write_bytes(original)
        (self.work / "replay.db").write_bytes(b"not a database")
        self.consume(expected=2)

    def test_invalid_ttl_or_oversized_request_creates_no_capability(self):
        self.issue("--ttl", "301", expected=2)
        self.assertFalse((self.work / "capability.json").exists())
        (self.work / "request.bin").write_bytes(b"x" * (1024 * 1024 + 1))
        self.issue(expected=2)
        self.assertFalse((self.work / "capability.json").exists())


if __name__ == "__main__":
    unittest.main()
