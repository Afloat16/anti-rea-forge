"""The public issuer CLI never returns token bytes or clobbers issuer files."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class NativeTokenCLI(unittest.TestCase):
    def test_external_delivery_and_refusal_to_replace_it(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            private = directory / "issuer"
            private.mkdir(mode=0o700)
            secret = private / "unlock.rg-token"
            public = directory / "include"
            args = [sys.executable, "-m", "releaseguard", "native-token-issue",
                    "--public-dir", str(public), "--secret-out", str(secret)]
            result = subprocess.run(args, capture_output=True, check=False, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            token = secret.read_bytes().rstrip(b"\n")
            self.assertRegex(token, rb"^rg1_[a-f0-9]{64}$")
            self.assertTrue(json.loads(result.stdout)["ok"])
            self.assertNotIn(token, result.stdout + result.stderr)
            self.assertTrue((public / "releaseguard_token.hpp").is_file())
            other_public = directory / "different"
            args[args.index(str(public))] = str(other_public)
            retry = subprocess.run(args, capture_output=True, check=False, timeout=20)
            self.assertEqual(retry.returncode, 2)
            self.assertFalse(other_public.exists())
            self.assertEqual(secret.read_bytes(), token + b"\n")
            self.assertNotIn(token, retry.stdout + retry.stderr)
