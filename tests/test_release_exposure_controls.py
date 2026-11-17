"""Keep new release-exposure observations honest about bytes and tool failures."""

from contextlib import redirect_stderr, redirect_stdout
import base64
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from benchmarks import release_exposure_controls as controls


def dump_row(address, data, ascii_text="owned fixture"):
    words = [data[index:index + 4].hex() for index in range(0, len(data), 4)]
    return f" {address:x} {' '.join(words):35}  {ascii_text}\n".encode("ascii")


class ExposureEvidenceValidation(unittest.TestCase):
    def test_objdump_ascii_column_is_not_mistaken_for_more_bytes(self):
        expected = bytes(range(20))
        output = b"Contents of section .text:\n" + dump_row(0x1000, expected[:16], "deadbeef") + dump_row(0x1010, expected[16:], "deadbeef")
        self.assertEqual(controls.parse_section_dump(output, 0x1000, len(expected)), expected)

    def test_missing_discontinuous_extra_and_malformed_dump_cannot_pass(self):
        good = dump_row(0x1000, bytes(range(16)))
        cases = [(b"", 16), (good, 17), (good + dump_row(0x1020, b"a"), 17),
                 (good + dump_row(0x1010, b"a"), 16), (good.replace(b"00010203", b"0001020 "), 16)]
        for output, size in cases:
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                controls.parse_section_dump(output, 0x1000, size)

    def test_existing_report_preserved_before_any_compiler_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "keep.json"
            report.write_bytes(b"keep")
            with patch.object(controls, "run_controls") as run, redirect_stderr(io.StringIO()):
                self.assertEqual(controls.main(["--out", str(report)]), 2)
            run.assert_not_called()
            self.assertEqual(report.read_bytes(), b"keep")

    def test_missing_tool_or_timeout_is_not_protection_success(self):
        for failure in (RuntimeError("Missing required tools: objdump"), subprocess.TimeoutExpired(["objdump"], 120)):
            with self.subTest(failure=type(failure)), patch.object(controls, "run_controls", side_effect=failure):
                stderr, stdout = io.StringIO(), io.StringIO()
                with redirect_stderr(stderr), redirect_stdout(stdout):
                    self.assertEqual(controls.main([]), 2)
                report = json.loads(stderr.getvalue())
                self.assertFalse(report["ok"])
                self.assertEqual(report["protection_outcome"], "not_measured")
                self.assertEqual(stdout.getvalue(), "")


@unittest.skipUnless(sys.platform.startswith("linux") and all(shutil.which(name) for name in controls.TOOLS),
                     "requires GNU/Linux, GNU binutils, C/C++ and OpenSSL development files")
class ActualReleaseExposureControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                ["g++", "-std=c++17", "-x", "c++", "-", "-lcrypto", "-o", str(Path(temporary) / "check")],
                input=b"#include <openssl/evp.h>\n#include <openssl/kdf.h>\nint main(){return EVP_PKEY_HKDF?0:1;}\n",
                capture_output=True, timeout=60, check=False)
        if result.returncode:
            reason = "requires OpenSSL development headers and libcrypto"
            if os.environ.get("RELEASEGUARD_REQUIRE_OPENSSL_NATIVE") == "1":
                raise AssertionError(reason)
            raise unittest.SkipTest(reason)

    def test_real_tools_positive_negative_and_key_redaction_controls(self):
        # Fresh fixtures remain project-owned. A predictable test key lets this
        # regression detect accidental disclosure in the public report.
        known_key = bytes(range(17, 49))
        random_bytes = controls.secrets.token_bytes

        def first_key_then_random(size):
            if size == 32 and not first_key_then_random.used:
                first_key_then_random.used = True
                return known_key
            return random_bytes(size)

        first_key_then_random.used = False
        with patch.object(controls.secrets, "token_bytes", side_effect=first_key_then_random):
            report = controls.run_controls()
        self.assertTrue(report["ok"], [name for name, passed in report["checks"].items() if not passed])
        self.assertTrue(report["scope"]["real_binutils_executed"])
        self.assertFalse(report["scope"]["rea_cli_executed"])
        self.assertFalse(report["metadata"]["original"]["scan"]["ok"])
        self.assertTrue(report["metadata"]["split_public"]["scan"]["ok"])
        self.assertFalse(report["metadata"]["zipped_sidecar_scan"]["ok"])
        self.assertEqual(report["metadata"]["original"]["objdump_text_sha256"], report["metadata"]["split_public"]["objdump_text_sha256"])
        self.assertTrue(report["assets"]["external_key"]["scan"]["ok"])
        self.assertIn("asset_key_exposure", report["assets"]["bundled_key"]["scan"]["finding_codes"])
        serialized = json.dumps(report).encode()
        for value in (known_key, known_key.hex().encode(), known_key.hex().upper().encode(),
                      base64.b64encode(known_key), base64.urlsafe_b64encode(known_key).rstrip(b"=")):
            self.assertNotIn(value, serialized)


if __name__ == "__main__":
    unittest.main()
