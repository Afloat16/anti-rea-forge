"""Real MSVC PDB control; require with RELEASEGUARD_REQUIRE_PDB_TOOLCHAIN=1."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from releaseguard.distribution import scan_release
from tests.test_asar import zip_archive


class RealMsvcPdbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        required = os.environ.get("RELEASEGUARD_REQUIRE_PDB_TOOLCHAIN") == "1"
        if sys.platform != "win32":
            if required:
                raise AssertionError("Mandatory MSVC PDB controls require Windows")
            raise unittest.SkipTest("Real MSVC PDB generation requires Windows")
        cls.compiler = shutil.which("cl")
        if cls.compiler is None:
            if required:
                raise AssertionError("Mandatory MSVC PDB controls require cl in a developer environment")
            raise unittest.SkipTest("MSVC is unavailable; initialize its developer environment")

    def test_real_msvc_pdb_is_blocked_when_renamed_or_zipped(self):
        with tempfile.TemporaryDirectory(prefix="owned pdb controls ") as temporary:
            work = Path(temporary).resolve()
            source = work / "owned_pdb_source.c"
            private_name = "owned_private_rule_for_pdb"
            source.write_text(
                "__declspec(noinline) static int " + private_name
                + "(int x) { return x * 37 + 19; }\n"
                "int main(void) { return " + private_name + "(3) == 130 ? 0 : 1; }\n",
                encoding="utf-8")

            def run(*arguments):
                result = subprocess.run([str(arg) for arg in arguments], cwd=work,
                                        capture_output=True, text=True, encoding="utf-8",
                                        errors="replace", timeout=60)
                self.assertEqual(result.returncode, 0,
                                 f"Command: {arguments!r}\n{result.stdout}\n{result.stderr}")
                return result.stdout

            # Explicitly keep private functions and full linker debug records;
            # a successful empty/stale PDB must not satisfy this control.
            run(self.compiler, "/nologo", "/Zi", "/Od", "/Ob0", "/FC",
                "/Foowned.obj", "/Fdowned-compiler.pdb", "/Feowned.exe", source,
                "/link", "/DEBUG:FULL", "/PDB:owned-linker.pdb", "/INCREMENTAL:NO",
                "/OPT:NOREF", "/OPT:NOICF")
            run(work / "owned.exe")
            pdb = work / "owned-linker.pdb"
            self.assertTrue(pdb.is_file(), "MSVC must emit the requested linker PDB")
            data = pdb.read_bytes()
            self.assertTrue(data.startswith(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"))
            self.assertTrue(private_name.encode("ascii") in data,
                            "The control must expose the owned private symbol")
            self.assertTrue(source.name.encode("ascii") in data,
                            "The control must expose its owned source-file marker")
            before = hashlib.sha256(data).hexdigest()

            release = work / "release"
            release.mkdir()
            target = release / "symbols.data"
            policy = work / "policy.json"
            policy.write_text('{"version":1}', encoding="utf-8")
            # A clean byte payload confirms this is content recognition, not a
            # blanket denial caused by the innocuous renamed filename.
            target.write_bytes(b"public distribution metadata")
            self.assertTrue(scan_release(release, policy)["ok"])
            for label, payload, members in (
                ("renamed", data, ()),
                ("zip", zip_archive("nested/symbols.data", data), ("nested/symbols.data",)),
            ):
                with self.subTest(container=label):
                    target.write_bytes(payload)
                    payload_hash = hashlib.sha256(payload).hexdigest()
                    report = scan_release(release, policy)
                    self.assertFalse(report["ok"])
                    self.assertFalse(report["checks"]["native_metadata_scan_completed"])
                    self.assertEqual(report["checks"]["native_files_checked"], 1)
                    expected = {"code": "native_metadata_unverifiable", "path": target.name,
                                "format": "msf7", "reason": "unsupported_standalone_metadata"}
                    if members:
                        expected["archive_members"] = list(members)
                    self.assertEqual(report["findings"], [expected])
                    self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), payload_hash)
                    self.assertEqual(hashlib.sha256(pdb.read_bytes()).hexdigest(), before)


if __name__ == "__main__":
    unittest.main()
