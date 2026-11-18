"""Uninspected static-library containers must not bypass native release gates."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from releaseguard.distribution import scan_release
from tests.test_asar import asar, zip_archive


class ArBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned ar boundaries ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "release"
        self.root.mkdir()
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="utf-8")
        self.target = self.root / "renamed.bin"

    def assert_unsupported(self, data, *, members=()):
        self.target.write_bytes(data)
        report = scan_release(self.root, self.policy)
        self.assertFalse(report["ok"])
        self.assertFalse(report["checks"]["archive_scan_completed"])
        finding = next(item for item in report["findings"]
                       if item["code"] == "unsupported_archive")
        self.assertEqual(finding["path"], "renamed.bin")
        self.assertEqual(finding.get("archive_members", []), list(members))
        self.assertEqual(self.target.read_bytes(), data)
        return report

    def test_regular_and_thin_ar_are_detected_without_filename_hints(self):
        for magic in (b"!<arch>\n", b"!<thin>\n"):
            with self.subTest(magic=magic):
                # Even an empty archive cannot claim member inspection: the
                # format is deliberately unsupported, not parsed as text.
                self.assert_unsupported(magic)

    def test_nested_renamed_ar_members_are_explicitly_unsupported(self):
        for magic in (b"!<arch>\n", b"!<thin>\n"):
            for wrapper in (lambda data: zip_archive("inner.data", data),
                            lambda data: asar([("inner.data", data)])):
                with self.subTest(magic=magic, wrapper=wrapper):
                    self.assert_unsupported(wrapper(magic), members=("inner.data",))

    def test_expected_static_library_and_debian_extensions_do_not_silently_pass(self):
        for name in ("library.a", "library.LIB", "package.deb"):
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(b"truncated or unsupported container")
                report = scan_release(self.root, self.policy)
                self.assertFalse(report["ok"])
                self.assertEqual(report["findings"], [
                    {"code": "unsupported_archive", "path": name}])
                path.unlink()

    def test_disabling_other_archive_readers_does_not_allow_ar(self):
        self.policy.write_text(json.dumps({"version": 1, "scan_zip_archives": False,
                                           "scan_asar_archives": False,
                                           "check_native_metadata": False}), encoding="utf-8")
        self.assert_unsupported(b"!<arch>\n")

    def test_magic_in_ordinary_text_is_not_treated_as_an_archive_header(self):
        self.target.write_bytes(b"A public description of !<arch>\n and !<thin>\n")
        self.assertTrue(scan_release(self.root, self.policy)["ok"])

    def test_real_gnu_ar_library_and_thin_references_are_blocked(self):
        required = os.environ.get("RELEASEGUARD_REQUIRE_AR_TOOLCHAIN") == "1"
        if not sys.platform.startswith("linux"):
            if required:
                self.fail("Mandatory GNU ar controls require Linux")
            self.skipTest("GNU ar object controls require Linux")
        cc, ar, nm = (shutil.which(name) for name in ("cc", "ar", "nm"))
        if not all((cc, ar, nm)):
            if required:
                self.fail("Mandatory GNU ar controls require cc, ar and nm")
            self.skipTest("GNU ar object controls need cc, ar and nm")

        def run(*args):
            result = subprocess.run([str(value) for value in args], cwd=self.work,
                                    check=True, capture_output=True, text=True, timeout=60)
            return result.stdout

        if "GNU ar" not in run(ar, "--version"):
            if required:
                self.fail("Mandatory GNU ar controls require GNU binutils ar")
            self.skipTest("The available ar is not GNU binutils")
        (self.work / "owned.c").write_text(
            "static int owned_private_rule(int x) { return x * 7 + 3; }\n"
            "int owned_public_entry(int x) { return owned_private_rule(x); }\n",
            encoding="utf-8")
        run(cc, "-O0", "-g", "-c", "owned.c", "-o", "owned.o")
        obj = self.work / "owned.o"
        self.assertIn("owned_private_rule", run(nm, "-a", obj))
        self.assertIn(b".debug_info", obj.read_bytes())
        # This independently proves ordinary native debug bytes are present;
        # denial must survive wrapping those same bytes in an archive.
        self.target.write_bytes(obj.read_bytes())
        self.assertFalse(scan_release(self.root, self.policy)["ok"])
        for name, flags, magic in (("regular.a", "rcs", b"!<arch>\n"),
                                   ("thin.a", "rcsT", b"!<thin>\n")):
            run(ar, flags, name, "owned.o")
            library = self.work / name
            data = library.read_bytes()
            self.assertTrue(data.startswith(magic))
            self.assertIn("owned_private_rule", run(nm, "-a", library))
            self.assert_unsupported(data)
            if flags == "rcsT":
                # Scanning the copied thin archive must not open external paths.
                obj.unlink()
                self.assert_unsupported(data)


if __name__ == "__main__":
    unittest.main()
