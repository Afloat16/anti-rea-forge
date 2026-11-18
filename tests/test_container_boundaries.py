"""Recognized opaque containers must not be reported as inspected payloads."""

import json
from pathlib import Path
import struct
import tempfile
import unittest

from releaseguard.distribution import scan_release
from tests.test_asar import asar, zip_archive


class ContainerBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned container boundaries ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "release"
        self.root.mkdir()
        self.policy = self.work / "policy.json"
        self.policy.write_text(json.dumps({"version": 1}))
        # A project-owned header marker, not a claimed valid or signed OTA image.
        self.payload = b"CrAU" + struct.pack(">QQI", 2, 0, 0)
        self.target = self.root / "renamed.bin"

    def test_android_ota_marker_is_explicitly_unsupported(self):
        self.target.write_bytes(self.payload)
        report = scan_release(self.root, self.policy)
        self.assertFalse(report["ok"])
        self.assertFalse(report["checks"]["archive_scan_completed"])
        self.assertTrue(any(item["code"] == "unsupported_archive" and item["path"] == "renamed.bin"
                            for item in report["findings"]))
        self.assertEqual(self.target.read_bytes(), self.payload)

    def test_android_ota_marker_inside_supported_containers_cannot_pass(self):
        for package in (zip_archive("firmware.payload", self.payload),
                        asar([("firmware.payload", self.payload)])):
            with self.subTest(package_bytes=len(package)):
                self.target.write_bytes(package)
                report = scan_release(self.root, self.policy)
                self.assertFalse(report["ok"])
                self.assertFalse(report["checks"]["archive_scan_completed"])
                self.assertTrue(any(item["code"] == "unsupported_archive" and
                                    item.get("archive_members") == ["firmware.payload"]
                                    for item in report["findings"]))


if __name__ == "__main__":
    unittest.main()
