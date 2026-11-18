"""Wasm metadata inspection stays enabled through CLI and archive namespaces."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from releaseguard.distribution import scan_release
from tests.test_asar import asar, zip_archive
from tests.test_wasm import HEADER, PRIVATE_FUNCTION, custom, owned_core, owned_module


class WasmDistributionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned wasm distribution ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "release"
        self.root.mkdir()
        self.target = self.root / "renamed.data"
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="utf-8")

    def test_renamed_owned_module_is_blocked_without_echoing_private_names(self):
        self.target.write_bytes(owned_module())
        report = scan_release(self.root, self.policy)
        self.assertFalse(report["ok"])
        self.assertTrue(report["checks"]["native_metadata_scan_completed"])
        self.assertEqual(report["checks"]["native_files_checked"], 1)
        self.assertEqual({row["code"] for row in report["findings"] if row.get("format") == "wasm"},
                         {"native_debug_metadata", "native_symbol_table"})
        self.assertNotIn(PRIVATE_FUNCTION, json.dumps(report))

    def test_nested_zip_and_asar_use_the_same_metadata_inspector(self):
        for wrap, members in ((lambda data: zip_archive("inner.zip", zip_archive("item.bin", data)), ["inner.zip", "item.bin"]),
                              (lambda data: asar([("item.bin", data)]), ["item.bin"])):
            with self.subTest(members=members):
                self.target.write_bytes(wrap(owned_module()))
                report = scan_release(self.root, self.policy)
                self.assertFalse(report["ok"])
                findings = [item for item in report["findings"] if item.get("format") == "wasm"]
                self.assertEqual(len(findings), 2)
                self.assertTrue(all(row["archive_members"] == members for row in findings))

    def test_component_unknown_section_and_truncated_core_fail_as_unverifiable(self):
        for payload in (b"\0asm", b"\0asm\x0d\0\1\0", HEADER + b"\x0e\1\0"):
            with self.subTest(payload=payload):
                self.target.write_bytes(payload)
                report = scan_release(self.root, self.policy)
                self.assertFalse(report["ok"])
                self.assertFalse(report["checks"]["native_metadata_scan_completed"])
                self.assertEqual(report["findings"], [{
                    "code": "native_metadata_unverifiable", "path": self.target.name,
                    "format": "wasm", "reason": "invalid_or_unsupported_metadata"}])

    def test_clean_core_and_explicit_opt_out_keep_compatibility(self):
        self.target.write_bytes(owned_core())
        self.assertTrue(scan_release(self.root, self.policy)["ok"])
        # Source-map marker checks are an independent policy surface. This
        # control uses the name section alone to isolate metadata opt-out.
        from tests.test_wasm import owned_names
        self.target.write_bytes(owned_core() + owned_names())
        self.policy.write_text('{"version":1,"check_native_metadata":false}', encoding="utf-8")
        report = scan_release(self.root, self.policy)
        self.assertTrue(report["ok"])
        self.assertFalse(report["checks"]["native_metadata_checked"])

    def test_linker_metadata_blocks_renamed_and_nested_releases_as_uninspected(self):
        payload = owned_core() + custom("linking", b"owned-private-linker-symbol")
        for content, members in ((payload, None),
                                 (zip_archive("module.bin", payload), ["module.bin"]),
                                 (asar([("module.bin", payload)]), ["module.bin"])):
            with self.subTest(members=members):
                self.target.write_bytes(content)
                report = scan_release(self.root, self.policy)
                self.assertFalse(report["ok"])
                self.assertFalse(report["checks"]["native_metadata_scan_completed"])
                expected = {"code": "native_metadata_unverifiable", "path": self.target.name,
                            "format": "wasm", "reason": "linker_metadata_requires_final_link"}
                if members is not None:
                    expected["archive_members"] = members
                self.assertEqual(report["findings"], [expected])
                self.assertNotIn("owned-private-linker-symbol", json.dumps(report))

    def test_real_cli_split_public_gate_and_private_restore_gate(self):
        self.target.write_bytes(owned_module())
        public_dir, private_dir = self.work / "public", self.work / "private"
        public_dir.mkdir()
        private_dir.mkdir()
        public, private = public_dir / "module.wasm", private_dir / "original.wasm"
        argv = [sys.executable, "-I", "-m", "releaseguard", "split-wasm-debug", "--input", str(self.target),
                "--public", str(public), "--private", str(private)]
        run = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout)
        self.assertTrue(result["ok"])
        self.assertEqual(result["private_original"], str(private))
        self.assertEqual(private.read_bytes(), self.target.read_bytes())
        self.assertTrue(scan_release(public_dir, self.policy)["ok"])
        self.assertFalse(scan_release(private_dir, self.policy)["ok"])
        repeated = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        self.assertEqual(repeated.returncode, 2)
        self.assertIn("error", json.loads(repeated.stderr))


if __name__ == "__main__":
    unittest.main()
