"""Declared private files must stay outside a complete public release scan."""

import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from releaseguard.core import GuardError
from releaseguard.distribution import scan_release
from releaseguard.private_inputs import (
    MAX_PRIVATE_INPUT_BYTES, assert_private_inputs_unchanged, snapshot_private_inputs,
)


def packed_asar(data, *, unpacked=False):
    entry = {"size": len(data), **({"unpacked": True} if unpacked else {"offset": "0"})}
    header = json.dumps({"files": {"renamed.dat": entry}}, separators=(",", ":")).encode()
    padding = b"\0" * (-len(header) % 4)
    size = len(header) + len(padding) + 8
    return struct.pack("<4I", 4, size, size - 4, len(header)) + header + padding + (b"" if unpacked else data)


def zipped(name, data):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, data)
    return output.getvalue()


class PrivateInputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="private input controls ")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "public"
        self.root.mkdir()
        self.private = self.base / "private-implementation.js"
        self.data = b"export function privateQuote(x) { return x * 37 + 19; }\n"
        self.private.write_bytes(self.data)
        self.app = self.root / "client.js"
        self.app.write_bytes(b"export const operation = 'quote';\n")
        self.policy = self.base / "policy.json"
        self.policy.write_text('{"version":1}', encoding="ascii")

    def snapshots(self, paths=None):
        return snapshot_private_inputs([self.private] if paths is None else paths, root=self.root)

    def scan(self):
        return scan_release(self.root, self.policy, private_input_files=[self.private])

    def test_snapshot_is_bounded_hash_evidence_without_public_repr(self):
        snapshots = self.snapshots()
        self.assertEqual(snapshots[0].sha256, hashlib.sha256(self.data).hexdigest())
        self.assertEqual(snapshots[0].size, len(self.data))
        self.assertNotIn(str(self.private), repr(snapshots))
        self.assertNotIn(snapshots[0].sha256, repr(snapshots))
        assert_private_inputs_unchanged(snapshots)

    def test_no_reference_metadata_or_contents_in_clean_report(self):
        report = self.scan()
        self.assertTrue(report["ok"])
        self.assertEqual(report["checks"]["private_inputs_checked"], 1)
        rendered = json.dumps(report)
        for private_value in (str(self.private), self.private.name, self.data.decode(),
                              hashlib.sha256(self.data).hexdigest()):
            self.assertNotIn(private_value, rendered)

    def test_renamed_disk_zip_nested_zip_asar_and_zip_asar_copies_are_rejected(self):
        cases = {
            "renamed.bin": self.data,
            "renamed.zip": zipped("renamed.bin", self.data),
            "nested.zip": zipped("inside.zip", zipped("renamed.bin", self.data)),
            "app.asar": packed_asar(self.data),
            "asar.zip": zipped("app.asar", packed_asar(self.data)),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                target = self.root / name
                target.write_bytes(data)
                report = self.scan()
                matches = [item for item in report["findings"] if item["code"] == "private_input_exposure"]
                self.assertFalse(report["ok"])
                self.assertTrue(matches)
                self.assertTrue(all(item["rule_index"] == 0 for item in matches))
                self.assertNotIn(str(self.private), json.dumps(report))
                self.assertTrue(all("sha256" not in item and "private_path" not in item for item in matches))
                target.unlink()

    def test_unpacked_asar_disk_and_zip_siblings_use_the_same_rule(self):
        archive = packed_asar(self.data, unpacked=True)
        (self.root / "app.asar").write_bytes(archive)
        sidecars = self.root / "app.asar.unpacked"
        sidecars.mkdir()
        (sidecars / "renamed.dat").write_bytes(self.data)
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"]["asar_unpacked_members_checked"], 1)
        (self.root / "app.asar").unlink()
        (sidecars / "renamed.dat").unlink()
        sidecars.rmdir()
        with zipfile.ZipFile(self.root / "package.zip", "w", zipfile.ZIP_DEFLATED) as package:
            package.writestr("app.asar", archive)
            package.writestr("app.asar.unpacked/renamed.dat", self.data)
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertTrue(any(item["code"] == "private_input_exposure" and item.get("archive_members") ==
                            ["app.asar.unpacked/renamed.dat"] for item in report["findings"]))

    def test_same_filename_with_public_bytes_passes_and_edited_copy_is_an_explicit_limit(self):
        target = self.root / self.private.name
        target.write_bytes(b"export const publicVersion = 1;\n")
        self.assertTrue(self.scan()["ok"])
        target.write_bytes(self.data + b"\n")
        # This reference rule covers exact whole-file copies, not transformed
        # or embedded logic. Keep this negative control to prevent overclaims.
        self.assertTrue(self.scan()["ok"])

    def test_references_must_be_nonempty_regular_files_outside_release(self):
        for path in (self.app, self.root, self.base / "missing"):
            with self.subTest(kind=path.name), self.assertRaises(GuardError) as caught:
                self.snapshots([path])
            self.assertNotIn(str(path), str(caught.exception))
        self.private.write_bytes(b"")
        with self.assertRaisesRegex(GuardError, "1 byte"):
            self.snapshots()
        if hasattr(os, "mkfifo"):
            fifo = self.base / "private-fifo"
            os.mkfifo(fifo)
            with self.assertRaises(GuardError):
                self.snapshots([fifo])

    def test_linked_leaf_and_ancestor_are_rejected(self):
        directory = self.base / "private-directory"
        directory.mkdir()
        (directory / "data").write_bytes(self.data)
        alias = self.base / "linked-private-directory"
        leaf = self.base / "linked-private-file"
        try:
            alias.symlink_to(directory, target_is_directory=True)
            leaf.symlink_to(self.private)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks are unavailable")
        for path in (alias / "data", leaf):
            with self.subTest(path=path.name), self.assertRaises(GuardError):
                self.snapshots([path])

    def test_changed_replaced_missing_and_linked_inputs_fail_recheck(self):
        for change in ("modify", "replace", "remove", "link"):
            with self.subTest(change=change):
                self.private.unlink(missing_ok=True)
                self.private.write_bytes(self.data)
                snapshots = self.snapshots()
                if change == "modify":
                    self.private.write_bytes(self.data.replace(b"37", b"38"))
                elif change == "replace":
                    temporary = self.base / "replacement"
                    temporary.write_bytes(self.data)
                    temporary.replace(self.private)
                elif change == "remove":
                    self.private.unlink()
                else:
                    self.private.unlink()
                    try:
                        self.private.symlink_to(self.app)
                    except (OSError, NotImplementedError):
                        continue
                with self.assertRaisesRegex(GuardError, "changed during") as caught:
                    assert_private_inputs_unchanged(snapshots)
                self.assertNotIn(str(self.private), str(caught.exception))

    def test_count_type_per_file_and_total_limits_fail_closed(self):
        for paths in (None, "file", [42], [""], ["bad\0path"], [self.private] * 65):
            with self.subTest(kind=type(paths).__name__), self.assertRaises(GuardError):
                snapshot_private_inputs(paths, root=self.root)
        with self.private.open("wb") as handle:
            handle.truncate(MAX_PRIVATE_INPUT_BYTES + 1)
        with self.assertRaisesRegex(GuardError, "8 MiB"):
            self.snapshots()
        with self.private.open("wb") as handle:
            handle.truncate(MAX_PRIVATE_INPUT_BYTES)
        self.assertEqual(len(self.snapshots([self.private] * 8)), 8)
        with self.assertRaisesRegex(GuardError, "64 MiB"):
            self.snapshots([self.private] * 9)

    def test_snapshot_does_not_import_or_execute_private_source(self):
        marker = self.base / "must-not-execute"
        self.private.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n", encoding="utf-8")
        self.snapshots()
        self.assertTrue(self.scan()["ok"])
        self.assertFalse(marker.exists())

    def test_scan_rechecks_private_inputs_after_reading_public_payloads(self):
        from releaseguard.distribution import _Scanner
        original = _Scanner.payload

        def changing(scanner, *args, **kwargs):
            result = original(scanner, *args, **kwargs)
            self.private.write_bytes(self.data.replace(b"37", b"39"))
            return result

        with patch.object(_Scanner, "payload", changing), self.assertRaisesRegex(GuardError, "changed during"):
            self.scan()

    def test_snapshot_rejects_mutation_while_reading(self):
        original = os.read
        altered = False

        def changing(descriptor, count):
            nonlocal altered
            data = original(descriptor, count)
            if data and not altered:
                altered = True
                self.private.write_bytes(self.data.replace(b"37", b"40"))
            return data

        with patch("releaseguard.private_inputs.os.read", side_effect=changing):
            with self.assertRaisesRegex(GuardError, "changed while"):
                self.snapshots()


if __name__ == "__main__":
    unittest.main()
