"""Deterministic input changes must fail before signing, admission or publication.

These controls exercise the trusted immutable-workflow consistency checks. They
do not claim an atomic filesystem snapshot or resistance to hostile directories.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard import analysis, core, distribution, project, sealed


class ReleaseSnapshotConsistencyTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="release snapshot controls ")
        self.addCleanup(temporary.cleanup)
        # A newly created macOS fixture can have a linked temporary ancestor.
        # Canonicalize our fixture, without weakening production key traversal.
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "release"
        self.root.mkdir()
        self.first = self.root / "a.bin"
        self.second = self.root / "b.bin"
        self.first.write_bytes(b"first file: original\n")
        self.second.write_bytes(b"second file: original\n")
        self.nested = self.root / "nested"
        self.nested.mkdir()
        (self.nested / "empty.bin").write_bytes(b"")
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()
        self.key = bytes(range(32))
        self.rotated_key = bytes(range(32, 64))
        self.key_file = self.base / "external.key"
        self.key_file.write_bytes(self.key)
        self.config_dir = self.base / "config"
        project.init_project(self.root, "owned-app", self.config_dir)
        self.config = self.config_dir / "project.json"
        self.policy = self.config_dir / "policy.json"
        self.out = self.base / "sidecars"

    def manifest(self) -> dict:
        return core.create_manifest(self.root, "owned-app", "1", self.private)

    def verify(self, manifest: dict) -> dict:
        return core.verify_manifest(manifest, self.root, self.public, "owned-app", "1")

    def prepare(self) -> dict:
        return project.prepare_release(
            self.config, self.private, "1", self.out, asset_key_files=[self.key_file],
        )

    def change_first(self) -> None:
        before = self.first.stat()
        self.first.write_bytes(b"first file: modified\n")
        # Make the same-length mutation observable even on a coarse clock;
        # do not rely on sleeps or scheduler timing for the regression.
        os.utime(self.first, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))

    def during_second_digest(self, action):
        original = core._digest
        changed = False

        def digest(path, expected_size=None):
            nonlocal changed
            if Path(path) == self.second and not changed:
                changed = True
                action()
            return original(path, expected_size=expected_size)

        return digest

    def assert_no_key_material(self, rendered: bytes) -> None:
        for key in (self.key, self.rotated_key):
            for value in (
                key, key.hex().encode("ascii"), key.hex().upper().encode("ascii"),
                base64.b64encode(key), hashlib.sha256(key).hexdigest().encode("ascii"),
            ):
                self.assertNotIn(value, rendered)
        self.assertNotIn(str(self.key_file).encode("utf-8"), rendered)

    def test_unchanged_inventory_and_empty_file_still_verify(self) -> None:
        before = {
            path.relative_to(self.root).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in self.root.rglob("*") if path.is_file()
        }
        body = self.verify(self.manifest())
        self.assertEqual([item["path"] for item in body["files"]],
                         ["a.bin", "b.bin", "nested/empty.bin"])
        self.assertEqual(body["files"][2]["size"], 0)
        after = {
            path.relative_to(self.root).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in self.root.rglob("*") if path.is_file()
        }
        self.assertEqual(before, after)

    def test_creation_rejects_mutation_of_an_already_hashed_file_before_signing(self) -> None:
        with patch.object(core, "_digest", side_effect=self.during_second_digest(self.change_first)):
            with patch.object(core, "sign_document") as signing:
                with self.assertRaisesRegex(core.GuardError, "changed"):
                    self.manifest()
        signing.assert_not_called()

    def test_verification_rechecks_previously_hashed_file_identity(self) -> None:
        manifest = self.manifest()
        with patch.object(core, "_digest", side_effect=self.during_second_digest(self.change_first)):
            with self.assertRaisesRegex(core.GuardError, "changed"):
                self.verify(manifest)

    def test_cooperating_analysis_gateway_denies_the_same_mid_scan_mutation(self) -> None:
        manifest = self.manifest()
        context = dict(product="owned-app", release="1", subject="reviewer", audience="gateway")
        now = core.utc_now()
        grant = analysis.issue_analysis_grant(
            self.private, manifest, **context, operations=["inspect"], now=now,
        )
        with patch.object(core, "_digest", side_effect=self.during_second_digest(self.change_first)):
            result = analysis.check_analysis_authorization(
                manifest, self.root, self.public, **context,
                operation="inspect", grant=grant, now=now,
            )
        self.assertFalse(result["authorized"])
        self.assertEqual(result["reason"], "release_mismatch")
        self.assertFalse(result["checks"]["release_integrity"])

    def test_prepare_rejects_a_late_hash_mutation_without_creating_sidecars(self) -> None:
        with patch.object(core, "_digest", side_effect=self.during_second_digest(self.change_first)):
            with self.assertRaisesRegex(core.GuardError, "changed"):
                self.prepare()
        self.assertFalse(self.out.exists())

    def test_creation_rechecks_nested_inventory_after_hashing(self) -> None:
        def add_file():
            (self.nested / "late.bin").write_bytes(b"late release input")

        with patch.object(core, "_digest", side_effect=self.during_second_digest(add_file)):
            with self.assertRaisesRegex(core.GuardError, "changed"):
                self.manifest()

    def test_verification_rejects_removal_after_a_file_was_hashed(self) -> None:
        manifest = self.manifest()
        with patch.object(core, "_digest", side_effect=self.during_second_digest(self.first.unlink)):
            with self.assertRaisesRegex(core.GuardError, "changed"):
                self.verify(manifest)

    def test_creation_rechecks_files_after_the_signer_returns(self) -> None:
        original = core.sign_document

        def signing(*args, **kwargs):
            document = original(*args, **kwargs)
            self.change_first()
            return document

        with patch.object(core, "sign_document", side_effect=signing):
            with self.assertRaisesRegex(core.GuardError, "changed"):
                self.manifest()

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
                         "FIFO replacement control requires POSIX nonblocking opens")
    def test_fifo_replacement_is_rejected_without_waiting_for_a_writer(self) -> None:
        original = os.open

        def replace_at_open(path, flags, *args, **kwargs):
            if Path(path) == self.first:
                # Assert before replacement so an old blocking implementation
                # fails this test safely instead of hanging its test process.
                self.assertTrue(flags & os.O_NONBLOCK)
                self.first.unlink()
                os.mkfifo(self.first)
            return original(path, flags, *args, **kwargs)

        with patch.object(core.os, "open", side_effect=replace_at_open):
            with self.assertRaises(core.GuardError):
                core._digest(self.first)

    def test_creation_hash_read_is_bounded_by_the_opened_size(self) -> None:
        size = self.first.stat().st_size
        requested = []
        original = os.fdopen
        victim = self.first

        class GrowingReader:
            def __init__(self, handle):
                self.handle = handle

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return self.handle.__exit__(*args)

            def fileno(self):
                return self.handle.fileno()

            def read(self, amount):
                if not requested:
                    with victim.open("ab") as writer:
                        writer.write(b"growth" * 1024)
                requested.append(amount)
                return self.handle.read(amount)

        def wrap(descriptor, *args, **kwargs):
            return GrowingReader(original(descriptor, *args, **kwargs))

        with patch.object(core.os, "fdopen", side_effect=wrap):
            with self.assertRaises(core.GuardError):
                core._digest(self.first)
        self.assertTrue(requested)
        self.assertLessEqual(sum(requested), size + 1)

    def test_key_snapshots_are_bounded_and_their_repr_does_not_disclose_inputs(self) -> None:
        snapshots = sealed.snapshot_asset_keys([self.key_file])
        self.assertEqual(snapshots[0].key, self.key)
        sealed.assert_asset_keys_unchanged(snapshots)
        self.assert_no_key_material(repr(snapshots).encode("utf-8"))
        self.assertEqual(sealed.snapshot_asset_keys([]), ())
        for paths in (str(self.key_file), [self.key_file] * 17):
            with self.subTest(kind=type(paths).__name__), self.assertRaises(core.GuardError):
                sealed.snapshot_asset_keys(paths)

    def test_key_snapshot_rejects_rotation_without_disclosing_key_or_digest(self) -> None:
        snapshots = sealed.snapshot_asset_keys([self.key_file])
        self.key_file.write_bytes(self.rotated_key)
        with self.assertRaisesRegex(core.GuardError, "Asset key inputs changed") as failure:
            sealed.assert_asset_keys_unchanged(snapshots)
        self.assert_no_key_material(str(failure.exception).encode("utf-8"))

    def test_key_snapshot_rejects_same_value_replacement_and_missing_file(self) -> None:
        snapshots = sealed.snapshot_asset_keys([self.key_file])
        replacement = self.base / "replacement.key"
        replacement.write_bytes(self.key)
        replacement.replace(self.key_file)
        with self.assertRaisesRegex(core.GuardError, "Asset key inputs changed"):
            sealed.assert_asset_keys_unchanged(snapshots)
        snapshots = sealed.snapshot_asset_keys([self.key_file])
        self.key_file.unlink()
        with self.assertRaisesRegex(core.GuardError, "Asset key inputs changed"):
            sealed.assert_asset_keys_unchanged(snapshots)

    def test_scan_rejects_rotation_even_when_the_new_key_leaks_before_inventory(self) -> None:
        original = distribution.snapshot_asset_keys

        def capture_then_rotate(paths):
            snapshots = original(paths)
            self.key_file.write_bytes(self.rotated_key)
            self.first.write_bytes(self.rotated_key)
            return snapshots

        with patch.object(distribution, "snapshot_asset_keys", side_effect=capture_then_rotate):
            with self.assertRaisesRegex(core.GuardError, "Asset key inputs changed") as failure:
                distribution.scan_release(self.root, self.policy, asset_key_files=[self.key_file])
        self.assert_no_key_material(str(failure.exception).encode("utf-8"))

    def test_prepare_rejects_key_rotation_after_scanning_before_signing(self) -> None:
        original = project.scan_release

        def scan(*args, **kwargs):
            report = original(*args, **kwargs)
            self.key_file.write_bytes(self.rotated_key)
            return report

        with patch.object(project, "scan_release", side_effect=scan):
            with patch.object(project, "create_manifest") as signing:
                with self.assertRaisesRegex(core.GuardError, "Asset key inputs changed"):
                    self.prepare()
        signing.assert_not_called()
        self.assertFalse(self.out.exists())

    def test_prepare_rejects_key_rotation_after_manifest_creation(self) -> None:
        original = project.create_manifest

        def sign(*args, **kwargs):
            manifest = original(*args, **kwargs)
            self.key_file.write_bytes(self.rotated_key)
            return manifest

        with patch.object(project, "create_manifest", side_effect=sign):
            with self.assertRaisesRegex(core.GuardError, "Asset key inputs changed"):
                self.prepare()
        self.assertFalse(self.out.exists())

    def test_prepare_rolls_back_all_new_sidecars_if_key_changes_while_writing(self) -> None:
        original = project.write_new
        written = []

        def write(path, content, **kwargs):
            original(path, content, **kwargs)
            written.append(Path(path).name)
            if Path(path).name == "manifest.json":
                self.key_file.write_bytes(self.rotated_key)

        with patch.object(project, "write_new", side_effect=write):
            with self.assertRaisesRegex(core.GuardError, "Asset key inputs changed"):
                self.prepare()
        self.assertIn("manifest.json", written)
        self.assertFalse(self.out.exists())
        self.assertEqual(self.first.read_bytes(), b"first file: original\n")

    def test_prepare_rolls_back_sidecars_when_release_changes_during_bundle_writes(self) -> None:
        original = project.write_new

        def write(path, content, **kwargs):
            original(path, content, **kwargs)
            if Path(path).name == "manifest.json":
                self.change_first()

        with patch.object(project, "write_new", side_effect=write):
            with self.assertRaises(core.GuardError):
                # No asset keys: rejection must come from the final release
                # verification, rather than a changed-key check.
                project.prepare_release(self.config, self.private, "1", self.out)
        self.assertFalse(self.out.exists())
        self.assertEqual(self.first.read_bytes(), b"first file: modified\n")

    def test_unchanged_key_preparation_keeps_key_material_out_of_all_reports(self) -> None:
        result = self.prepare()
        self.assertTrue(result["prepared"])
        self.assertEqual(result["scan"]["checks"]["asset_keys_checked"], 1)
        self.assert_no_key_material(json.dumps(result).encode("utf-8"))
        for path in self.out.iterdir():
            self.assert_no_key_material(path.read_bytes())
        self.verify(core.read_document(self.out / "manifest.json"))


if __name__ == "__main__":
    unittest.main()
