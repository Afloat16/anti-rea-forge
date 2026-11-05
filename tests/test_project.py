"""Build-only integration must preserve releases and fail before publication."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard.core import GuardError, create_manifest, read_document, verify_manifest
from releaseguard.project import check_project, init_project, load_project, prepare_release


class ProjectTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="releaseguard project ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.release = self.work / "release with spaces"
        self.release.mkdir()
        self.app = self.release / "app.py"
        self.marker = self.work / "must-not-run"
        self.app.write_text(
            f"from pathlib import Path\nPath({str(self.marker)!r}).write_text('ran')\n",
            encoding="utf-8",
        )
        self.assets = self.release / "assets.bin"
        self.assets.write_bytes(bytes(range(256)) * 4096)
        self.directory = self.work / "guard config"
        self.config = self.directory / "project.json"
        self.output = self.work / "release evidence"
        self.private = Ed25519PrivateKey.generate()

    def initialize(self):
        return init_project(self.release, "Example 产品", self.directory)

    def snapshot(self):
        return {
            path.relative_to(self.release).as_posix():
                (path.read_bytes(), path.stat().st_size, path.stat().st_mtime_ns, path.stat().st_mode)
            for path in self.release.rglob("*") if path.is_file()
        }

    def test_init_check_prepare_preserve_bytes_size_mtime_mode_and_never_execute(self):
        before = self.snapshot()
        setup = self.initialize()
        self.assertTrue(setup["ok"])
        self.assertFalse(setup["release_modified"])
        self.assertTrue(check_project(self.config)["ok"])
        prepared = prepare_release(self.config, self.private, "1.2.3", self.output)
        self.assertTrue(prepared["prepared"])
        self.assertFalse(prepared["application_runtime_integration"])
        self.assertEqual(set(self.output.iterdir()), {
            self.output / name for name in ("manifest.json", "ANALYSIS_NOTICE.md", "release-report.json")
        })
        body = verify_manifest(read_document(self.output / "manifest.json"), self.release,
                               self.private.public_key(), "Example 产品", "1.2.3")
        self.assertEqual(len(body["files"]), 2)
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.marker.exists())

    def test_root_can_be_built_after_initialization(self):
        future = self.work / "future release"
        init_project(future, "future", self.directory)
        self.assertFalse(future.exists())
        future.mkdir()
        (future / "app.js").write_text("export const answer = 42;", encoding="utf-8")
        self.assertTrue(check_project(self.config)["ok"])

    def test_project_identifiers_cannot_create_an_unusable_analysis_manifest(self):
        invalid = (" Demo ", "产" * 100, "e\u0301", "demo\u200b")
        for product in invalid:
            with self.subTest(product=product), self.assertRaises(GuardError):
                init_project(self.release, product, self.directory)
            self.assertFalse(self.directory.exists())
        self.initialize()
        for release in invalid:
            with self.subTest(release=release), self.assertRaises(GuardError):
                prepare_release(self.config, self.private, release, self.output)
            self.assertFalse(self.output.exists())

    def test_existing_non_directory_root_is_rejected_before_configuration_is_written(self):
        with self.assertRaises(GuardError):
            init_project(self.app, "demo", self.directory)
        self.assertFalse(self.directory.exists())

    def test_root_link_cannot_silently_pin_the_wrong_release(self):
        alias = self.work / "current-release"
        try:
            alias.symlink_to(self.release, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Directory symlinks are not available")
        with self.assertRaisesRegex(GuardError, "link/reparse"):
            init_project(alias, "demo", self.directory)
        self.assertFalse(self.directory.exists())

    def test_paths_are_relative_to_config_and_survive_project_move(self):
        self.initialize()
        document = read_document(self.config)
        self.assertEqual(document["root"], "../release with spaces")
        moved = self.work / "moved"
        moved.mkdir()
        self.release.rename(moved / self.release.name)
        self.directory.rename(moved / self.directory.name)
        report = check_project(moved / self.directory.name / "project.json")
        self.assertTrue(report["ok"])
        self.assertEqual(Path(report["root"]), moved / self.release.name)

    def test_findings_do_not_create_signed_material(self):
        self.initialize()
        (self.release / "private.map").write_text('{"sourcesContent":["private"]}', encoding="utf-8")
        result = prepare_release(self.config, self.private, "1", self.output)
        self.assertFalse(result["ok"])
        self.assertFalse(result["prepared"])
        self.assertEqual(result["outputs"], {})
        self.assertFalse(self.output.exists())

    def test_changed_release_between_scan_and_sign_is_not_published(self):
        self.initialize()

        def changed(*args, **kwargs):
            self.app.write_text("answer = 43\n", encoding="utf-8")
            return create_manifest(*args, **kwargs)

        with patch("releaseguard.project.create_manifest", side_effect=changed):
            with self.assertRaisesRegex(GuardError, "changed between scanning and signing"):
                prepare_release(self.config, self.private, "1", self.output)
        self.assertFalse(self.output.exists())

    def test_existing_config_and_bundle_are_never_overwritten(self):
        self.initialize()
        original = self.config.read_bytes()
        with self.assertRaises(FileExistsError):
            self.initialize()
        self.assertEqual(self.config.read_bytes(), original)
        self.output.mkdir()
        sentinel = self.output / "sentinel"
        sentinel.write_bytes(b"keep")
        with self.assertRaises(GuardError):
            prepare_release(self.config, self.private, "1", self.output)
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_configuration_and_outputs_cannot_be_inside_release(self):
        for output in (self.release, self.release / "guard"):
            with self.subTest(output=output), self.assertRaises(GuardError):
                init_project(self.release, "Example", output)
        self.initialize()
        with self.assertRaises(GuardError):
            prepare_release(self.config, self.private, "1", self.release / "guard")

    def test_policy_must_stay_outside_the_release(self):
        self.initialize()
        document = read_document(self.config)
        document["policy"] = str(self.release / "policy.json")
        self.config.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(GuardError, "Scan policy must be outside"):
            load_project(self.config)

    def test_ambiguous_unknown_or_unbounded_configuration_is_rejected(self):
        self.initialize()
        original = read_document(self.config)
        cases = [
            '{"version":1,"version":1}',
            json.dumps({**original, "version": True}),
            json.dumps({**original, "command": "anything"}),
            json.dumps({**original, "root": "\x00"}),
            " " * 65537,
        ]
        for value in cases:
            with self.subTest(value=value[:80]):
                self.config.write_text(value, encoding="utf-8")
                with self.assertRaises(GuardError):
                    load_project(self.config)

    def test_configuration_symlink_or_special_file_is_rejected(self):
        self.initialize()
        target = self.config.with_name("target.json")
        self.config.rename(target)
        try:
            self.config.symlink_to(target)
        except (OSError, NotImplementedError):
            # Windows without link privilege still exercises the directory case.
            self.config.mkdir()
        with self.assertRaises(GuardError):
            load_project(self.config)

    def test_partial_initialization_is_cleaned_up(self):
        from releaseguard.project import write_new

        def failing(path, content, **kwargs):
            if Path(path).name == "policy.json":
                raise OSError("Synthetic write failure")
            return write_new(path, content, **kwargs)

        with patch("releaseguard.project.write_new", side_effect=failing):
            with self.assertRaises(OSError):
                self.initialize()
        self.assertFalse(self.directory.exists())

    def test_notice_has_context_and_no_self_issued_trust(self):
        self.initialize()
        result = prepare_release(self.config, self.private, "1", self.output)
        notice = (self.output / "ANALYSIS_NOTICE.md").read_text(encoding="utf-8")
        self.assertIn(result["manifest_sha256"], notice)
        self.assertIn("unsigned information", notice)
        self.assertIn("does not change the software license", notice)
        self.assertNotIn("BEGIN PRIVATE KEY", notice)


if __name__ == "__main__":
    unittest.main()
