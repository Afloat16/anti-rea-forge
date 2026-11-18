"""Configure protection inputs once without unsafe or unusable setup output."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from releaseguard.core import GuardError
from releaseguard.project import check_project, init_project, load_project


class ProjectInitInputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="project init inputs ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.project = self.work / "owned project"
        self.project.mkdir()
        self.root = self.project / "public"
        self.root.mkdir()
        self.app = self.root / "client.js"
        self.app.write_bytes(b"export const operation = 'quote';\n")
        self.secrets = self.project / "private inputs"
        self.secrets.mkdir()
        self.private = self.secrets / "private implementation.py"
        self.private_bytes = b"def private_quote(units):\n    return units * 117 + 23\n"
        self.private.write_bytes(self.private_bytes)
        self.key = self.secrets / "asset key.bin"
        self.key_bytes = bytes(range(32))
        self.key.write_bytes(self.key_bytes)
        self.output = self.project / "guard config"

    def initialize(self, **kwargs):
        return init_project(self.root, "owned-service", self.output, **kwargs)

    def test_saves_validated_relative_paths_without_disclosing_reference_material(self):
        before = self.app.read_bytes(), self.app.stat()
        result = self.initialize(asset_key_files=[self.key], private_input_files=[self.private])
        document = json.loads((self.output / "project.json").read_text())
        self.assertEqual(document["asset_key_files"], ["../private inputs/asset key.bin"])
        self.assertEqual(document["private_input_files"], ["../private inputs/private implementation.py"])
        self.assertEqual(set(result), {"ok", "config", "policy", "notice", "release_modified"})
        serialized = json.dumps(result)
        for secret in (self.private.name, self.key.name, str(self.private), str(self.key),
                       self.private_bytes.decode(), self.key_bytes.hex(),
                       hashlib.sha256(self.private_bytes).hexdigest()):
            self.assertNotIn(secret, serialized)
        report = check_project(self.output / "project.json")
        self.assertTrue(report["ok"])
        self.assertEqual(report["checks"]["asset_keys_checked"], 1)
        self.assertEqual(report["checks"]["private_inputs_checked"], 1)
        self.assertEqual(self.app.read_bytes(), before[0])
        self.assertEqual(self.app.stat().st_mtime_ns, before[1].st_mtime_ns)

    def test_saved_references_survive_project_move_and_reject_copy_without_extra_arguments(self):
        self.initialize(asset_key_files=[self.key], private_input_files=[self.private])
        moved = self.work / "moved project"
        self.project.rename(moved)
        config = moved / self.output.name / "project.json"
        self.assertTrue(check_project(config)["ok"])
        (moved / self.root.name / "renamed.bin").write_bytes(self.private_bytes)
        report = check_project(config)
        self.assertFalse(report["ok"])
        self.assertTrue(any(f["code"] == "private_input_exposure" for f in report["findings"]))

    def test_future_release_can_be_initialized_with_existing_external_inputs(self):
        future = self.project / "future public"
        init_project(future, "future-service", self.output,
                     asset_key_files=[self.key], private_input_files=[self.private])
        self.assertFalse(future.exists())
        future.mkdir()
        (future / "client.js").write_bytes(b"export {};\n")
        self.assertTrue(check_project(self.output / "project.json")["ok"])

    def test_missing_empty_directory_and_excessive_private_inputs_create_nothing(self):
        empty = self.secrets / "empty.bin"
        empty.touch()
        oversized = self.secrets / "oversized.bin"
        with oversized.open("wb") as handle:
            handle.truncate(8 * 1024 * 1024 + 1)
        for paths in ([self.secrets / "missing.bin"], [empty], [self.secrets], [oversized],
                      [self.private] * 65, "not-a-sequence", [42]):
            with self.subTest(paths_type=type(paths).__name__):
                with self.assertRaises(GuardError):
                    self.initialize(private_input_files=paths)
                self.assertFalse(self.output.exists())

    def test_invalid_keys_create_nothing(self):
        short = self.secrets / "short.key"
        short.write_bytes(b"short")
        for paths in ([self.secrets / "missing.key"], [short], [self.secrets], [self.key] * 17,
                      "not-a-sequence", [42]):
            with self.subTest(paths_type=type(paths).__name__):
                with self.assertRaises(GuardError):
                    self.initialize(asset_key_files=paths)
                self.assertFalse(self.output.exists())

    def test_release_local_private_inputs_and_keys_are_rejected(self):
        public_key = self.root / "key.bin"
        public_key.write_bytes(self.key_bytes)
        for kwargs in ({"asset_key_files": [public_key]}, {"private_input_files": [self.app]}):
            with self.subTest(kind=next(iter(kwargs))):
                with self.assertRaisesRegex(GuardError, "outside"):
                    self.initialize(**kwargs)
                self.assertFalse(self.output.exists())

    def test_linked_inputs_and_linked_ancestors_are_not_resolved_into_accepted_references(self):
        link = self.project / "private alias"
        try:
            link.symlink_to(self.secrets, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Directory symlinks are unavailable")
        for kwargs in ({"private_input_files": [link / self.private.name]},
                       {"asset_key_files": [link / self.key.name]}):
            with self.subTest(kind=next(iter(kwargs))):
                with self.assertRaises(GuardError):
                    self.initialize(**kwargs)
                self.assertFalse(self.output.exists())

    def test_input_change_while_writing_configuration_removes_the_entire_new_bundle(self):
        import releaseguard.project as project
        for input_file in (self.key, self.private):
            with self.subTest(kind=input_file.suffix):
                self.key.write_bytes(self.key_bytes)
                self.private.write_bytes(self.private_bytes)
                original = project.write_new

                def change(path, content):
                    original(path, content)
                    if Path(path).name == "policy.json":
                        data = input_file.read_bytes()
                        input_file.write_bytes(bytes([data[0] ^ 1]) + data[1:])

                with patch("releaseguard.project.write_new", side_effect=change):
                    with self.assertRaisesRegex(GuardError, "changed during"):
                        self.initialize(asset_key_files=[self.key], private_input_files=[self.private])
                self.assertFalse(self.output.exists())

    def test_oversized_generated_configuration_is_rejected_before_writing(self):
        with patch("releaseguard.project._relative_or_absolute", return_value="x" * 32768):
            with self.assertRaisesRegex(GuardError, "64 KiB"):
                self.initialize(asset_key_files=[self.key], private_input_files=[self.private])
        self.assertFalse(self.output.exists())

    def test_omitted_inputs_preserve_empty_configuration_and_load_contract(self):
        self.initialize()
        project = load_project(self.output / "project.json")
        self.assertEqual(project["asset_key_files"], [])
        self.assertEqual(project["private_input_files"], [])
        self.assertTrue(check_project(self.output / "project.json")["ok"])


if __name__ == "__main__":
    unittest.main()
