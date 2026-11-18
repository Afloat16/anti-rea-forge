"""Private references survive configuration, CLI and signed-publication boundaries."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard.core import GuardError, generate_keys
from releaseguard.project import check_project, init_project, load_project, prepare_release


class ProjectPrivateInputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="project private inputs ")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "public"
        self.root.mkdir()
        self.app = self.root / "client.js"
        self.app.write_bytes(b"export const operation = 'quote';\n")
        self.private_file = self.base / "server implementation.py"
        self.data = b"def quote(x):\n    return x * 37 + 19\n"
        self.private_file.write_bytes(self.data)
        self.config_dir = self.base / "configuration"
        init_project(self.root, "owned-service", self.config_dir)
        self.config = self.config_dir / "project.json"
        self.output = self.base / "publication"
        self.issuer = Ed25519PrivateKey.generate()
        self.configure(["../server implementation.py"])

    def configure(self, paths):
        document = json.loads(self.config.read_bytes())
        document["private_input_files"] = paths
        self.config.write_text(json.dumps(document), encoding="utf-8")

    def prepare(self, **kwargs):
        return prepare_release(self.config, self.issuer, "1", self.output, **kwargs)

    def cli(self, *args, expected=0):
        env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
               "RELEASEGUARD_PASSPHRASE": "owned-test-private-input-passphrase"}
        result = subprocess.run([sys.executable, "-m", "releaseguard", *map(str, args)],
                                cwd=self.base, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn(str(self.private_file), result.stdout + result.stderr)
        return json.loads(result.stdout if expected in (0, 3) else result.stderr)

    def test_paths_resolve_from_config_and_clean_publication_contains_only_counts(self):
        project = load_project(self.config)
        self.assertEqual(project["private_input_files"], [self.config_dir / "../server implementation.py"])
        self.assertEqual(check_project(self.config)["checks"]["private_inputs_checked"], 1)
        prepared = self.prepare()
        self.assertTrue(prepared["prepared"])
        saved = json.loads((self.output / "release-report.json").read_bytes())
        self.assertEqual(saved["checks"]["private_inputs_checked"], 1)
        for report in (prepared, saved):
            rendered = json.dumps(report)
            for private in (str(self.private_file), self.private_file.name,
                            hashlib.sha256(self.data).hexdigest(), self.data.decode()):
                self.assertNotIn(private, rendered)

    def test_omitted_and_empty_extra_lists_cannot_clear_configured_private_files(self):
        self.app.write_bytes(self.data)
        for kwargs in ({}, {"private_input_files": []}):
            with self.subTest(kwargs=kwargs):
                self.assertFalse(check_project(self.config, **kwargs)["ok"])
                with patch("releaseguard.project.create_manifest") as signing:
                    prepared = self.prepare(**kwargs)
                signing.assert_not_called()
                self.assertFalse(prepared["prepared"])
                self.assertFalse(self.output.exists())

    def test_extra_inputs_are_additive_with_a_combined_count_limit(self):
        second = self.base / "private-model.dat"
        second.write_bytes(b"owned-private-model-content")
        self.app.write_bytes(second.read_bytes())
        report = check_project(self.config, private_input_files=[second])
        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"]["private_inputs_checked"], 2)
        self.assertTrue(any(f["code"] == "private_input_exposure" and f["rule_index"] == 1
                            for f in report["findings"]))
        for action in (check_project,):
            with self.assertRaisesRegex(GuardError, "combined"):
                action(self.config, private_input_files=[second] * 64)
        with self.assertRaisesRegex(GuardError, "combined"):
            self.prepare(private_input_files=[second] * 64)

    def test_invalid_config_and_release_local_reference_fail_before_signing(self):
        for value in (None, "server.py", [42], [""], ["bad\0path"], ["../server implementation.py"] * 65,
                      [str(self.app)]):
            with self.subTest(kind=type(value).__name__):
                self.configure(value)
                with self.assertRaises(GuardError):
                    load_project(self.config)
                self.assertFalse(self.output.exists())

    def test_missing_reference_never_becomes_a_partial_success(self):
        self.private_file.unlink()
        with self.assertRaises(GuardError):
            check_project(self.config)
        with self.assertRaises(GuardError):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_private_reference_link_loop_returns_a_fixed_cli_error(self):
        loop = self.base / "private-loop"
        try:
            loop.symlink_to(loop.name)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks are unavailable")
        self.configure(["../private-loop"])
        report = self.cli("check", "--config", self.config, expected=2)
        self.assertNotIn(str(loop), json.dumps(report))
        self.assertFalse(report["ok"])

    def test_reference_change_between_scan_sign_and_publication_removes_all_sidecars(self):
        import releaseguard.project as project
        for phase in ("scan_release", "create_manifest", "write_new", "verify_manifest"):
            with self.subTest(phase=phase):
                self.private_file.write_bytes(self.data)
                original = getattr(project, phase)
                changed = False

                def changing(*args, **kwargs):
                    nonlocal changed
                    result = original(*args, **kwargs)
                    if not changed and (phase != "write_new" or Path(args[0]).name == "release-report.json"):
                        changed = True
                        self.private_file.write_bytes(self.data.replace(b"37", b"38"))
                    return result

                with patch.object(project, phase, side_effect=changing):
                    with self.assertRaisesRegex(GuardError, "changed during"):
                        self.prepare()
                self.assertTrue(changed)
                self.assertFalse(self.output.exists())

    def test_cli_scan_check_prepare_preserve_failure_and_additive_rules(self):
        report = self.cli("scan-release", "--root", self.root, "--policy", self.config_dir / "policy.json",
                          "--private-input-file", self.private_file)
        self.assertEqual(report["checks"]["private_inputs_checked"], 1)
        self.app.write_bytes(self.data)
        self.cli("scan-release", "--root", self.root, "--policy", self.config_dir / "policy.json",
                 "--private-input-file", self.private_file, expected=3)
        report = self.cli("check", "--config", self.config, expected=3)
        self.assertEqual(report["checks"]["private_inputs_checked"], 1)
        issuer_dir = self.base / "issuer"
        issuer_dir.mkdir()
        generate_keys(issuer_dir / "private.pem", issuer_dir / "public.pem",
                      b"owned-test-private-input-passphrase")
        prepared = self.cli("prepare", "--config", self.config, "--private", issuer_dir / "private.pem",
                            "--release", "1", "--out", self.output, expected=3)
        self.assertFalse(prepared["prepared"])
        self.assertFalse(self.output.exists())
        self.private_file.unlink()
        self.cli("check", "--config", self.config, expected=2)

    def test_cli_extra_reference_cannot_override_saved_configuration(self):
        second = self.base / "different-private.dat"
        second.write_bytes(b"different private input")
        self.app.write_bytes(self.data)
        report = self.cli("check", "--config", self.config, "--private-input-file", second, expected=3)
        self.assertEqual(report["checks"]["private_inputs_checked"], 2)


if __name__ == "__main__":
    unittest.main()
