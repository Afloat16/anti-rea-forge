"""A public release must bind successful main CI to the tested archive bytes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

_path = Path(__file__).resolve().parents[1] / "tools/publish_release.py"
_spec = importlib.util.spec_from_file_location("release_publisher", _path)
publisher = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(publisher)
_pack_spec = importlib.util.spec_from_file_location("release_packages", _path.with_name("check_release_artifacts.py"))
packages = importlib.util.module_from_spec(_pack_spec)
_pack_spec.loader.exec_module(packages)


class ReleaseReadinessTests(unittest.TestCase):
    sha = "a" * 40
    version = "1.0.0"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="release-readiness-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.jobs = [{"name": name, "status": "completed", "conclusion": "success"}
                     for name in ("compile", "install")]
        self.required = [job["name"] for job in self.jobs]
        self.run = {"head_sha": self.sha, "event": "push", "head_branch": "main",
                    "repository": {"full_name": publisher.REPOSITORY},
                    "head_repository": {"full_name": publisher.REPOSITORY},
                    "path": ".github/workflows/ci.yml", "status": "completed", "conclusion": "success"}
        names = ["open_release_guard-1.0.0-py3-none-any.whl", "open_release_guard-1.0.0.tar.gz",
                 "anti-rea-forge-releaseguard-1.0.0.tgz"]
        records = []
        for name in names:
            data = ("owned archive fixture " + name).encode()
            (self.root / name).write_bytes(data)
            records.append({"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        self.report = {"schema": "anti-rea-forge.installation.v1", "ok": True,
                       "source_dirty": False,
                       "source_commit": self.sha, "version": self.version, "platform": "Linux",
                       "python_installations": [{"artifact": name, "version": self.version,
                           "isolated_import": True, "clean_release_accepted": True,
                           "renamed_source_map_blocked": True, "leaked_key_blocked": True,
                           "structured_key_blocked": True, "wasm_split_verified": True,
                           "consumer_key_encodings_blocked": True, "incomplete_source_map_blocked": True,
                           "relocatable_wasm_blocked": True,
                           "private_input_clean_accepted": True, "private_input_copy_blocked": True,
                           "pyc_integer_key_blocked": True, "encoded_pem_blocked": True,
                           "standalone_llvm_unverifiable": True,
                           "private_input_containment_blocked": True, "stringified_key_blocked": True,
                           "initialized_references_verified": True, "text_report_verified": True,
                           "native_resources_present": 5, "asset_roundtrip_bytes": 4096}
                           for name in names[:2]],
                       "javascript_installation": {"installed_sdk": True,
                           "clean_release_accepted": True, "source_map_blocked": True,
                           "private_input_clean_accepted": True, "private_input_copy_blocked": True,
                           "private_input_containment_blocked": True, "initialized_references_verified": True},
                       "artifacts": records}

    def test_complete_main_run_and_exact_bytes_are_accepted(self):
        publisher.validate_ci(self.run, self.jobs, self.sha, self.required)
        self.assertEqual(len(publisher.validate_artifacts(self.root, self.report, self.version, self.sha)), 3)

    def test_other_event_branch_commit_or_repository_cannot_publish(self):
        for key, value in (("event", "pull_request"), ("head_branch", "feature"),
                           ("head_sha", "b" * 40), ("path", ".github/workflows/other.yml"),
                           ("repository", {"full_name": "other/repo"}),
                           ("head_repository", {"full_name": "fork/repo"})):
            changed = {**self.run, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                publisher.validate_ci(changed, self.jobs, self.sha, self.required)

    def test_successful_summary_does_not_hide_skipped_missing_or_duplicate_jobs(self):
        for jobs in (self.jobs[:-1], self.jobs + [self.jobs[0]], [self.jobs[0], self.jobs[0]],
                     [self.jobs[0], {**self.jobs[1], "conclusion": "skipped"}],
                     [self.jobs[0], {**self.jobs[1], "status": "in_progress"}]):
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                publisher.validate_ci(self.run, jobs, self.sha, self.required)

    def test_report_from_other_commit_version_or_platform_cannot_publish(self):
        for key, value in (("source_commit", "b" * 40), ("version", "0.10.0"),
                           ("platform", "Windows"), ("ok", False), ("source_dirty", True)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                publisher.validate_artifacts(self.root, {**self.report, key: value}, self.version, self.sha)

    def test_changed_archive_is_rejected_even_at_the_same_size(self):
        path = self.root / self.report["artifacts"][0]["name"]
        path.write_bytes(b"X" * path.stat().st_size)
        with self.assertRaisesRegex(ValueError, "digest"):
            publisher.validate_artifacts(self.root, self.report, self.version, self.sha)

    def test_archive_paths_and_duplicates_cannot_change_the_inventory(self):
        for name in ("../outside.whl", "unverified.whl", self.report["artifacts"][1]["name"]):
            changed = copy.deepcopy(self.report)
            changed["artifacts"][0]["name"] = name
            with self.subTest(name=name), self.assertRaises(ValueError):
                publisher.validate_artifacts(self.root, changed, self.version, self.sha)

    def test_installation_failures_cannot_be_hidden_by_report_ok(self):
        for section, index, field in (("python_installations", 0, "leaked_key_blocked"),
                                       ("python_installations", 1, "isolated_import"),
                                       ("python_installations", 0, "structured_key_blocked"),
                                       ("python_installations", 1, "wasm_split_verified"),
                                       ("python_installations", 0, "consumer_key_encodings_blocked"),
                                       ("python_installations", 1, "incomplete_source_map_blocked"),
                                       ("python_installations", 1, "relocatable_wasm_blocked"),
                                       ("python_installations", 0, "private_input_clean_accepted"),
                                       ("python_installations", 1, "private_input_copy_blocked"),
                                       ("python_installations", 0, "pyc_integer_key_blocked"),
                                       ("python_installations", 1, "encoded_pem_blocked"),
                                       ("python_installations", 0, "standalone_llvm_unverifiable"),
                                       ("javascript_installation", None, "source_map_blocked"),
                                       ("javascript_installation", None, "private_input_clean_accepted"),
                                       ("javascript_installation", None, "private_input_copy_blocked")):
            changed = copy.deepcopy(self.report)
            target = changed[section] if index is None else changed[section][index]
            target[field] = False
            with self.subTest(field=field), self.assertRaises(ValueError):
                publisher.validate_artifacts(self.root, changed, self.version, self.sha)

    def test_missing_or_nonboolean_new_controls_cannot_authorize_publication(self):
        for section, fields in (
            ("python_installations", ("private_input_clean_accepted", "private_input_copy_blocked",
                                      "pyc_integer_key_blocked", "encoded_pem_blocked", "standalone_llvm_unverifiable",
                                      "private_input_containment_blocked", "stringified_key_blocked",
                                      "initialized_references_verified", "text_report_verified")),
            ("javascript_installation", ("private_input_clean_accepted", "private_input_copy_blocked",
                                         "private_input_containment_blocked", "initialized_references_verified")),
        ):
            for field in fields:
                for value in (None, False, 1, "true"):
                    changed = copy.deepcopy(self.report)
                    target = changed[section][0] if section == "python_installations" else changed[section]
                    if value is None:
                        del target[field]
                    else:
                        target[field] = value
                    with self.subTest(section=section, field=field, value=value), self.assertRaises(ValueError):
                        publisher.validate_artifacts(self.root, changed, self.version, self.sha)

    def test_python_installation_records_must_cover_both_actual_archives(self):
        changed = copy.deepcopy(self.report)
        changed["python_installations"][1] = copy.deepcopy(changed["python_installations"][0])
        with self.assertRaisesRegex(ValueError, "different archives"):
            publisher.validate_artifacts(self.root, changed, self.version, self.sha)

    def test_version_sources_and_release_policy_are_aligned(self):
        root = _path.parents[1]
        from releaseguard import __version__
        package = json.loads((root / "packages/releaseguard/package.json").read_text())
        policy = json.loads((root / "release-policy.json").read_text())
        self.assertEqual(__version__, package["version"])
        self.assertEqual(__version__, policy["version"])
        self.assertIn(f'version = "{__version__}"', (root / "pyproject.toml").read_text())

    def test_wheel_metadata_supports_windows_line_endings_without_ambiguous_identity(self):
        text = "Metadata-Version: 2.4\nName: open-release-guard\nVersion: 1.0.0\n\nDescription\n"
        for newline in ("\n", "\r\n"):
            payload = text.replace("\n", newline).encode()
            packages.validate_wheel_metadata(payload, self.version)
        for payload in (text.replace("1.0.0", "0.10.0"),
                        text.replace("open-release-guard", "different-package"),
                        text.replace("Version: 1.0.0", "Version: 1.0.0\nVersion: 1.0.0")):
            with self.subTest(payload=payload), self.assertRaises(RuntimeError):
                packages.validate_wheel_metadata(payload.encode(), self.version)


if __name__ == "__main__":
    unittest.main()
