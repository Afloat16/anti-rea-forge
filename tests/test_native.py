"""Native build integration and release-gate behavior, without running images."""

from __future__ import annotations

import hashlib
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from releaseguard import __version__
from releaseguard import native
from releaseguard.core import GuardError
from tests.test_pe import make_debug_pe, make_pe
from tests.test_elf import make_elf


class NativeTests(unittest.TestCase):
    def test_elf_gate_requires_observable_clean_metadata(self) -> None:
        self.write_policy(formats=["elf"])
        self.binary.write_bytes(make_elf())
        self.assertTrue(self.gate()["ok"])
        self.binary.write_bytes(make_elf(no_sections=True))
        self.assert_failed_gate()
        self.binary.write_bytes(make_elf(entries=[(".debug_info", 1)]))
        self.assert_failed_gate()
        self.binary.write_bytes(make_elf(entries=[(".internal_symbols", 2)]))
        self.assert_failed_gate()

    def test_high_entropy_flag_requires_64_bit_aslr_evidence(self) -> None:
        self.write_policy(required_pe_flags=["high_entropy_va"])
        for image in (
            make_pe(flags=0x20),
            make_pe(plus=True, flags=0x20),
            make_pe(plus=True, flags=0x60),
        ):
            with self.subTest(image=image[:4]):
                self.binary.write_bytes(image)
                self.assert_failed_gate()
        self.binary.write_bytes(make_pe(plus=True, flags=0x60, directories={5: (0x1000, 12)}))
        self.assertTrue(self.gate()["ok"])

    def test_cfg_flag_requires_dynamic_base_dependency(self) -> None:
        self.write_policy(required_pe_flags=["guard_cf"])
        self.binary.write_bytes(make_pe(plus=True, flags=0x4000, directories={10: (0x1040, 64)}))
        self.assert_failed_gate()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        # Match _root's canonical directory spelling before using paths in
        # scan counters and replacement hooks (e.g. Windows RUNNER~1 aliases).
        self.base = Path(self.temporary.name).resolve()
        self.binary = self.base / "app.exe"
        self.binary.write_bytes(make_pe())
        self.policy_path = self.base / "policy.json"
        self.write_policy()

    def write_policy(self, **overrides) -> dict:
        policy = {"version": 1, **overrides}
        self.policy_path.write_text(json.dumps(policy), encoding="utf-8")
        return policy

    def gate(self, *, root=None) -> dict:
        report = native.gate(self.binary, self.policy_path, root=root)
        self.assertIs(type(report), dict)
        self.assertIs(type(report.get("ok")), bool)
        self.assertIs(type(report.get("artifact")), dict)
        self.assertIs(type(report.get("checks")), dict)
        self.assertIs(type(report.get("findings")), list)
        for finding in report["findings"]:
            self.assertIs(type(finding), dict)
            self.assertIs(type(finding.get("code")), str)
            self.assertTrue(finding["code"])
        return report

    def assert_failed_gate(self, *, root=None) -> dict:
        report = self.gate(root=root)
        self.assertFalse(report["ok"], report)
        self.assertTrue(report["findings"], report)
        return report

    def metadata(self, output: Path) -> dict:
        return json.loads((output / "releaseguard-native.json").read_text("utf-8"))

    def assert_assets(self, output: Path) -> dict:
        metadata = self.metadata(output)
        self.assertEqual(metadata["format"], "open-release-guard-native/v1")
        self.assertEqual(metadata["version"], __version__)
        self.assertRegex(metadata["seed"], r"\A[0-9a-f]{16}\Z")
        expected = {
            "releaseguard_build.hpp", "cmake/ReleaseGuard.cmake",
            "include/releaseguard/literal.hpp",
            "include/releaseguard/secure_buffer.hpp",
        }
        self.assertEqual(set(metadata["assets"]), expected)
        for relative, digest in metadata["assets"].items():
            self.assertRegex(digest, r"\A[0-9a-f]{64}\Z")
            self.assertEqual(hashlib.sha256((output / relative).read_bytes()).hexdigest(), digest)
        return metadata

    def test_native_init_generates_complete_assets_and_metadata(self) -> None:
        output = self.base / "generated"
        result = native.init_native(output)
        self.assertIs(type(result), dict)
        self.assert_assets(output)

    def test_native_init_reuses_seed_and_leaves_existing_assets_unchanged(self) -> None:
        output = self.base / "generated"
        native.init_native(output)
        before = {path.relative_to(output).as_posix(): path.read_bytes()
                  for path in output.rglob("*") if path.is_file()}
        seed = self.metadata(output)["seed"]
        native.init_native(str(output))
        self.assertEqual(self.metadata(output)["seed"], seed)
        after = {path.relative_to(output).as_posix(): path.read_bytes()
                 for path in output.rglob("*") if path.is_file()}
        self.assertEqual(after, before)

    def test_native_init_explicit_seed_is_reproducible(self) -> None:
        seed = "0123456789abcdef"
        first, second = self.base / "first", self.base / "second"
        native.init_native(first, seed=seed)
        native.init_native(second, seed=seed)
        self.assertEqual(self.assert_assets(first)["seed"], seed)
        self.assertEqual(self.assert_assets(second)["seed"], seed)
        for relative in self.metadata(first)["assets"]:
            self.assertEqual((first / relative).read_bytes(), (second / relative).read_bytes())
        native.init_native(first, seed=seed)

    def test_native_init_rejects_different_seed_without_overwriting(self) -> None:
        output = self.base / "generated"
        native.init_native(output, seed="0123456789abcdef")
        before = (output / "releaseguard_build.hpp").read_bytes()
        with self.assertRaises(GuardError):
            native.init_native(output, seed="fedcba9876543210")
        self.assertEqual((output / "releaseguard_build.hpp").read_bytes(), before)
        self.assertEqual(self.metadata(output)["seed"], "0123456789abcdef")

    def test_native_init_rejects_changed_asset_without_overwriting(self) -> None:
        output = self.base / "generated"
        native.init_native(output)
        asset = output / "include" / "releaseguard" / "literal.hpp"
        original = asset.read_bytes()
        modified = original + b"\n// local changes must be preserved\n"
        asset.write_bytes(modified)
        with self.assertRaises(GuardError):
            native.init_native(output)
        self.assertEqual(asset.read_bytes(), modified)

    def test_native_init_rejects_unknown_nonempty_output_without_overwriting(self) -> None:
        output = self.base / "existing"
        output.mkdir()
        existing = output / "important.txt"
        existing.write_bytes(b"keep this user file")
        with self.assertRaises(GuardError):
            native.init_native(output)
        self.assertEqual(existing.read_bytes(), b"keep this user file")
        self.assertEqual(list(output.iterdir()), [existing])

    def test_native_init_accepts_an_existing_empty_directory(self) -> None:
        output = self.base / "empty"
        output.mkdir()
        native.init_native(output)
        self.assert_assets(output)

    def test_native_init_rejects_invalid_seed(self) -> None:
        for index, seed in enumerate(["", "abc", "g" * 16, "0" * 17, 1, True]):
            with self.subTest(seed=seed), self.assertRaises(GuardError):
                native.init_native(self.base / f"invalid_{index}", seed=seed)

    def test_native_init_normalizes_uppercase_seed(self) -> None:
        output = self.base / "uppercase-seed"
        native.init_native(output, seed="ABCDEF0123456789")
        self.assertEqual(self.assert_assets(output)["seed"], "abcdef0123456789")

    def test_load_policy_applies_documented_defaults(self) -> None:
        policy = native.load_policy(str(self.policy_path))
        self.assertEqual(policy["version"], 1)
        self.assertEqual(policy["formats"], ["pe"])
        self.assertEqual(policy["forbid_literals"], [])
        self.assertEqual(policy["forbid_extensions"], [".pdb", ".ilk", ".map"])
        self.assertIs(policy["require_native"], True)
        self.assertIs(policy["require_no_debug_metadata"], True)
        self.assertIs(policy["require_no_symbol_table"], True)
        self.assertEqual(policy["required_pe_flags"], [])
        self.assertEqual(policy["max_binary_bytes"], 512 * 1024 * 1024)
        self.assertEqual(policy["forbid_path_components"], [])
        self.assertEqual(policy["forbid_file_sha256"], [])
        self.assertIs(policy["scan_release_literals"], False)
        self.assertEqual(policy["max_release_scan_bytes"], 64 * 1024 * 1024)
        self.assertIsNone(policy["allowed_release_files"])

    def test_load_policy_accepts_explicit_values(self) -> None:
        expected = self.write_policy(
            formats=["pe", "elf"], forbid_literals=["forbidden"],
            forbid_extensions=[".pdb"], require_native=False,
            require_no_debug_metadata=False, require_no_symbol_table=False,
            required_pe_flags=["dynamic_base", "nx_compat", "guard_cf", "high_entropy_va"],
            max_binary_bytes=4 * 1024 * 1024 * 1024,
            forbid_path_components=["src", ".git", "Backups"],
            forbid_file_sha256=["0" * 64], scan_release_literals=True,
            max_release_scan_bytes=512 * 1024 * 1024,
            allowed_release_files=["app.exe", "data/catalog.bin"],
        )
        self.assertEqual(native.load_policy(self.policy_path), expected)

    def test_load_policy_rejects_unknown_fields_and_duplicate_json_keys(self) -> None:
        for raw in [
            '{"version":1,"allow_everything":true}',
            '{"version":1,"version":1}',
            '{"version":1,"require_native":true,"require_native":false}',
        ]:
            self.policy_path.write_text(raw, encoding="utf-8")
            with self.subTest(raw=raw), self.assertRaises((GuardError, ValueError)):
                native.load_policy(self.policy_path)

    def test_load_policy_requires_exact_integer_version(self) -> None:
        for raw in ['{}', '{"version":true}', '{"version":1.0}',
                    '{"version":"1"}', '{"version":2}']:
            self.policy_path.write_text(raw, encoding="utf-8")
            with self.subTest(raw=raw), self.assertRaises((GuardError, ValueError)):
                native.load_policy(self.policy_path)

    def test_load_policy_rejects_wrong_field_types(self) -> None:
        cases = [
            {"formats": "pe"}, {"formats": ["macho"]}, {"formats": [True]},
            {"forbid_literals": "password"}, {"forbid_literals": [123]},
            {"forbid_extensions": ".pdb"}, {"forbid_extensions": [True]},
            {"required_pe_flags": "guard_cf"}, {"required_pe_flags": ["unknown"]},
            {"require_native": 1}, {"require_no_debug_metadata": "true"},
            {"require_no_symbol_table": None}, {"max_binary_bytes": True},
            {"max_binary_bytes": "512"}, {"max_binary_bytes": 0},
            {"max_binary_bytes": 4 * 1024 * 1024 * 1024 + 1},
            {"forbid_path_components": "src"}, {"forbid_path_components": [True]},
            {"forbid_file_sha256": "0" * 64}, {"forbid_file_sha256": [True]},
            {"scan_release_literals": 1}, {"scan_release_literals": "true"},
            {"max_release_scan_bytes": True}, {"max_release_scan_bytes": "64"},
            {"max_release_scan_bytes": 0}, {"max_release_scan_bytes": 512 * 1024 * 1024 + 1},
            {"allowed_release_files": None}, {"allowed_release_files": "app.exe"},
            {"allowed_release_files": [True]},
        ]
        for changes in cases:
            self.write_policy(**changes)
            with self.subTest(changes=changes), self.assertRaises((GuardError, ValueError)):
                native.load_policy(self.policy_path)

    def test_load_policy_enforces_literal_count_and_length(self) -> None:
        for literals in [[""], ["x" * 1025], [f"rule_{i}" for i in range(65)]]:
            self.write_policy(forbid_literals=literals)
            with self.subTest(length=len(literals)), self.assertRaises((GuardError, ValueError)):
                native.load_policy(self.policy_path)
        self.write_policy(forbid_literals=["x" * 1024] + [f"rule_{i}" for i in range(63)])
        self.assertEqual(len(native.load_policy(self.policy_path)["forbid_literals"]), 64)

    def test_path_component_rules_reject_paths_globs_aliases_and_casefold_duplicates(self) -> None:
        for components in [
            [""], ["."], [".."], ["src/main.cpp"], ["src\\main.cpp"],
            ["*.cpp"], ["src?"], ["[Ss]rc"], ["{src,source}"],
            ["src "], ["src."], ["src\x00"], ["src", "SRC"],
            ["x" * 256], [f"dir{i}" for i in range(65)],
        ]:
            self.write_policy(forbid_path_components=components)
            with self.subTest(components=components), self.assertRaises(GuardError):
                native.load_policy(self.policy_path)

    def test_digest_rules_require_bounded_unique_canonical_sha256(self) -> None:
        for digests in [["0" * 63], ["A" * 64], ["z" * 64], ["0" * 64 + "\n"],
                        ["0" * 64] * 2, [f"{i:064x}" for i in range(65)]]:
            self.write_policy(forbid_file_sha256=digests)
            with self.subTest(digests=digests), self.assertRaises(GuardError):
                native.load_policy(self.policy_path)

    def test_allowlist_requires_bounded_nonempty_safe_exact_paths(self) -> None:
        for paths in [[], ["app.exe", "APP.EXE"], ["../app.exe"], ["/app.exe"],
                      ["data\\app.exe"], ["data/../app.exe"], ["data/*.bin"],
                      [f"file{i}.bin" for i in range(20_001)]]:
            self.write_policy(allowed_release_files=paths)
            with self.subTest(count=len(paths), paths=paths[:2]), self.assertRaises(GuardError):
                native.load_policy(self.policy_path)

    def test_each_explicit_release_policy_field_requires_root_even_if_inactive(self) -> None:
        for changes in [
            {"forbid_path_components": []}, {"forbid_path_components": ["src"]},
            {"forbid_file_sha256": []}, {"forbid_file_sha256": ["0" * 64]},
            {"scan_release_literals": False}, {"scan_release_literals": True},
            {"max_release_scan_bytes": 64 * 1024 * 1024},
            {"allowed_release_files": ["app.exe"]},
        ]:
            self.write_policy(**changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(GuardError, "require --root"):
                self.gate()

    def make_release(self) -> Path:
        release = self.base / "release"
        release.mkdir()
        self.binary.rename(release / self.binary.name)
        self.binary = release / self.binary.name
        return release

    def test_forbidden_components_cover_source_git_backups_and_empty_directories(self) -> None:
        release = self.make_release()
        self.write_policy(forbid_path_components=["src", ".git", "backups"])
        (release / "sRc").mkdir()
        (release / "sRc" / "main.cpp").write_bytes(b"source")
        (release / "nested" / ".GIT").mkdir(parents=True)
        (release / "nested" / ".GIT" / "config").write_bytes(b"metadata")
        (release / "Backups").mkdir()
        (release / "src-old").mkdir()
        report = self.assert_failed_gate(root=release)
        matches = [finding for finding in report["findings"]
                   if finding["code"] == "forbidden_path_component"]
        self.assertEqual({finding["path"] for finding in matches},
                         {"sRc", "nested/.GIT", "Backups"})
        self.assertEqual(len(matches), 3)
        self.assertEqual(report["checks"]["release_scan_bytes"], 0)

    def test_forbidden_components_match_file_names_and_unicode_casefold(self) -> None:
        release = self.make_release()
        (release / "Straße").write_bytes(b"not executable")
        self.write_policy(forbid_path_components=["STRASSE"])
        report = self.assert_failed_gate(root=release)
        self.assertIn({"code": "forbidden_path_component", "rule_index": 0, "path": "Straße"},
                      report["findings"])

    def test_release_digest_rules_find_renamed_old_binary_without_read_bytes(self) -> None:
        release = self.make_release()
        old_bytes = b"old source-owned binary fixture"
        nested = release / "assets"
        nested.mkdir()
        old = nested / "renamed-resource.dat"
        old.write_bytes(old_bytes)
        self.write_policy(forbid_file_sha256=["0" * 64, hashlib.sha256(old_bytes).hexdigest()])
        with patch.object(Path, "read_bytes", side_effect=AssertionError("Unbounded reading forbidden")):
            report = self.assert_failed_gate(root=release)
        self.assertIn({"code": "forbidden_file_digest", "rule_index": 1,
                       "path": "assets/renamed-resource.dat"}, report["findings"])
        self.assertEqual(report["checks"]["release_scan_bytes"], self.binary.stat().st_size + len(old_bytes))
        self.assertFalse(report["checks"]["release_literals_scanned"])

    def test_release_digest_rules_include_main_artifact(self) -> None:
        release = self.make_release()
        self.write_policy(forbid_file_sha256=[hashlib.sha256(self.binary.read_bytes()).hexdigest()])
        report = self.assert_failed_gate(root=release)
        self.assertIn({"code": "forbidden_file_digest", "rule_index": 0, "path": "app.exe"},
                      report["findings"])

    def test_release_literal_scan_covers_non_artifact_files_in_all_five_encodings(self) -> None:
        release = self.make_release()
        literal = "ReleaseResource_保护"
        self.write_policy(forbid_literals=[literal], scan_release_literals=True)
        resource = release / "asset.dat"
        for encoding in native._ENCODINGS:
            resource.write_bytes(b"\xa5" * 7 + literal.encode(encoding))
            with self.subTest(encoding=encoding):
                report = self.assert_failed_gate(root=release)
                self.assertIn({"code": "forbidden_literal", "rule_index": 0,
                               "encoding": encoding, "offset": 7, "path": "asset.dat"},
                              report["findings"])
                self.assertNotIn(literal, json.dumps(report, ensure_ascii=False))

    def test_release_literal_scan_reports_main_artifact_path_without_duplicate(self) -> None:
        release = self.make_release()
        literal = "main-only-secret"
        offset = self.binary.stat().st_size
        with self.binary.open("ab") as handle:
            handle.write(literal.encode())
        self.write_policy(forbid_literals=[literal], scan_release_literals=True)
        report = self.assert_failed_gate(root=release)
        matches = [finding for finding in report["findings"] if finding["code"] == "forbidden_literal"]
        self.assertEqual(matches, [{"code": "forbidden_literal", "rule_index": 0,
                                    "encoding": "utf-8", "offset": offset, "path": "app.exe"}])

    def test_release_literal_scan_detects_multiple_chunk_spans(self) -> None:
        release = self.make_release()
        literal = "CrossChunk_保护_string"
        self.write_policy(forbid_literals=[literal], scan_release_literals=True)
        resource = release / "resource.bin"
        for encoding in native._ENCODINGS:
            resource.write_bytes(b"\xa5" * 29 + literal.encode(encoding) + b"\xa5")
            with self.subTest(encoding=encoding), patch.object(native, "_CHUNK_BYTES", 32):
                report = self.assert_failed_gate(root=release)
                self.assertTrue(any(finding.get("path") == "resource.bin" and
                                    finding.get("encoding") == encoding and
                                    finding.get("offset") == 29 for finding in report["findings"]))

    def test_release_payload_budget_is_cumulative_including_main_and_exact_limit_passes(self) -> None:
        release = self.make_release()
        (release / "one.bin").write_bytes(b"a" * 47)
        (release / "two.bin").write_bytes(b"b" * 53)
        total = self.binary.stat().st_size + 100
        for options in [{"scan_release_literals": True}, {"forbid_file_sha256": ["0" * 64]}]:
            self.write_policy(**options, max_release_scan_bytes=total)
            with self.subTest(options=options):
                report = self.gate(root=release)
                self.assertTrue(report["ok"], report)
                self.assertEqual(report["checks"]["release_scan_bytes"], total)
                self.assertTrue(report["checks"]["release_payload_scan_completed"])
                self.write_policy(**options, max_release_scan_bytes=total - 1)
                with self.assertRaisesRegex(GuardError, "max_release_scan_bytes"):
                    self.gate(root=release)

    def test_release_budget_rejects_main_before_payload_read_and_charges_each_file_once(self) -> None:
        release = self.make_release()
        self.write_policy(scan_release_literals=True,
                          max_release_scan_bytes=self.binary.stat().st_size - 1)
        with patch.object(native, "_scan", side_effect=AssertionError("Over-budget payload must not be read")), \
                self.assertRaisesRegex(GuardError, "max_release_scan_bytes"):
            self.gate(root=release)
        resource = release / "resource.bin"
        resource.write_bytes(b"data")
        self.write_policy(scan_release_literals=True,
                          max_release_scan_bytes=self.binary.stat().st_size + resource.stat().st_size)
        with patch.object(native, "_scan", wraps=native._scan) as scanned:
            report = self.gate(root=release)
        self.assertTrue(report["ok"], report)
        scanned_paths = [Path(call.args[0]) for call in scanned.call_args_list]
        self.assertEqual(scanned_paths.count(self.binary), 1)
        self.assertEqual(scanned_paths.count(resource), 1)

    def test_release_empty_files_do_not_consume_budget_or_get_silently_skipped(self) -> None:
        release = self.make_release()
        (release / "zero.bin").write_bytes(b"")
        self.write_policy(forbid_file_sha256=[hashlib.sha256(b"").hexdigest()],
                          max_release_scan_bytes=self.binary.stat().st_size)
        report = self.assert_failed_gate(root=release)
        self.assertIn({"code": "forbidden_file_digest", "rule_index": 0, "path": "zero.bin"},
                      report["findings"])

    def test_allowlist_reports_extra_and_missing_files_with_exact_names(self) -> None:
        release = self.make_release()
        (release / "renamed-source.dat").write_bytes(b"source without a revealing extension")
        self.write_policy(allowed_release_files=["app.exe", "required.bin"])
        report = self.assert_failed_gate(root=release)
        self.assertIn({"code": "unexpected_release_file", "path": "renamed-source.dat"}, report["findings"])
        self.assertIn({"code": "missing_release_file", "path": "required.bin"}, report["findings"])
        self.write_policy(allowed_release_files=["app.exe", "renamed-source.dat"])
        self.assertTrue(self.gate(root=release)["ok"])
        self.write_policy(allowed_release_files=["APP.EXE", "renamed-source.dat"])
        report = self.assert_failed_gate(root=release)
        self.assertIn({"code": "unexpected_release_file", "path": "app.exe"}, report["findings"])
        self.assertIn({"code": "missing_release_file", "path": "APP.EXE"}, report["findings"])

    def test_release_payload_changed_after_scan_is_rejected_even_with_preserved_mtime(self) -> None:
        release = self.make_release()
        resource = release / "resource.bin"
        resource.write_bytes(b"original")
        self.write_policy(scan_release_literals=True)
        real_inventory = native._inventory
        inventory_calls = 0

        def changed_inventory(root):
            nonlocal inventory_calls
            inventory_calls += 1
            observed = real_inventory(root)
            if inventory_calls == 2:
                before = resource.stat()
                replacement = self.base / "replacement.bin"
                replacement.write_bytes(b"modified")
                os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
                os.replace(replacement, resource)
            return observed

        with patch.object(native, "_inventory", changed_inventory), \
                self.assertRaisesRegex(GuardError, "Release file changed after scanning"):
            self.gate(root=release)

    def test_new_release_file_during_scan_cannot_be_silently_skipped(self) -> None:
        release = self.make_release()
        self.write_policy(scan_release_literals=True)
        real_inventory = native._inventory
        calls = 0

        def growing_inventory(root):
            nonlocal calls
            calls += 1
            if calls == 2:
                (release / "late-source.cpp").write_bytes(b"source")
            return real_inventory(root)

        with patch.object(native, "_inventory", growing_inventory), \
                self.assertRaisesRegex(GuardError, "inventory changed"):
            self.gate(root=release)

    def test_release_file_replacement_between_lstat_and_open_is_rejected(self) -> None:
        release = self.make_release()
        resource = release / "resource.bin"
        resource.write_bytes(b"original")
        self.write_policy(forbid_file_sha256=["0" * 64])
        real_open = native.os.open
        changed = False

        def replacing_open(path, flags, *args, **kwargs):
            nonlocal changed
            if Path(path) == resource and not changed:
                changed = True
                replacement = self.base / "replacement.bin"
                replacement.write_bytes(b"modified")
                os.replace(replacement, resource)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(native.os, "open", replacing_open), \
                self.assertRaisesRegex(GuardError, "changed before scanning"):
            self.gate(root=release)
        self.assertTrue(changed, "The replacement hook must exercise the identity check")

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "POSIX FIFO test")
    def test_release_file_replaced_by_fifo_is_rejected_without_blocking(self) -> None:
        release = self.make_release()
        resource = release / "resource.bin"
        resource.write_bytes(b"original")
        self.write_policy(scan_release_literals=True)
        real_open = native.os.open
        changed = False

        def fifo_open(path, flags, *args, **kwargs):
            nonlocal changed
            if Path(path) == resource and not changed:
                self.assertTrue(flags & os.O_NONBLOCK, "Opening replacement FIFO must not block")
                changed = True
                resource.unlink()
                os.mkfifo(resource)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(native.os, "open", fifo_open), \
                self.assertRaisesRegex(GuardError, "changed before scanning"):
            self.gate(root=release)

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "POSIX FIFO test")
    def test_identity_recheck_rejects_fifo_replacement_without_blocking(self) -> None:
        before = self.binary.stat()
        identity = (before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns)
        real_open = native.os.open

        def fifo_open(path, flags, *args, **kwargs):
            self.assertTrue(flags & os.O_NONBLOCK, "Identity recheck must not block on FIFO")
            self.binary.unlink()
            os.mkfifo(self.binary)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(native.os, "open", fifo_open), \
                self.assertRaisesRegex(GuardError, "changed after scanning"):
            native._assert_scanned_identity(self.binary, identity, "Artifact")

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "POSIX FIFO test")
    def test_metadata_prefix_rejects_fifo_replacement_without_blocking(self) -> None:
        real_open = native.os.open

        def fifo_open(path, flags, *args, **kwargs):
            self.assertTrue(flags & os.O_NONBLOCK, "Prefix inspection must not block on FIFO")
            self.binary.unlink()
            os.mkfifo(self.binary)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(native.os, "open", fifo_open), \
                self.assertRaisesRegex(GuardError, "changed before metadata inspection"):
            native.read_limited_prefix(self.binary, 4)

    def test_minimal_native_pe_passes_default_policy(self) -> None:
        report = self.gate()
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["findings"], [])

    def test_native_gate_accepts_string_paths_and_does_not_modify_binary(self) -> None:
        original = self.binary.read_bytes()
        report = native.gate(str(self.binary), str(self.policy_path))
        self.assertTrue(report["ok"], report)
        self.assertEqual(self.binary.read_bytes(), original)

    def test_gate_rejects_managed_pe_by_default(self) -> None:
        self.binary.write_bytes(make_pe(directories={14: (0x1080, 72)}))
        self.assert_failed_gate()
        self.write_policy(require_native=False)
        self.assertTrue(self.gate()["ok"])

    def test_gate_rejects_debug_directory_by_default(self) -> None:
        self.binary.write_bytes(make_pe(directories={6: (0x1020, 28)}))
        self.assert_failed_gate()
        self.write_policy(require_no_debug_metadata=False)
        self.assertTrue(self.gate()["ok"])

    def test_gate_rejects_coff_symbols_by_default(self) -> None:
        data = make_pe()
        struct.pack_into("<II", data, 0x8C, 0x440, 1)
        self.binary.write_bytes(data)
        self.assert_failed_gate()
        self.write_policy(require_no_symbol_table=False)
        self.assertTrue(self.gate()["ok"])

    def test_required_pe_flags_are_enforced(self) -> None:
        flags = ["dynamic_base", "nx_compat", "guard_cf", "high_entropy_va"]
        self.write_policy(required_pe_flags=flags)
        self.assert_failed_gate()
        self.binary.write_bytes(make_pe(
            plus=True, flags=0x4160,
            directories={5: (0x1000, 12), 10: (0x1040, 64)},
        ))
        self.assertTrue(self.gate()["ok"])

    def test_required_pe_flags_need_corresponding_static_evidence(self) -> None:
        for flag, bit in [("dynamic_base", 0x40), ("guard_cf", 0x4000)]:
            self.write_policy(required_pe_flags=[flag])
            self.binary.write_bytes(make_pe(flags=bit))
            with self.subTest(flag=flag):
                self.assert_failed_gate()

    def test_disallowed_binary_format_fails_policy(self) -> None:
        self.write_policy(formats=["elf"])
        self.assert_failed_gate()

    def test_forbidden_literals_in_all_required_encodings_are_detected(self) -> None:
        literal = "UltraSensitiveMarker_保护"
        self.write_policy(forbid_literals=["missing_first_rule", literal])
        for encoding in ["utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"]:
            encoded = literal.encode(encoding)
            offset = len(make_pe()) + 17
            self.binary.write_bytes(make_pe() + b"\xa5" * 17 + encoded + b"\xa5" * 8)
            report = self.assert_failed_gate()
            matches = [finding for finding in report["findings"]
                       if finding.get("rule_index") == 1]
            with self.subTest(encoding=encoding):
                self.assertTrue(matches, report)
                self.assertTrue(any(finding.get("encoding") == encoding and
                                    finding.get("offset") == offset for finding in matches), report)
                self.assertNotIn(literal, json.dumps(report, ensure_ascii=False))
                self.assertNotIn("missing_first_rule", json.dumps(report, ensure_ascii=False))

    def test_literal_scan_detects_matches_across_chunk_boundaries(self) -> None:
        literal = "BoundarySecret_保护"
        self.write_policy(forbid_literals=[literal])
        for boundary in [64 * 1024, 1024 * 1024]:
            for encoding in ["utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"]:
                encoded = literal.encode(encoding)
                offset = boundary - max(1, len(encoded) // 2)
                data = make_pe() + b"\xa5" * (offset - len(make_pe())) + encoded
                self.binary.write_bytes(data)
                report = self.assert_failed_gate()
                with self.subTest(boundary=boundary, encoding=encoding):
                    self.assertTrue(any(finding.get("rule_index") == 0 and
                                        finding.get("encoding") == encoding and
                                        finding.get("offset") == offset
                                        for finding in report["findings"]), report)

    def test_nonmatching_literal_passes_without_disclosing_rule(self) -> None:
        literal = "ThisMustRemainSecret_不会出现"
        self.write_policy(forbid_literals=[literal])
        report = self.gate()
        self.assertTrue(report["ok"], report)
        self.assertNotIn(literal, json.dumps(report, ensure_ascii=False))

    def test_default_forbidden_companion_extensions_are_detected(self) -> None:
        for extension in [".pdb", ".ilk", ".map"]:
            companion = self.binary.with_suffix(extension)
            companion.write_bytes(b"private build metadata")
            with self.subTest(extension=extension):
                self.assert_failed_gate()
            companion.unlink()
        self.assertTrue(self.gate()["ok"])

    def test_forbidden_companion_does_not_require_matching_case(self) -> None:
        (self.base / "APP.PDB").write_bytes(b"private symbols")
        self.assert_failed_gate()

    def test_explicit_root_scans_all_subdirectories_for_forbidden_files(self) -> None:
        release = self.base / "release"
        release.mkdir()
        self.binary = release / "app.exe"
        self.binary.write_bytes(make_pe())
        nested = release / "symbols"
        nested.mkdir()
        (nested / "unrelated.pdb").write_bytes(b"unrelated private symbols")
        self.assertTrue(self.gate()["ok"])
        self.assert_failed_gate(root=release)

    def test_explicit_root_must_contain_artifact(self) -> None:
        other = self.base / "other-root"
        other.mkdir()
        with self.assertRaises((GuardError, ValueError)):
            native.gate(self.binary, self.policy_path, root=other)

    def test_empty_forbidden_extension_policy_allows_companion(self) -> None:
        self.binary.with_suffix(".pdb").write_bytes(b"private symbols")
        self.write_policy(forbid_extensions=[])
        self.assertTrue(self.gate()["ok"])

    def test_oversized_binary_is_rejected_without_scanning_content(self) -> None:
        with self.binary.open("ab") as handle:
            handle.truncate(16 * 1024 * 1024)
        self.write_policy(max_binary_bytes=1024)
        original_open = Path.open

        def guarded_open(path, *args, **kwargs):
            if Path(path) == self.binary:
                raise AssertionError("Oversized binary content must not be scanned")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", guarded_open):
            self.assert_failed_gate()

    def test_malformed_or_nonbinary_artifacts_raise_validation_error(self) -> None:
        for data in [b"", b"MZ", b"#! /bin/sh\necho NEVER_EXECUTE\n", b"plain text"]:
            self.binary.write_bytes(data)
            with self.subTest(data=data), self.assertRaises((GuardError, ValueError)):
                native.gate(self.binary, self.policy_path)

    def test_gate_does_not_execute_samples(self) -> None:
        import subprocess

        with patch.object(subprocess, "Popen", side_effect=AssertionError("Execution forbidden")), \
                patch.object(os, "system", side_effect=AssertionError("Execution forbidden")):
            self.assertTrue(self.gate()["ok"])

    def test_same_size_change_between_scan_and_metadata_check_is_rejected(self) -> None:
        literal = "LEAK_MARKER_1234"
        self.write_policy(forbid_literals=[literal])
        self.binary.write_bytes(make_pe() + b"x" * len(literal))
        original_prefix = native.read_limited_prefix

        def modified_prefix(path, length):
            previous = path.stat()
            path.write_bytes(make_pe() + literal.encode("ascii"))
            # Force an observable timestamp change even on coarse filesystems.
            os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns + 2_000_000_000))
            return original_prefix(path, length)

        with patch.object(native, "read_limited_prefix", modified_prefix):
            with self.assertRaises((GuardError, ValueError)):
                native.gate(self.binary, self.policy_path)

    def test_gate_accepts_stable_handle_ctime_different_from_path_ctime(self) -> None:
        real_fstat = os.fstat

        def handle_timestamps(descriptor):
            info = real_fstat(descriptor)
            values = {name: getattr(info, name) for name in (
                "st_dev", "st_ino", "st_size", "st_mode", "st_mtime_ns", "st_ctime_ns",
            )}
            # Model Windows: path metadata reports birth time while the
            # handle reports a later metadata change time for the same file.
            values["st_ctime_ns"] += 123_456_789
            return SimpleNamespace(**values)

        with patch.object(native.os, "fstat", handle_timestamps):
            self.assertTrue(self.gate()["ok"])

    def test_gate_rejects_handle_change_time_after_scan_without_path_change(self) -> None:
        real_fstat = os.fstat
        real_prefix = native.read_limited_prefix
        changed = False

        def handle_timestamps(descriptor):
            info = real_fstat(descriptor)
            values = {name: getattr(info, name) for name in (
                "st_dev", "st_ino", "st_size", "st_mode", "st_mtime_ns", "st_ctime_ns",
            )}
            if changed:
                values["st_ctime_ns"] += 2_000_000_000
            return SimpleNamespace(**values)

        def metadata_phase(path, length):
            nonlocal changed
            changed = True
            return real_prefix(path, length)

        with patch.object(native.os, "fstat", handle_timestamps), \
                patch.object(native, "read_limited_prefix", metadata_phase):
            with self.assertRaisesRegex(GuardError, "changed after scanning"):
                self.gate()

    def test_gate_accepts_validated_security_debug_directory_entry(self) -> None:
        self.binary.write_bytes(make_debug_pe([(20, struct.pack("<I", 1))]))
        report = self.gate()
        self.assertTrue(report["ok"])
        self.assertFalse(report["checks"]["debug_metadata_present"])

    def test_gate_rejects_debug_data_alongside_security_directory_entry(self) -> None:
        self.binary.write_bytes(make_debug_pe([
            (20, struct.pack("<I", 1)), (2, b"RSDS synthetic CodeView data"),
        ]))
        report = self.assert_failed_gate()
        self.assertIn({"code": "debug_metadata_present"}, report["findings"])

    def test_gate_rejects_same_size_replacement_with_preserved_mtime(self) -> None:
        original_prefix = native.read_limited_prefix

        def replaced_prefix(path, length):
            before = path.stat()
            replacement = path.with_name("replacement.exe")
            replacement.write_bytes(path.read_bytes())
            os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
            os.replace(replacement, path)
            return original_prefix(path, length)

        with patch.object(native, "read_limited_prefix", replaced_prefix):
            with self.assertRaisesRegex(GuardError, "changed after scanning"):
                self.gate()


if __name__ == "__main__":
    unittest.main()
