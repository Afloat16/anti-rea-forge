"""Native build integration and release-gate behavior, without running images."""

from __future__ import annotations

import hashlib
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from releaseguard import native
from releaseguard.core import GuardError
from tests.test_pe import make_pe
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
        self.base = Path(self.temporary.name)
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
        self.assertEqual(metadata["version"], "0.2.0")
        self.assertRegex(metadata["seed"], r"\A[0-9a-f]{16}\Z")
        expected = {
            "releaseguard_build.hpp", "cmake/ReleaseGuard.cmake",
            "include/releaseguard/literal.hpp",
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

    def test_load_policy_accepts_explicit_values(self) -> None:
        expected = self.write_policy(
            formats=["pe", "elf"], forbid_literals=["forbidden"],
            forbid_extensions=[".pdb"], require_native=False,
            require_no_debug_metadata=False, require_no_symbol_table=False,
            required_pe_flags=["dynamic_base", "nx_compat", "guard_cf", "high_entropy_va"],
            max_binary_bytes=4 * 1024 * 1024 * 1024,
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


if __name__ == "__main__":
    unittest.main()
