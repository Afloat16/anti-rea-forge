"""Behavioral regressions for portable distributions and bounded ZIP scanning."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import struct
import tempfile
import unittest
import zipfile
import zlib
import warnings
from pathlib import Path
from unittest.mock import patch

from releaseguard.core import GuardError
from releaseguard import distribution


def archive(entries, *, compression=zipfile.ZIP_DEFLATED):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=compression) as handle:
        for name, value in entries:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message="Duplicate name:", category=UserWarning)
                handle.writestr(name, value)
    return target.getvalue()


class PortableReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "dist"
        self.root.mkdir()
        self.policy = self.base / "policy.json"
        self.configure()

    def configure(self, **values):
        self.policy.write_text(json.dumps({"version": 1, **values}), encoding="utf-8")

    def put(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def scan(self):
        return distribution.scan_release(self.root, self.policy)

    def codes(self):
        return {item["code"] for item in self.scan()["findings"]}

    def test_portable_source_and_text_distributions_need_no_native_binary(self):
        self.put("my_package/__init__.py", b"def hello(): return 'world'\n")
        self.put("client/index.js", b"export const ready = true;\n")
        self.put("NOTICE", b"MIT")
        report = self.scan()
        self.assertTrue(report["ok"])
        self.assertTrue(report["checks"]["scan_completed"])
        self.assertEqual(report["checks"]["files_scanned"], 3)
        self.assertEqual(report["files"][0]["path"], "NOTICE")
        self.assertEqual(report["files"][0]["sha256"], hashlib.sha256(b"MIT").hexdigest())

    def test_external_asset_key_exposure_in_encodings_and_nested_zip(self):
        key = bytes(range(32))
        private = self.base / "asset.key"
        private.write_bytes(key)
        patterns = {"raw": key, "hex": key.hex().encode(), "uppercase": key.hex().upper().encode(),
                    "base64": base64.b64encode(key), "base64url": base64.urlsafe_b64encode(key).rstrip(b"="),
                    "wide": key.hex().encode("utf-32-be")}
        for name, data in patterns.items():
            self.put(name + ".bin", b"prefix" + data + b"suffix")
        self.put("nested.zip", archive([("data.zip", archive([("key.dat", key)]))]))
        with patch.object(distribution, "_CHUNK_BYTES", 17):
            report = distribution.scan_release(self.root, self.policy, asset_key_files=[private])
        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"]["asset_keys_checked"], 1)
        findings = [item for item in report["findings"] if item["code"] == "asset_key_exposure"]
        self.assertEqual({item["path"] for item in findings}, {name + ".bin" for name in patterns} | {"nested.zip"})
        self.assertTrue(any(item.get("archive_members") == ["data.zip", "key.dat"] for item in findings))
        self.assertNotIn(key.hex(), json.dumps(report))
        self.assertNotIn(base64.b64encode(key).decode(), json.dumps(report))

    def test_asset_key_inputs_fail_closed_and_clean_release_passes(self):
        self.put("app", b"ordinary release")
        key = self.base / "asset.key"
        for value in (b"", b"short", b"x" * 33):
            key.write_bytes(value)
            with self.assertRaises(GuardError):
                distribution.scan_release(self.root, self.policy, asset_key_files=[key])
        key.write_bytes(bytes(range(32)))
        self.assertTrue(distribution.scan_release(self.root, self.policy, asset_key_files=[key])["ok"])
        with self.assertRaises(GuardError):
            distribution.scan_release(self.root, self.policy, asset_key_files=str(key))

    def test_empty_release_is_not_accepted(self):
        with self.assertRaisesRegex(GuardError, "empty"):
            self.scan()

    def test_literals_match_all_encodings_without_echoing_secrets(self):
        secret = "secret-never-echo-\u6d4b\U0001f511"
        self.configure(forbid_literals=[secret])
        for index, encoding in enumerate(distribution._ENCODINGS):
            self.put(f"file-{index}", b"noise" + secret.encode(encoding))
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertEqual({finding["encoding"] for finding in report["findings"]}, set(distribution._ENCODINGS))
        self.assertNotIn(secret, json.dumps(report, ensure_ascii=False))
        self.assertEqual({finding["rule_index"] for finding in report["findings"]}, {0})

    def test_markers_and_literals_cross_stream_chunk_boundaries(self):
        self.configure(forbid_literals=["boundary-secret"])
        self.put("app.js", b"123456789" + b"boundary-secret" + b"sourceMappingURL=data:")
        with patch.object(distribution, "_CHUNK_BYTES", 11):
            self.assertEqual(self.codes(), {"forbidden_literal", "source_map_marker"})

    def test_default_key_and_sourcemap_checks_include_wide_encodings(self):
        for index, encoding in enumerate(distribution._ENCODINGS):
            self.put(f"item-{index}", ('-----BEGIN PRIVATE KEY-----\n"sourcesContent"').encode(encoding))
        report = self.scan()
        self.assertFalse(report["ok"])
        for code in ("private_key_marker", "source_map_marker"):
            self.assertEqual({f["encoding"] for f in report["findings"] if f["code"] == code}, set(distribution._ENCODINGS))

    def test_detection_can_be_explicitly_disabled_for_intentional_public_material(self):
        self.configure(check_private_keys=False, check_source_maps=False, forbid_extensions=[])
        self.put("public-example.map", b'-----BEGIN PRIVATE KEY-----\n{"sourcesContent":[]}')
        report = self.scan()
        self.assertTrue(report["ok"])
        self.assertFalse(report["checks"]["private_key_markers_checked"])
        self.assertFalse(report["checks"]["source_map_markers_checked"])

    def test_paths_extensions_and_digests_apply_to_every_disk_file(self):
        data = b"known-old-release"
        self.configure(forbid_file_sha256=[hashlib.sha256(data).hexdigest()])
        self.put("other/backup.PDB", data)
        self.put("config/.env", b"SECRET=value")
        self.assertEqual(self.codes(), {"forbidden_extension", "forbidden_file_digest", "forbidden_path_component"})

    def test_forbidden_empty_directory_is_detected(self):
        self.put("app.js", b"ok")
        (self.root / ".git").mkdir()
        self.assertIn("forbidden_path_component", self.codes())

    def test_exact_allowlist_reports_missing_and_added_files(self):
        self.configure(allowed_release_files=["app.js", "NOTICE"])
        self.put("app.js", b"ok")
        self.put("extra.txt", b"extra")
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertEqual({f["code"] for f in report["findings"]}, {"missing_release_file", "unexpected_release_file"})
        self.assertTrue(report["checks"]["release_allowlist_applied"])

    def test_disk_file_and_total_byte_budgets_are_fail_closed(self):
        self.put("one", b"12345")
        self.put("two", b"12345")
        for policy in ({"max_file_bytes": 4}, {"max_total_bytes": 9}, {"max_files": 1}):
            with self.subTest(policy=policy):
                self.configure(**policy)
                with self.assertRaises(GuardError):
                    self.scan()

    def test_policy_rejects_unknown_ambiguous_or_unbounded_fields(self):
        self.put("file", b"ok")
        invalid = [
            {"version": True}, {"version": 2}, {"formats": ["elf"]},
            {"max_file_bytes": True}, {"max_file_bytes": 0},
            {"max_total_bytes": 513 * 1024 * 1024}, {"max_archive_depth": 0},
            {"max_archive_entries": -1}, {"max_files": 20001},
            {"check_private_keys": 1}, {"check_source_maps": "true"},
            {"scan_zip_archives": None}, {"forbid_literals": ["a", "a"]},
            {"forbid_literals": ["\ud800"]}, {"forbid_literals": [""]},
            {"forbid_extensions": [".MAP"]}, {"forbid_path_components": ["a/b"]},
            {"forbid_path_components": [".git", ".GIT"]},
            {"forbid_file_sha256": ["A" * 64]}, {"allowed_release_files": []},
            {"allowed_release_files": ["../file"]}, {"allowed_release_files": ["a", "A"]},
        ]
        for values in invalid:
            with self.subTest(values=values):
                self.configure(**values)
                with self.assertRaises(GuardError):
                    self.scan()
        self.policy.write_text('{"version":1,"version":1}')
        with self.assertRaises(GuardError):
            self.scan()

    def test_file_links_and_linked_roots_are_rejected(self):
        target = self.base / "outside"
        target.write_bytes(b"secret")
        try:
            (self.root / "link").symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("File symlink creation is unavailable")
        with self.assertRaises(GuardError):
            self.scan()
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(GuardError):
            distribution.scan_release(alias, self.policy)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs require POSIX")
    def test_special_file_does_not_block_scanning(self):
        os.mkfifo(self.root / "pipe")
        with self.assertRaises(GuardError):
            self.scan()

    def test_changed_or_added_files_do_not_return_a_passing_report(self):
        target = self.put("app.js", b"original")
        original = distribution._Scanner.container
        def changed(scanner, *args, **kwargs):
            original(scanner, *args, **kwargs)
            target.write_bytes(b"modified")
        with patch.object(distribution._Scanner, "container", changed):
            with self.assertRaises(GuardError):
                self.scan()
        def added(scanner, *args, **kwargs):
            original(scanner, *args, **kwargs)
            self.put("additional", b"new")
        with patch.object(distribution._Scanner, "container", added):
            with self.assertRaises(GuardError):
                self.scan()

    def test_zip_jar_and_wheel_contents_are_scanned_without_extraction(self):
        for suffix in ("zip", "jar", "whl"):
            self.put(f"package.{suffix}", archive([
                ("code.js", b"//# sourceMappingURL=data:application/json;base64,abc"),
                ("keys/key.pem", b"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
            ]))
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"]["archives_scanned"], 3)
        self.assertEqual(report["checks"]["archive_entries"], 6)
        self.assertTrue(all("archive_members" in f for f in report["findings"]))
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["package.jar", "package.whl", "package.zip"])

    def test_zip_magic_and_end_record_defeat_extension_rename(self):
        data = archive([("config", b"private-test-secret")])
        self.configure(forbid_literals=["private-test-secret"])
        self.put("renamed.dat", data)
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"]["archives_scanned"], 1)
        self.assertEqual({f["path"] for f in report["findings"]}, {"renamed.dat"})

    def test_prefixed_and_concatenated_zip_cannot_hide_earlier_archive(self):
        hidden = archive([("private.pem", b"-----BEGIN PRIVATE KEY-----")])
        clean = archive([("NOTICE", b"public")])
        for data in (hidden + clean, b"MZ-executable-stub" + hidden):
            self.put("renamed.data", data)
            with self.assertRaises(GuardError):
                self.scan()

    def test_nested_zip_reports_unambiguous_chain_and_counts_all_expansion(self):
        inner = archive([("confidential", b"test-key")])
        outer = archive([("folder!/inner.zip", inner)])
        self.put("outer!.zip", outer)
        self.configure(forbid_literals=["test-key"], allowed_release_files=["outer!.zip"])
        report = self.scan()
        self.assertFalse(report["ok"])
        finding = next(f for f in report["findings"] if f.get("archive_members") == ["folder!/inner.zip", "confidential"])
        self.assertEqual(finding["path"], "outer!.zip")
        self.assertEqual(report["checks"]["bytes_scanned"], len(outer) + len(inner) + len(b"test-key"))
        self.assertEqual(report["checks"]["archives_scanned"], 2)
        self.assertNotIn("unexpected_release_file", {f["code"] for f in report["findings"]})

    def test_archive_name_and_hash_rules_apply_to_expanded_members(self):
        body = b"known-body"
        self.configure(forbid_file_sha256=[hashlib.sha256(body).hexdigest()])
        self.put("dist.zip", archive([(".git/config", body), ("src/index.map", b"{}")]))
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertTrue({"forbidden_path_component", "forbidden_extension", "forbidden_file_digest"}.issubset({f["code"] for f in report["findings"]}))

    def test_archive_expansion_and_nested_depth_limits_fail_before_success(self):
        self.put("large.zip", archive([("expanded", b"x" * 200000)]))
        for values in ({"max_file_bytes": 10000}, {"max_total_bytes": 10000}):
            self.configure(**values)
            with self.assertRaises(GuardError):
                self.scan()
        (self.root / "large.zip").unlink()
        self.put("nested.zip", archive([("inner.zip", archive([("file", b"x")]))]))
        self.configure(max_archive_depth=1)
        with self.assertRaisesRegex(GuardError, "nesting"):
            self.scan()

    def test_global_entry_budget_includes_nested_and_multiple_archives(self):
        self.put("one.zip", archive([("a", b"a"), ("b", b"b")]))
        self.put("two.zip", archive([("a", b"a"), ("b", b"b")]))
        self.configure(max_archive_entries=3)
        with self.assertRaisesRegex(GuardError, "entry count"):
            self.scan()

    def test_archive_symlinks_special_entries_and_unsafe_names_are_rejected(self):
        for name in ("../escape", "/absolute", "dir\\escape", "CON", "file:ads", "dir/./file", "name."):
            with self.subTest(name=name):
                # ZipInfo normalizes backslashes when writing on Windows. Set
                # both raw header names after writing a same-length safe name.
                raw_name = name.encode("utf-8")
                data = bytearray(archive([("x" * len(raw_name), b"x")]))
                for signature, length_offset, name_offset in (
                    (b"PK\x03\x04", 26, 30), (b"PK\x01\x02", 28, 46)
                ):
                    header = data.index(signature)
                    length = struct.unpack_from("<H", data, header + length_offset)[0]
                    self.assertEqual(length, len(raw_name))
                    start = header + name_offset
                    data[start:start + length] = raw_name
                    self.assertEqual(data[start:start + length], raw_name)
                self.put("bad.zip", data)
                with self.assertRaises(GuardError):
                    self.scan()
        for mode in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK):
            info = zipfile.ZipInfo("special")
            info.create_system = 3
            info.external_attr = (mode | 0o777) << 16
            self.put("bad.zip", archive([(info, b"target")]))
            with self.assertRaises(GuardError):
                self.scan()

    def test_implicit_directory_alias_and_duplicate_member_paths_fail(self):
        fixtures = [
            [("Dir/a", b"a"), ("dir/b", b"b")],
            [("one", b"a"), ("one/child", b"b")],
            [("one/a", b"a"), ("one", b"b")],
            [("A", b"a"), ("a", b"b")],
            [("same", b"a"), ("same", b"b")],
        ]
        for items in fixtures:
            with self.subTest(items=items):
                self.put("bad.zip", archive(items))
                with self.assertRaises(GuardError):
                    self.scan()

    def test_explicit_directory_after_implicit_directory_is_valid(self):
        self.put("valid.zip", archive([("dir/file", b"ok"), ("dir/", b"")]))
        self.assertTrue(self.scan()["ok"])

    def test_disabled_archive_expansion_cannot_silently_pass(self):
        self.configure(scan_zip_archives=False)
        self.put("payload.zip", archive([("secret", b"value")]))
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertIn("archive_not_scanned", {f["code"] for f in report["findings"]})
        self.assertEqual(report["checks"]["archives_scanned"], 0)
        self.assertFalse(report["checks"]["archive_scan_completed"])

    def test_detected_unsupported_archives_are_findings_even_when_renamed(self):
        self.put("asset.dat", b"\x1f\x8b" + b"opaque")
        self.put("electron.asar", b"opaque")
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertEqual({f["code"] for f in report["findings"]}, {"unsupported_archive"})
        self.assertFalse(report["checks"]["archive_scan_completed"])

    def test_malformed_and_truncated_zip_is_an_error(self):
        for data in (b"PK\x03\x04garbage", archive([("file", b"ok")])[:-5], b"not a zip"):
            self.put("bad.zip", data)
            with self.assertRaises(GuardError):
                self.scan()

    def test_encrypted_zip_header_is_rejected(self):
        data = bytearray(archive([("file", b"ok")]))
        local = data.index(b"PK\x03\x04")
        central = data.index(b"PK\x01\x02")
        struct.pack_into("<H", data, local + 6, 1)
        struct.pack_into("<H", data, central + 8, 1)
        self.put("encrypted.zip", bytes(data))
        with self.assertRaisesRegex(GuardError, "Encrypted"):
            self.scan()

    def test_unsupported_zip_compression_is_rejected(self):
        self.put("other.zip", archive([("file", b"ok")], compression=zipfile.ZIP_BZIP2))
        with self.assertRaisesRegex(GuardError, "unsupported|supported"):
            self.scan()

    def test_central_directory_preflight_prevents_declared_count_evasion(self):
        data = bytearray(archive([("a", b"x"), ("b", b"x")]))
        end = data.rindex(b"PK\x05\x06")
        struct.pack_into("<HH", data, end + 8, 1, 1)
        self.put("bad.zip", bytes(data))
        with patch.object(distribution.zipfile, "ZipFile", side_effect=AssertionError("must reject before allocation")):
            with self.assertRaisesRegex(GuardError, "declared bounds"):
                self.scan()

    def test_crc_corruption_fails_closed(self):
        data = bytearray(archive([("file", b"payload")], compression=zipfile.ZIP_STORED))
        data[data.index(b"payload")] ^= 1
        self.put("bad.zip", bytes(data))
        with self.assertRaises(GuardError):
            self.scan()

    def test_forged_smaller_sizes_and_prefix_crc_do_not_hide_compressed_suffix(self):
        payload = b"public-prefix\x00-----BEGIN PRIVATE KEY-----"
        for name, wanted_size in (("file", len(b"public-prefix")), ("assets/", 0)):
            for change_local in (False, True):
                data = bytearray(archive([(name, payload)]))
                local = data.index(b"PK\x03\x04")
                central = data.index(b"PK\x01\x02")
                crc = zlib.crc32(payload[:wanted_size])
                struct.pack_into("<I", data, central + 16, crc)
                struct.pack_into("<I", data, central + 24, wanted_size)
                if change_local:
                    struct.pack_into("<I", data, local + 14, crc)
                    struct.pack_into("<I", data, local + 22, wanted_size)
                self.put("bad.zip", data)
                with self.subTest(name=name, change_local=change_local):
                    with self.assertRaises(GuardError):
                        self.scan()

    def test_deflate_decoder_errors_are_guard_errors(self):
        data = bytearray(archive([("file", b"ok")]))
        local = data.index(b"PK\x03\x04")
        name_size, extra_size = struct.unpack_from("<HH", data, local + 26)
        data[local + 30 + name_size + extra_size] = 0xff  # Reserved DEFLATE block type.
        self.put("bad.zip", data)
        with self.assertRaises(GuardError):
            self.scan()

    def test_unindexed_compressed_local_record_between_members_is_rejected(self):
        original = archive([("one", b"one"), ("two", b"two")])
        with zipfile.ZipFile(io.BytesIO(original)) as handle:
            insertion = handle.getinfo("two").header_offset
        unindexed = archive([("hidden", b"-----BEGIN PRIVATE KEY-----")]).split(b"PK\x01\x02")[0]
        data = bytearray(original[:insertion] + unindexed + original[insertion:])
        first = data.index(b"PK\x01\x02")
        second = data.index(b"PK\x01\x02", first + 1)
        old_offset = struct.unpack_from("<I", data, second + 42)[0]
        struct.pack_into("<I", data, second + 42, old_offset + len(unindexed))
        end = data.rindex(b"PK\x05\x06")
        old_directory = struct.unpack_from("<I", data, end + 16)[0]
        struct.pack_into("<I", data, end + 16, old_directory + len(unindexed))
        self.put("unindexed.zip", data)
        with self.assertRaisesRegex(GuardError, "unindexed"):
            self.scan()

    def test_central_member_cannot_refer_to_another_disk(self):
        data = bytearray(archive([("file", b"ok")]))
        central = data.index(b"PK\x01\x02")
        struct.pack_into("<H", data, central + 34, 1)
        self.put("split.zip", data)
        with self.assertRaisesRegex(GuardError, "disk"):
            self.scan()

    def test_unicode_path_override_is_rejected_independently_of_python_version(self):
        info = zipfile.ZipInfo("public.txt")
        alternate = b"\x01" + struct.pack("<I", zlib.crc32(b"public.txt")) + b".env"
        info.extra = struct.pack("<HH", 0x7075, len(alternate)) + alternate
        self.put("alias.zip", archive([(info, b"sensitive")]))
        with self.assertRaisesRegex(GuardError, "Unicode Path"):
            self.scan()

    def test_zip64_local_headers_are_explicitly_unsupported(self):
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w") as handle:
            with handle.open("small", "w", force_zip64=True) as member:
                member.write(b"ok")
        self.put("zip64.zip", target.getvalue())
        with self.assertRaisesRegex(GuardError, "ZIP64"):
            self.scan()

    def test_streamed_zip_data_descriptors_are_validated(self):
        class Unseekable(io.BytesIO):
            def seek(self, *args):
                raise io.UnsupportedOperation("not seekable")
        target = Unseekable()
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as handle:
            handle.writestr("file", b"public")
        data = target.getvalue()
        self.put("streamed.zip", data)
        self.assertTrue(self.scan()["ok"])
        mutated = bytearray(data)
        descriptor = mutated.index(b"PK\x07\x08")
        mutated[descriptor + 4] ^= 1
        self.put("streamed.zip", mutated)
        with self.assertRaisesRegex(GuardError, "descriptor"):
            self.scan()

    def test_finding_budget_does_not_truncate_into_success(self):
        self.put("file", b"-----BEGIN PRIVATE KEY----- sourceMappingURL")
        with patch.object(distribution, "_MAX_FINDINGS", 1):
            with self.assertRaisesRegex(GuardError, "finding limit"):
                self.scan()


if __name__ == "__main__":
    unittest.main()
