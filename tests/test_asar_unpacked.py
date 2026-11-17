"""Unpacked ASAR members bind to the same inventoried sibling namespace."""

import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from releaseguard.asar import read_asar_entries, read_asar_member
from releaseguard.core import GuardError
from releaseguard.distribution import scan_release
from tests.test_asar import asar, asar_header


def external_asar(name, data, *, integrity=True):
    packed = asar([(name, data)], integrity=integrity)
    size = struct.unpack_from("<I", packed, 12)[0]
    header = json.loads(packed[16:16 + size])
    node = header
    for part in name.split("/"):
        node = node["files"][part]
    del node["offset"]
    node["unpacked"] = True
    return asar_header(header)


def zip_files(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files:
            archive.writestr(name, data)
    return out.getvalue()


class AsarUnpackedTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="asar sibling controls ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "release"
        self.root.mkdir()
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="utf-8")
        self.target = self.root / "resource.bin"

    def write_sidecar(self, name, data):
        target = self.root / ("resource.bin.unpacked/" + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    def scan(self, **kwargs):
        return scan_release(self.root, self.policy, **kwargs)

    def test_external_index_requires_opt_in_and_never_reads_header_as_payload(self):
        data = external_asar("addons/owned.node", b"owned")
        args = dict(max_entries=10, max_member_bytes=4096)
        with self.assertRaisesRegex(GuardError, "verified sibling namespace"):
            read_asar_entries(io.BytesIO(data), len(data), **args)
        entries = read_asar_entries(io.BytesIO(data), len(data), allow_unpacked=True, **args)
        entry = next(item for item in entries if not item.directory)
        self.assertTrue(entry.unpacked)
        self.assertEqual((entry.offset, entry.size), (0, 5))
        with self.assertRaisesRegex(GuardError, "cannot be read as packed"):
            read_asar_member(io.BytesIO(data), entry)

    def test_owned_physical_sidecar_is_scanned_once_and_bound_to_its_index(self):
        for data in (b"owned external bytes", b""):
            with self.subTest(size=len(data)):
                package = external_asar("addons/owned.node", data)
                self.target.write_bytes(package)
                self.write_sidecar("addons/owned.node", data)
                report = self.scan()
                self.assertTrue(report["ok"])
                self.assertEqual(report["checks"]["asar_unpacked_members_checked"], 1)
                self.assertEqual(report["checks"]["files_scanned"], 2)
                self.assertEqual(report["checks"]["bytes_scanned"], len(package) + len(data))
                self.assertIn("asar-unpacked-siblings", report["checks"]["archive_formats"])

    def test_legacy_external_index_without_integrity_still_checks_actual_bytes(self):
        data = b"owned legacy sidecar"
        self.target.write_bytes(external_asar("addon.node", data, integrity=False))
        self.write_sidecar("addon.node", data)
        self.assertTrue(self.scan()["ok"])

    def test_missing_wrong_size_changed_digest_and_unindexed_sidecars_are_rejected(self):
        data = b"owned"
        self.target.write_bytes(external_asar("addon.node", data))
        with self.assertRaisesRegex(GuardError, "missing from"):
            self.scan()
        sidecar = self.write_sidecar("addon.node", data + b"x")
        with self.assertRaisesRegex(GuardError, "size differs"):
            self.scan()
        sidecar.write_bytes(b"wrong")
        with self.assertRaisesRegex(GuardError, "digest mismatch"):
            self.scan()
        sidecar.write_bytes(data)
        self.write_sidecar("unindexed.bin", b"extra")
        with self.assertRaisesRegex(GuardError, "unindexed files"):
            self.scan()

    def test_empty_unpacked_directory_and_wholly_packed_archive_reject_stale_sidecars(self):
        packages = (
            asar_header({"files": {"addons": {"unpacked": True, "files": {}}}}),
            asar([("app.js", b"export const publicValue = 7;")]),
        )
        self.write_sidecar("unindexed.bin", b"stale external bytes")
        for package in packages:
            with self.subTest(package_size=len(package)):
                self.target.write_bytes(package)
                with self.assertRaisesRegex(GuardError, "unindexed files"):
                    self.scan()

    def test_incorrect_external_block_digest_cannot_pass(self):
        package = external_asar("addon.node", b"owned")
        size = struct.unpack_from("<I", package, 12)[0]
        header = json.loads(package[16:16 + size])
        header["files"]["addon.node"]["integrity"]["blocks"][0] = "0" * 64
        self.target.write_bytes(asar_header(header))
        self.write_sidecar("addon.node", b"owned")
        with self.assertRaisesRegex(GuardError, "block digest mismatch"):
            self.scan()

    def test_source_maps_and_external_keys_are_found_at_actual_sidecar_paths(self):
        key = bytes(range(32))
        private = self.work / "external.key"
        private.write_bytes(key)
        for name, data, expected in (
            ("owned.node", key, "asset_key_exposure"),
            ("data.bin", b'{"ver\\u0073ion":3,"sources":[],"mappings":""}', "source_map_structure"),
        ):
            with self.subTest(name=name):
                # Separate fixtures avoid leaving unindexed siblings behind.
                if self.target.exists():
                    self.target.unlink()
                sidecar_root = self.root / "resource.bin.unpacked"
                if sidecar_root.exists():
                    for previous in sidecar_root.iterdir():
                        previous.unlink()
                self.target.write_bytes(external_asar(name, data))
                self.write_sidecar(name, data)
                report = self.scan(asset_key_files=[private])
                self.assertFalse(report["ok"])
                self.assertTrue(any(item["code"] == expected and
                                    item["path"] == "resource.bin.unpacked/" + name
                                    for item in report["findings"]))

    def test_zip_siblings_work_even_when_sidecar_precedes_its_archive(self):
        data = b"owned zipped sidecar"
        package = external_asar("addons/owned.node", data)
        outer = zip_files([
            ("resources/application.asar.unpacked/addons/owned.node", data),
            ("resources/application.asar", package),
        ])
        self.target.write_bytes(outer)
        report = self.scan()
        self.assertTrue(report["ok"])
        self.assertEqual(report["checks"]["asar_unpacked_members_checked"], 1)
        self.assertEqual(report["checks"]["bytes_scanned"], len(outer) + len(package) + len(data))

    def test_packed_asar_siblings_are_resolved_inside_the_same_container(self):
        data = b"owned nested sidecar"
        package = external_asar("addon.node", data)
        self.target.write_bytes(asar([
            ("nested.asar.unpacked/addon.node", data),
            ("nested.asar", package),
        ]))
        report = self.scan()
        self.assertTrue(report["ok"])
        self.assertEqual(report["checks"]["archives_scanned"], 2)
        self.assertEqual(report["checks"]["asar_unpacked_members_checked"], 1)

    def test_an_external_file_in_another_namespace_cannot_satisfy_a_reference(self):
        data = b"owned"
        package = external_asar("addon.node", data)
        self.target.write_bytes(zip_files([("application.asar", package)]))
        other = self.root / "application.asar.unpacked"
        other.mkdir()
        (other / "addon.node").write_bytes(data)
        with self.assertRaisesRegex(GuardError, "missing from"):
            self.scan()

    def test_symlink_sidecar_and_wrong_archive_basename_are_rejected(self):
        data = b"owned"
        self.target.write_bytes(external_asar("addon.node", data))
        actual = self.work / "outside"
        actual.write_bytes(data)
        sidecar = self.root / "resource.bin.unpacked/addon.node"
        sidecar.parent.mkdir()
        try:
            sidecar.symlink_to(actual)
        except (OSError, NotImplementedError):
            self.skipTest("Symbolic-link creation is unavailable")
        with self.assertRaises(GuardError):
            self.scan()
        sidecar.unlink()
        (sidecar.parent / "addon.node").write_bytes(data)
        self.target.rename(self.root / "renamed.bin")
        with self.assertRaisesRegex(GuardError, "missing from"):
            self.scan()

    def test_external_members_obey_shared_byte_and_entry_budgets(self):
        data = b"owned"
        package = external_asar("addon.node", data)
        self.target.write_bytes(package)
        self.write_sidecar("addon.node", data)
        self.policy.write_text(json.dumps({"version": 1, "max_total_bytes": len(package) + len(data) - 1}))
        with self.assertRaisesRegex(GuardError, "budget|remaining"):
            self.scan()
        self.policy.write_text(json.dumps({"version": 1, "scan_asar_archives": False}))
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertFalse(report["checks"]["archive_scan_completed"])

    def test_unpacked_directories_cannot_hide_packed_or_ambiguous_entries(self):
        valid = {"files": {"addons": {"unpacked": True, "files": {
            "owned.node": {"unpacked": True, "size": 0},
        }}}}
        data = asar_header(valid)
        entries = read_asar_entries(io.BytesIO(data), len(data), max_entries=4,
                                    max_member_bytes=4, allow_unpacked=True)
        self.assertTrue(all(item.unpacked for item in entries))
        for bad in ({"unpacked": True, "size": 0, "offset": "0"},
                    {"unpacked": False, "size": 0, "offset": "0"},
                    {"size": 0, "offset": "0"}):
            with self.subTest(bad=bad):
                valid["files"]["addons"]["files"]["owned.node"] = bad
                data = asar_header(valid)
                with self.assertRaises(GuardError):
                    read_asar_entries(io.BytesIO(data), len(data), max_entries=4,
                                      max_member_bytes=4, allow_unpacked=True)


if __name__ == "__main__":
    unittest.main()
