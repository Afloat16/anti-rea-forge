"""Owned ASAR fixtures exercise real member boundaries and scanner recursion."""

import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from releaseguard.asar import looks_like_asar, read_asar_entries, read_asar_member
from releaseguard.core import GuardError
from releaseguard.distribution import scan_release


def asar_header(document, data=b"", *, raw=None):
    text = raw if raw is not None else json.dumps(document, separators=(",", ":")).encode()
    padding = b"\0" * (-len(text) % 4)
    header_size = 8 + len(text) + len(padding)
    return struct.pack("<4I", 4, header_size, header_size - 4, len(text)) + text + padding + data


def asar(files, *, integrity=False):
    root = {"files": {}}
    body = bytearray()
    for name, data in files:
        directory = root["files"]
        parts = name.split("/")
        for part in parts[:-1]:
            directory = directory.setdefault(part, {"files": {}})["files"]
        node = {"offset": str(len(body)), "size": len(data)}
        if integrity:
            block_size = 4
            chunks = [data[start:start + block_size] for start in range(0, len(data), block_size)] or [b""]
            node["integrity"] = {"algorithm": "SHA256", "hash": hashlib.sha256(data).hexdigest(),
                                 "blockSize": block_size,
                                 "blocks": [hashlib.sha256(chunk).hexdigest() for chunk in chunks]}
        directory[parts[-1]] = node
        body.extend(data)
    return asar_header(root, bytes(body))


def zip_archive(name, data):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, data)
    return out.getvalue()


class AsarParserTests(unittest.TestCase):
    def entries(self, data, **kwargs):
        return read_asar_entries(io.BytesIO(data), len(data), max_entries=kwargs.get("max_entries", 100),
                                 max_member_bytes=kwargs.get("max_member_bytes", 4096))

    def test_canonical_packed_files_directories_empty_files_and_integrity(self):
        data = asar([("main.js", b"public"), ("assets/empty", b""), ("assets/data", b"123456789")], integrity=True)
        self.assertTrue(looks_like_asar(data))
        entries = self.entries(data)
        found = {entry.name: read_asar_member(io.BytesIO(data), entry) for entry in entries if not entry.directory}
        self.assertEqual(found, {"main.js": b"public", "assets/empty": b"", "assets/data": b"123456789"})

    def test_exact_deduplicated_ranges_supported_but_partial_overlap_rejected(self):
        root = {"files": {"a": {"offset": "0", "size": 4}, "b": {"offset": "0", "size": 4}}}
        data = asar_header(root, b"abcd")
        self.assertEqual(len(self.entries(data)), 2)
        root["files"]["b"] = {"offset": "1", "size": 3}
        with self.assertRaisesRegex(GuardError, "overlapping"):
            self.entries(asar_header(root, b"abcd"))

    def test_unindexed_prefix_trailing_data_and_oversized_members_rejected(self):
        for offset, size, body in (("1", 2, b"abc"), ("0", 1, b"abc"), ("0", 4, b"abc")):
            with self.subTest(offset=offset, size=size), self.assertRaises(GuardError):
                self.entries(asar_header({"files": {"a": {"offset": offset, "size": size}}}, body))
        with self.assertRaisesRegex(GuardError, "max_file_bytes"):
            self.entries(asar([("a", b"12345")]), max_member_bytes=4)

    def test_header_lengths_padding_duplicate_keys_and_bounds_rejected(self):
        good = asar([("a", b"ok")])
        corruptions = [good[:10], good[:4] + struct.pack("<I", 2**32 - 1) + good[8:],
                       good[:12] + struct.pack("<I", 2**32 - 1) + good[16:],
                       asar_header({}, raw=b'{"files":{},"files":{}}')]
        # A tiny canonical header has padding; nonzero bytes cannot be hidden there.
        padded = bytearray(asar_header({"files": {}}))
        padded[-1] = 1
        corruptions.append(bytes(padded))
        for data in corruptions:
            with self.subTest(size=len(data)), self.assertRaises(GuardError):
                self.entries(data)

    def test_paths_links_unpacked_unknown_layouts_and_numeric_ambiguity_rejected(self):
        for name in ("../private", "/absolute", "a\\b", "CON", "a.", "e\u0301", "a:b"):
            with self.subTest(name=name), self.assertRaises(GuardError):
                self.entries(asar_header({"files": {name: {"offset": "0", "size": 0}}}))
        for node in ({"link": "elsewhere"}, {"unpacked": True, "size": 0},
                     {"files": {}, "unpacked": True}, {"offset": "00", "size": 0},
                     {"offset": "0", "size": False}, {"offset": "0", "size": 0, "future": True},
                     {"files": {}, "offset": "0", "size": 0}):
            with self.subTest(node=node), self.assertRaises(GuardError):
                self.entries(asar_header({"files": {"a": node}}))
        with self.assertRaisesRegex(GuardError, "colliding"):
            self.entries(asar_header({"files": {"A": {"files": {}}, "a": {"offset": "0", "size": 0}}}))

    def test_header_entry_and_directory_depth_limits(self):
        with self.assertRaisesRegex(GuardError, "max_archive_entries"):
            self.entries(asar([("a", b""), ("b", b"")]), max_entries=1)
        root = {"files": {}}
        node = root
        for _ in range(65):
            child = {"files": {}}
            node["files"]["d"] = child
            node = child
        with self.assertRaisesRegex(GuardError, "nesting"):
            self.entries(asar_header(root))
        with patch("releaseguard.asar.MAX_DOCUMENT_BYTES", 8), self.assertRaisesRegex(GuardError, "header exceeds"):
            self.entries(asar([("a", b"")]))

    def test_integrity_mismatch_and_truncation_cannot_pass(self):
        data = asar([("a", b"owned fixture")], integrity=True)
        entry = self.entries(data)[0]
        with self.assertRaisesRegex(GuardError, "digest mismatch"):
            read_asar_member(io.BytesIO(data[:-1] + b"!"), entry)
        with self.assertRaisesRegex(GuardError, "truncated"):
            read_asar_member(io.BytesIO(data[:-1]), entry)
        header_size = struct.unpack_from("<I", data, 4)[0]
        json_size = struct.unpack_from("<I", data, 12)[0]
        root = json.loads(data[16:16 + json_size])
        root["files"]["a"]["integrity"]["blocks"][0] = "0" * 64
        bad_blocks = asar_header(root, data[8 + header_size:])
        with self.assertRaisesRegex(GuardError, "block digest mismatch"):
            read_asar_member(io.BytesIO(bad_blocks), self.entries(bad_blocks)[0])


class AsarScanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="asar owned controls ")
        self.addCleanup(temporary.cleanup)
        # Use the owned real directory when the host's temp path is an alias.
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "release"
        self.root.mkdir()
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="utf-8")
        self.target = self.root / "renamed.bin"

    def configure(self, **kwargs):
        self.policy.write_text(json.dumps({"version": 1, **kwargs}), encoding="utf-8")

    def test_renamed_asar_scans_decoded_names_and_member_bytes(self):
        self.target.write_bytes(asar([(".env", b"a value"), ("source.map", b"{}")]))
        report = scan_release(self.root, self.policy)
        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"]["archives_scanned"], 1)
        self.assertEqual(report["checks"]["archive_entries"], 2)
        self.assertTrue(any(item["code"] == "forbidden_path_component" and item["archive_members"] == [".env"]
                            for item in report["findings"]))
        self.assertEqual(list(self.root.iterdir()), [self.target])

    def test_mixed_zip_asar_nesting_uses_all_rules_and_global_budgets(self):
        key = bytes(range(32))
        key_file = self.work / "external.key"
        key_file.write_bytes(key)
        inner = zip_archive("key.bin", key)
        packaged = asar([("payload.zip", inner)])
        self.target.write_bytes(packaged)
        report = scan_release(self.root, self.policy, asset_key_files=[key_file])
        self.assertFalse(report["ok"])
        self.assertTrue(any(item["code"] == "asset_key_exposure"
                            and item.get("archive_members") == ["payload.zip", "key.bin"] for item in report["findings"]))
        self.assertEqual(report["checks"]["bytes_scanned"], len(packaged) + len(inner) + len(key))
        self.configure(max_archive_depth=1)
        with self.assertRaisesRegex(GuardError, "nesting"):
            scan_release(self.root, self.policy)
        self.configure(max_archive_entries=1)
        with self.assertRaisesRegex(GuardError, "entry count"):
            scan_release(self.root, self.policy)
        self.configure(max_total_bytes=len(packaged) + len(inner) + len(key) - 1)
        with self.assertRaises(GuardError):
            scan_release(self.root, self.policy)

    def test_asar_inside_zip_and_disabled_scanning_never_report_clean(self):
        packaged = asar([(".env", b"private")])
        self.target.write_bytes(zip_archive("renamed.dat", packaged))
        report = scan_release(self.root, self.policy)
        self.assertFalse(report["ok"])
        self.assertTrue(any(item.get("archive_members") == ["renamed.dat", ".env"] for item in report["findings"]))
        self.configure(scan_asar_archives=False)
        report = scan_release(self.root, self.policy)
        self.assertFalse(report["ok"])
        self.assertFalse(report["checks"]["archive_scan_completed"])
        self.assertTrue(any(item["code"] == "archive_not_scanned" for item in report["findings"]))

    def test_clean_ordinary_asar_passes_and_opaque_named_asar_fails(self):
        self.target.write_bytes(asar([("app.js", b"export const answer = 42;")], integrity=True))
        self.assertTrue(scan_release(self.root, self.policy)["ok"])
        self.target.unlink()
        (self.root / "app.asar").write_bytes(b"not an ASAR")
        with self.assertRaises(GuardError):
            scan_release(self.root, self.policy)


if __name__ == "__main__":
    unittest.main()
