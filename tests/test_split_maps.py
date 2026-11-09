"""Exercise the published/private split as a file transformation, not an evasion score."""

import gzip
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from releaseguard.core import GuardError
from releaseguard.split_maps import split_source_maps


class SplitMapsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="source map split ")
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        self.root = work / "input"
        self.assets = self.root / "assets"
        self.assets.mkdir(parents=True)
        self.public = work / "release"
        self.private = work / "symbols"
        self.app = self.assets / "app.js"
        self.marker = work / "not-executed"
        self.app.write_bytes(b"console.log(42);\n")
        self.content = "// synthetic private source\nexport const n: number = 42;\n"
        self.doc = {"version": 3, "sources": ["../src/a.ts"], "names": ["n"],
                    "sourcesContent": [self.content], "mappings": "AAAAA,CAAA;AACA"}
        self.map_file = self.assets / "app.js.MAP"
        self.map_file.write_text(json.dumps(self.doc), encoding="utf-8")

    def split(self):
        return split_source_maps(self.root, self.public, self.private)

    def assert_rolled_back(self):
        self.assertFalse(self.public.exists())
        self.assertFalse(self.private.exists())

    def test_hidden_map_is_private_with_relative_names_and_public_bytes_preserved(self):
        (self.root / "empty").mkdir()
        (self.assets / "chunk.js").write_bytes(b"export default 42;")
        before = {p.relative_to(self.root): (p.read_bytes(), p.stat().st_mtime_ns)
                  for p in self.root.rglob("*") if p.is_file()}
        if os.name == "posix":
            self.app.chmod(0o751)
        r = self.split()
        self.assertTrue(r["ok"])
        self.assertEqual(r["public_files"], 2)
        self.assertEqual(r["private_maps"], 1)
        self.assertTrue(r["public_bytes_unchanged"])
        self.assertEqual((self.public / "assets/app.js").read_bytes(), self.app.read_bytes())
        self.assertTrue((self.public / "empty").is_dir())
        self.assertEqual({p.relative_to(self.private).as_posix()
                          for p in self.private.rglob("*") if p.is_file()}, {"assets/app.js.MAP"})
        self.assertEqual((self.private / "assets/app.js.MAP").read_bytes(), self.map_file.read_bytes())
        self.assertFalse((self.public / "assets/app.js.MAP").exists())
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE((self.public / "assets/app.js").stat().st_mode), 0o751)
            for p in (self.private, self.private / "assets", self.private / "assets/app.js.MAP"):
                self.assertEqual(stat.S_IMODE(p.stat().st_mode) & 0o077, 0)
        self.assertEqual(before, {p.relative_to(self.root): (p.read_bytes(), p.stat().st_mtime_ns)
                                  for p in self.root.rglob("*") if p.is_file()})
        self.assertNotIn(self.content, json.dumps(r))

    def test_inline_url_and_external_url_are_policy_findings_not_rewritten(self):
        for url in ("app.js.map", "data:application/json;base64,e30="):
            with self.subTest(url=url):
                raw = f"console.log(42);\n//# sourceMappingURL={url}\n".encode()
                self.app.write_bytes(raw)
                r = self.split()
                self.assertFalse(r["ok"])
                self.assertIn("source_map_marker", {f["code"] for f in r["findings"]})
                self.assertEqual(self.app.read_bytes(), raw)
                self.assert_rolled_back()

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits")
    def test_success_restores_public_directory_modes_without_special_bits(self):
        self.root.chmod(0o751)
        self.assets.chmod(0o750)
        empty = self.root / "empty"
        empty.mkdir()
        empty.chmod(0o1750)
        self.assertTrue(self.split()["ok"])
        self.assertEqual(stat.S_IMODE(self.public.stat().st_mode), 0o751)
        self.assertEqual(stat.S_IMODE((self.public / "assets").stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((self.public / "empty").stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((self.private / "assets").stat().st_mode), 0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits")
    def test_failure_after_read_only_directory_mode_is_applied_still_rolls_back(self):
        self.root.chmod(0o751)
        self.assets.chmod(0o550)
        self.addCleanup(self.assets.chmod, 0o700)
        real_chmod = os.chmod
        observed = []

        def failing(path, mode):
            if path == self.public and mode == 0o751:
                observed.append(stat.S_IMODE((self.public / "assets").stat().st_mode))
                raise OSError("synthetic final metadata failure")
            return real_chmod(path, mode)

        with patch("releaseguard.split_maps.os.chmod", side_effect=failing):
            with self.assertRaises(OSError):
                self.split()
        self.assertEqual(observed, [0o550])
        self.assert_rolled_back()

    def test_complete_original_source_cannot_ship_as_an_unrelated_asset(self):
        (self.root / "unrelated.txt").write_bytes(self.content.encode())
        r = self.split()
        self.assertIn({"code": "embedded_source_copy", "path": "unrelated.txt"}, r["findings"])
        self.assert_rolled_back()

    def test_renamed_regular_and_indexed_maps_checked_semantically(self):
        for name, data in [
            ("alias.dat", b'{"version": 3,"sour\\u0063es":["x"],"mapp\\u0069ngs":"AAAA"}'),
            ("style.bin", (b")]}'\n" + b'{"version":3,"sec\\u0074ions":[]}')),
            ("other.txt", '{"version":3,"mappings":"","sources":[]}'.encode("utf-16")),
        ]:
            with self.subTest(name=name):
                p = self.root / name
                p.write_bytes(data)
                r = self.split()
                self.assertIn({"code": "disguised_source_map", "path": name}, r["findings"])
                self.assert_rolled_back()
                p.unlink()

    def test_non_source_map_default_portable_findings_are_not_filtered_out(self):
        (self.root / "private.pem").write_bytes(b"-----BEGIN PRIVATE KEY-----")
        (self.root / ".git").mkdir()
        r = self.split()
        codes = {f["code"] for f in r["findings"]}
        self.assertFalse(r["ok"])
        self.assertTrue({"private_key_marker", "forbidden_path_component"} <= codes)
        self.assert_rolled_back()

    def test_compressed_or_opaque_packaging_is_refused_before_publishing(self):
        zipped = io.BytesIO()
        with zipfile.ZipFile(zipped, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("inner/debug.map", self.map_file.read_bytes())
        for name, data in [("archive.blob", zipped.getvalue()), ("app.map.gz", gzip.compress(b"map")),
                           ("app.js.br", b"precompressed"), ("debug.asar", b"opaque")]:
            with self.subTest(name=name):
                p = self.root / name
                p.write_bytes(data)
                self.assertFalse(self.split()["ok"])
                self.assert_rolled_back()
                p.unlink()

    def test_invalid_private_maps_or_vlq_positions_cannot_count_as_protection(self):
        cases = [b"not a source map", b'{"version":3,"version":3}', b'{"version":3,"sections":[]}',
                 json.dumps({**self.doc, "sourcesContent": [123]}).encode()]
        for mappings in ("!", "g", "AAA", "AAAAAA", "ACAA", "BAAA", "AAAA,,C", "AAAA,"):
            cases.append(json.dumps({**self.doc, "mappings": mappings}).encode())
        for data in cases:
            with self.subTest(data=data[:128]):
                self.map_file.write_bytes(data)
                with self.assertRaises(GuardError):
                    self.split()
                self.assert_rolled_back()

    def test_no_map_or_no_public_files_cannot_produce_a_protection_report(self):
        self.map_file.unlink()
        with self.assertRaises(GuardError):
            self.split()
        self.app.unlink()
        self.map_file.write_text(json.dumps(self.doc))
        with self.assertRaises(GuardError):
            self.split()
        self.assert_rolled_back()

    def test_distinct_new_roots_are_required_and_existing_output_is_untouched(self):
        for pub, private in [(self.public, self.public), (self.root / "publish", self.private),
                             (self.public, self.root / "symbols"), (self.public, self.public / "symbols")]:
            with self.subTest(pub=pub, private=private), self.assertRaises((GuardError, FileNotFoundError)):
                split_source_maps(self.root, pub, private)
        self.assert_rolled_back()
        self.private.mkdir()
        sentinel = self.private / "keep"
        sentinel.write_bytes(b"untouched")
        with self.assertRaises(GuardError):
            self.split()
        self.assertEqual(sentinel.read_bytes(), b"untouched")
        self.assertFalse(self.public.exists())

    def test_source_links_and_output_symlink_targets_are_never_followed(self):
        alias = self.assets / "alias"
        try:
            alias.symlink_to(self.app)
        except (OSError, NotImplementedError):
            self.skipTest("File symlinks are unavailable")
        with self.assertRaises(GuardError):
            self.split()
        alias.unlink()
        self.private.symlink_to(self.app)
        with self.assertRaises(GuardError):
            self.split()
        self.assertTrue(self.private.is_symlink())
        self.assertFalse(self.public.exists())
        self.assertEqual(self.app.read_bytes(), b"console.log(42);\n")

    def test_split_byte_budgets_are_enforced_before_reading_oversized_inputs(self):
        for field in ("_MAX_FILE", "_MAX_TOTAL", "MAX_DOCUMENT_BYTES"):
            with self.subTest(field=field), patch("releaseguard.split_maps." + field, 8):
                with self.assertRaises(GuardError):
                    self.split()
                self.assert_rolled_back()

    def test_no_execution_and_existing_successful_outputs_cannot_be_modified_by_rerun(self):
        (self.root / "setup.py").write_text(
            f"from pathlib import Path\nPath({str(self.marker)!r}).write_text('executed')\n")
        self.assertTrue(self.split()["ok"])
        self.assertFalse(self.marker.exists())
        self.app.write_text("new build")
        with self.assertRaises(GuardError):
            self.split()
        self.assertEqual((self.public / "assets/app.js").read_bytes(), b"console.log(42);\n")

    def test_policy_io_failures_clean_each_owned_output_tree(self):
        with patch("releaseguard.split_maps.scan_release", side_effect=OSError("synthetic failure")):
            with self.assertRaises(OSError):
                self.split()
        self.assert_rolled_back()

    def test_input_replacement_during_validation_never_succeeds(self):
        from releaseguard.distribution import scan_release

        def change(*args):
            result = scan_release(*args)
            replacement = self.root / "swap"
            replacement.write_bytes(b"Q" * self.app.stat().st_size)
            replacement.replace(self.app)
            return result

        with patch("releaseguard.split_maps.scan_release", side_effect=change):
            with self.assertRaises(GuardError):
                self.split()
        self.assert_rolled_back()


if __name__ == "__main__":
    unittest.main()
