"""Release checks for accidentally packaged native bearer credentials."""

from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard import distribution
from releaseguard.core import GuardError
from releaseguard.native_token import issue_native_token
from releaseguard.project import check_project, init_project, prepare_release


class NativeTokenScanTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.root = self.base / "release"
        self.root.mkdir()
        self.policy = self.base / "policy.json"
        self.configure()
        # Deliberately a shape control; no verifier has been issued for this value.
        self.shaped = "rg1_" + "abcdef0123456789" * 4

    def configure(self, **options):
        self.policy.write_text(json.dumps({"version": 1, **options}), encoding="utf-8")

    def scan(self):
        return distribution.scan_release(self.root, self.policy)

    def test_issued_public_headers_pass_real_private_file_blocks_without_echo(self):
        private = self.base / "restricted"
        private.mkdir()
        credential = private / "unlock.txt"
        issue_native_token(self.root / "include", credential)
        report = self.scan()
        self.assertTrue(report["ok"])
        self.assertTrue(report["checks"]["native_token_format_checked"])
        (self.root / "mistaken-backup.txt").write_bytes(credential.read_bytes())
        report = self.scan()
        self.assertFalse(report["ok"])
        self.assertEqual(report["findings"], [{"code": "native_token_exposure",
            "path": "mistaken-backup.txt", "encoding": "utf-8"}])
        self.assertNotIn(credential.read_text(encoding="ascii").strip(), json.dumps(report))

    def test_unaligned_encodings_cross_stream_boundaries_and_deduplicate(self):
        # Prefix and body span multiple blocks. A second match in a single
        # payload must not multiply findings, nor may a malformed first prefix
        # hide a later credential.
        encodings = ("utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")
        files = [f"blob-{i}" for i in range(len(encodings))]
        for name, enc in zip(files, encodings):
            payload = ("rg1_not-a-token:" + self.shaped + "!" + self.shaped + ";").encode(enc)
            (self.root / name).write_bytes(b"z" * 7 + payload)
        with patch.object(distribution, "_CHUNK_BYTES", 11):
            report = self.scan()
        self.assertFalse(report["ok"])
        observed = [(f["path"], f["encoding"]) for f in report["findings"]]
        self.assertEqual(len(observed), len(set(observed)))
        # Opposite endian interpretations of overlapping NULs can be ambiguous.
        for name, enc in zip(files, encodings):
            self.assertIn((name, enc), observed)
        self.assertNotIn(self.shaped, json.dumps(report))

    def test_near_misses_and_a_public_digest_are_not_bearers(self):
        text = "\n".join([
            self.shaped[4:], self.shaped[:-1], "RG1_" + self.shaped[4:],
            "rg1_" + "A" * 64, "rg1_" + "0" * 63 + "g",
            "rg1_" + "0" * 32 + "\x00" + "0" * 32, "rg1_ + 64 lowercase hex digits",
        ])
        (self.root / "public-info.dat").write_bytes(text.encode())
        self.assertTrue(self.scan()["ok"])

    def test_token_shape_inside_longer_text_is_conservatively_flagged(self):
        (self.root / "bundle.bin").write_bytes(("prefix" + self.shaped + "ab-more").encode())
        self.assertEqual(self.scan()["findings"][0]["code"], "native_token_exposure")

    def test_deflated_nested_archive_checks_expanded_member_not_just_outer_bytes(self):
        def zipped(name, data):
            stream = BytesIO()
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr(name, data)
            return stream.getvalue()

        raw = self.shaped.encode("utf-32-be")
        outer = zipped("nested.zip", zipped("debug/settings.bin", raw))
        self.assertNotIn(raw, outer)
        (self.root / "product.zip").write_bytes(outer)
        report = self.scan()
        self.assertEqual(report["checks"]["archives_scanned"], 2)
        self.assertIn({"code": "native_token_exposure", "path": "product.zip",
                       "archive_members": ["nested.zip", "debug/settings.bin"],
                       "encoding": "utf-32-be"}, report["findings"])
        self.assertNotIn(self.shaped, json.dumps(report))

    def test_explicit_opt_out_keeps_other_policy_checks(self):
        (self.root / "example.txt").write_text(self.shaped, encoding="ascii")
        self.configure(check_native_tokens=False)
        report = self.scan()
        self.assertTrue(report["ok"])
        self.assertFalse(report["checks"]["native_token_format_checked"])
        (self.root / "leak.pem").write_bytes(b"-----BEGIN PRIVATE KEY-----")
        self.assertEqual({f["code"] for f in self.scan()["findings"]}, {"private_key_marker"})
        for bad in ("false", 0, None):
            self.configure(check_native_tokens=bad)
            with self.subTest(option=bad), self.assertRaises(GuardError):
                distribution.load_distribution_policy(self.policy)

    def test_default_project_check_and_prepare_do_not_publish_a_token(self):
        setup = self.base / ".releaseguard"
        init_project(self.root, "scan-tests", setup)
        config = setup / "project.json"
        (self.root / "debug.dat").write_text(self.shaped, encoding="ascii")
        checked = check_project(config)
        self.assertFalse(checked["ok"])
        bundle = self.base / "public-evidence"
        result = prepare_release(config, Ed25519PrivateKey.generate(), "1", bundle)
        self.assertFalse(result["prepared"])
        self.assertEqual(result["scan"]["findings"], checked["findings"])
        self.assertFalse(bundle.exists())
        self.assertNotIn(self.shaped, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
