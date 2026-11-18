"""Known opaque package layouts cannot pass as ordinary byte payloads."""

from __future__ import annotations

import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from releaseguard.distribution import scan_release
from tests.test_asar import asar, zip_archive
from tests.test_elf import make_elf


def v7_tar(data: bytes, name: str = "owned/module.bin") -> bytes:
    member = tarfile.TarInfo(name)
    member.size = len(data)
    # V7 uses the first 257 bytes of the POSIX header without ustar extension
    # fields. Independently read back below with Python's established TAR reader.
    header = bytearray(member.tobuf(format=tarfile.USTAR_FORMAT))
    header[257:] = b"\0" * (512 - 257)
    header[148:156] = b" " * 8
    header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
    return bytes(header) + data + b"\0" * (-len(data) % 512) + b"\0" * 1024


class OpaqueCompressionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned opaque packages ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "release"
        self.root.mkdir()
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="utf-8")
        self.target = self.root / "renamed.data"

    def scan(self, payload):
        self.target.write_bytes(payload)
        report = scan_release(self.root, self.policy)
        self.assertEqual(self.target.read_bytes(), payload)
        return report

    def test_v7_tar_hiding_native_debug_metadata_is_recognized_when_renamed(self):
        native = bytes(make_elf(entries=[(".debug_info", 1)]))
        payload = v7_tar(native)
        with tarfile.open(fileobj=io.BytesIO(payload)) as reader:
            self.assertEqual(reader.getnames(), ["owned/module.bin"])
            self.assertEqual(reader.extractfile("owned/module.bin").read(), native)
        report = self.scan(payload)
        self.assertFalse(report["ok"])
        self.assertFalse(report["checks"]["archive_scan_completed"])
        self.assertEqual(report["findings"], [{"code": "unsupported_archive", "path": self.target.name}])

    def test_v7_tar_is_rejected_inside_zip_and_asar(self):
        payload = v7_tar(b"owned data")
        for wrapper in (lambda value: zip_archive("archive.data", value),
                        lambda value: asar([("archive.data", value)])):
            with self.subTest(wrapper=wrapper):
                report = self.scan(wrapper(payload))
                self.assertFalse(report["ok"])
                self.assertEqual(report["findings"], [{"code": "unsupported_archive", "path": self.target.name,
                                                       "archive_members": ["archive.data"]}])

    def test_v7_recognition_requires_checksum_and_bounded_canonical_header(self):
        payload = v7_tar(b"owned")
        checksum = bytearray(payload)
        checksum[0] ^= 1
        unsupported_tail = bytearray(payload)
        unsupported_tail[300] = 1
        invalid_number = bytearray(payload)
        invalid_number[124:136] = b"not-an-octal"
        for invalid in (unsupported_tail, invalid_number):
            invalid[148:156] = b" " * 8
            invalid[148:156] = f"{sum(invalid[:512]):06o}\0 ".encode("ascii")
        fixtures = (bytes(checksum), bytes(unsupported_tail), bytes(invalid_number),
                    payload[:512], payload[:-1], b"\0" * 2048, b"public " * 400)
        for data in fixtures:
            with self.subTest(size=len(data), prefix=data[:8]):
                # An unrecognized layout must not be mislabeled as parsed TAR.
                # Native/literal checks remain independent of this recognition.
                self.assertTrue(self.scan(data)["ok"])

    def test_v7_nonascii_filename_uses_unsigned_checksum(self):
        self.assertFalse(self.scan(v7_tar(b"owned", "owned/\u00e9.bin"))["ok"])

    def test_expected_brotli_names_are_explicitly_unsupported(self):
        for name in ("app.js.br", "sources.map.BR"):
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(b"opaque Brotli candidate")
                report = scan_release(self.root, self.policy)
                self.assertFalse(report["ok"])
                self.assertFalse(report["checks"]["archive_scan_completed"])
                self.assertEqual(report["findings"], [{"code": "unsupported_archive", "path": name}])
                path.unlink()

    def test_brotli_names_inside_supported_containers_are_not_ignored(self):
        for wrapper in (lambda value: zip_archive("app.js.br", value),
                        lambda value: asar([("app.js.br", value)])):
            report = self.scan(wrapper(b"opaque Brotli candidate"))
            self.assertEqual(report["findings"], [{"code": "unsupported_archive", "path": self.target.name,
                                                   "archive_members": ["app.js.br"]}])

    @unittest.skipUnless(shutil.which("node"), "Brotli control needs Node's built-in zlib")
    def test_real_brotli_source_map_round_trip_is_blocked_by_expected_suffix(self):
        source = b'{"version":3,"sources":["owned.ts"],"mappings":"AAAA","sourcesContent":["const owned = 47;"]}'
        encoder = "const z=require('node:zlib'); let c=[]; process.stdin.on('data',d=>c.push(d)); process.stdin.on('end',()=>process.stdout.write(z.brotliCompressSync(Buffer.concat(c))));"
        decoder = "const z=require('node:zlib'); let c=[]; process.stdin.on('data',d=>c.push(d)); process.stdin.on('end',()=>process.stdout.write(z.brotliDecompressSync(Buffer.concat(c))));"
        encoded = subprocess.run(["node", "-e", encoder], input=source, capture_output=True, check=True, timeout=30).stdout
        decoded = subprocess.run(["node", "-e", decoder], input=encoded, capture_output=True, check=True, timeout=30).stdout
        self.assertEqual(decoded, source)
        self.assertNotIn(b"sourcesContent", encoded)
        self.target = self.root / "sources.map.br"
        report = self.scan(encoded)
        self.assertFalse(report["ok"])
        self.assertEqual(report["findings"], [{"code": "unsupported_archive", "path": self.target.name}])
        self.assertFalse(report["checks"]["archive_scan_completed"])


if __name__ == "__main__":
    unittest.main()
