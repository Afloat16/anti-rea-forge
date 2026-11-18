"""Standalone debug containers cannot evade checks by losing their .pdb suffix."""

from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest

from releaseguard.distribution import scan_release
from tests.test_asar import asar, zip_archive


# Independent format fixtures follow microsoft/microsoft-pdb PDB/msf/msf.cpp
# and dotnet/runtime's PortablePdb-Metadata.md. They are not compiler output or
# a claimed complete MSF/PDB implementation.
MSF7 = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0"
MSF2 = b"Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0"


def portable_metadata(*, pdb: bool = True) -> bytes:
    version = b"PDB v1.0\0\0\0\0" if pdb else b"v4.0.30319\0\0"
    header = b"BSJB" + struct.pack("<HHII", 1, 1, 0, len(version)) + version
    # ECMA-335 metadata root: stream names are NUL-terminated and padded to 4.
    streams = [(b"#~\0\0", struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, 0, 0))]
    if pdb:
        streams.insert(0, (b"#Pdb\0\0\0\0", b"\0" * 32))
    directory_size = sum(8 + len(name) for name, _ in streams)
    offset = len(header) + 4 + directory_size
    directory, body = bytearray(), bytearray()
    for name, content in streams:
        directory.extend(struct.pack("<II", offset, len(content)) + name)
        body.extend(content)
        offset += len(content)
    return header + struct.pack("<HH", 0, len(streams)) + directory + body


class StandaloneMetadataTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned debug metadata ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "release"
        self.root.mkdir()
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="utf-8")
        self.target = self.root / "renamed.bin"

    def assert_unverifiable(self, data, format_name, *, members=()):
        self.target.write_bytes(data)
        report = scan_release(self.root, self.policy)
        self.assertFalse(report["ok"])
        self.assertFalse(report["checks"]["native_metadata_scan_completed"])
        self.assertEqual(report["checks"]["native_files_checked"], 1)
        expected = {"code": "native_metadata_unverifiable", "path": "renamed.bin",
                    "format": format_name, "reason": "unsupported_standalone_metadata"}
        if members:
            expected["archive_members"] = list(members)
        self.assertEqual(report["findings"], [expected])
        self.assertEqual(self.target.read_bytes(), data)

    def test_microsoft_signatures_are_recognized_without_name_hints(self):
        for data, format_name in ((MSF7 + b"\0\0" + b"\0" * 128, "msf7"),
                                  (MSF2 + b"\0" * 128, "msf2"),
                                  (portable_metadata(), "cli-metadata")):
            with self.subTest(format=format_name):
                self.assert_unverifiable(data, format_name)

    def test_msf7_alignment_bytes_are_not_part_of_microsofts_magic(self):
        # Microsoft's 30-byte memcmp ignores two structure-alignment bytes;
        # requiring LLVM's canonical 32 bytes would let this variant pass.
        self.assert_unverifiable(MSF7 + b"AB" + b"\0" * 128, "msf7")

    def test_metadata_is_rejected_inside_zip_and_asar(self):
        for payload, format_name in ((MSF7 + b"\0" * 64, "msf7"),
                                     (MSF2 + b"\0" * 64, "msf2"),
                                     (portable_metadata(), "cli-metadata")):
            for wrapper in (lambda data: zip_archive("symbols.data", data),
                            lambda data: asar([("symbols.data", data)])):
                with self.subTest(format=format_name, wrapper=wrapper):
                    self.assert_unverifiable(wrapper(payload), format_name,
                                             members=("symbols.data",))

    def test_truncated_recognized_containers_fail_closed(self):
        for data, format_name in ((MSF7, "msf7"), (MSF2, "msf2"), (b"BSJB", "cli-metadata")):
            with self.subTest(format=format_name):
                self.assert_unverifiable(data, format_name)

    def test_cli_magic_does_not_claim_every_metadata_root_is_a_portable_pdb(self):
        # BSJB is shared with ordinary CLI metadata. A raw root is unsupported,
        # not evidence that #Pdb or any particular private field was decoded.
        self.assert_unverifiable(portable_metadata(pdb=False), "cli-metadata")

    def test_metadata_option_can_be_explicitly_disabled(self):
        self.policy.write_text(json.dumps({"version": 1, "check_native_metadata": False}),
                               encoding="utf-8")
        for payload in (MSF7, MSF2, portable_metadata()):
            self.target.write_bytes(payload)
            report = scan_release(self.root, self.policy)
            self.assertTrue(report["ok"])
            self.assertFalse(report["checks"]["native_metadata_checked"])

    def test_unrelated_text_does_not_trigger_native_metadata(self):
        for payload in (b"Public docs mention " + MSF7,
                        b"Microsoft C/C++ public documentation", b"public BSJB string"):
            with self.subTest(payload=payload):
                self.target.write_bytes(payload)
                self.assertTrue(scan_release(self.root, self.policy)["ok"])


if __name__ == "__main__":
    unittest.main()
