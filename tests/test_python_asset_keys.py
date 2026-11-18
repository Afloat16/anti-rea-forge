"""Canonical integer disclosures in owned, executable CPython bytecode."""

import base64
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import marshal
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from releaseguard.core import GuardError
from releaseguard.distribution import scan_release
from releaseguard.encoded_asset_keys import (
    MAX_PYC_ASSET_KEYS, MAX_PYC_SCAN_BYTES, scan_pyc_asset_keys,
)
from tests.test_asar import asar, zip_archive


KEY = bytes(range(224, 256))
OTHER_KEY = bytes(range(128, 160))


def owned_pyc(source, *, version=4, flags=3):
    """Only this trusted local fixture generator is allowed to marshal code."""
    code = compile(source, "owned/pricing.py", "exec", dont_inherit=True, optimize=0)
    header = importlib.util.MAGIC_NUMBER + struct.pack("<I", flags)
    header += importlib.util.source_hash(source.encode()) if flags & 1 else bytes(8)
    return header + marshal.dumps(code, version)


def key_source(key=KEY, *, byteorder="big", signed=False, repeat=False):
    integer = int.from_bytes(key, byteorder, signed=signed)
    source = ("def public_price(quantity):\n    return max(0, quantity) * 7 + 11\n\n"
              "def asset_key():\n"
              f"    return ({integer}).to_bytes(32, {byteorder!r}, signed={signed!r})\n")
    if repeat:
        source += ("\ndef another_key():\n"
                   f"    return ({integer}).to_bytes(32, {byteorder!r}, signed={signed!r})\n")
    return source


class PythonAssetKeys(unittest.TestCase):
    def scan(self, data, keys=(KEY,), size=None):
        return scan_pyc_asset_keys(io.BytesIO(data), len(data) if size is None else size,
                                   asset_keys=keys)

    def assert_findings(self, report, indexes=(0,)):
        self.assertEqual(report["format"], "cpython-pyc")
        self.assertEqual(report["profile"], "canonical-marshal-integer/v1")
        self.assertIs(report["full_marshal_validation_performed"], False)
        self.assertEqual(report["findings"], [
            {"code": "asset_key_exposure", "rule_index": index,
             "representation": "python-marshal-integer"} for index in indexes])

    def assert_report_contains_no_key(self, report, key=KEY):
        raw = json.dumps(report).encode()
        for form in (key, key.hex().encode(), base64.b64encode(key),
                     hashlib.sha256(key).hexdigest().encode(),
                     *(str(int.from_bytes(key, order, signed=signed)).encode()
                       for order in ("big", "little") for signed in (False, True))):
            self.assertNotIn(form, raw)
        self.assertNotIn(b"owned/pricing.py", raw)
        self.assertNotIn(b"asset_key()", raw)

    def execute_owned(self, data):
        with tempfile.TemporaryDirectory(prefix="owned-pyc-") as temporary:
            path = Path(temporary) / "pricing.pyc"
            path.write_bytes(data)
            loader = importlib.machinery.SourcelessFileLoader("owned_pyc_fixture", str(path))
            spec = importlib.util.spec_from_loader(loader.name, loader)
            module = importlib.util.module_from_spec(spec)
            loader.exec_module(module)
            return module

    def test_all_signed_endian_and_reference_flag_forms_recover_exact_keys(self):
        for version in (2, 4):
            for order in ("big", "little"):
                for signed in (False, True):
                    with self.subTest(version=version, order=order, signed=signed):
                        data = owned_pyc(key_source(byteorder=order, signed=signed), version=version)
                        self.assertNotIn(KEY, data)
                        self.assertNotIn(KEY.hex().encode(), data)
                        module = self.execute_owned(data)
                        self.assertEqual(module.asset_key(), KEY)
                        self.assertEqual([module.public_price(q) for q in (-3, 0, 1, 9)], [11, 11, 18, 74])
                        report = self.scan(data)
                        self.assert_findings(report)
                        self.assert_report_contains_no_key(report)
                        self.assertEqual(report["bytes_scanned"], len(data))

    def test_leading_zero_bytes_preserve_exact_32_byte_reconstruction(self):
        for key in (b"\0" * 4 + bytes(range(224, 252)),
                    bytes(range(224, 252)) + b"\0" * 4,
                    ((1 << 127) + 3).to_bytes(32, "big")):
            for order in ("big", "little"):
                for signed in (False, True):
                    with self.subTest(order=order, signed=signed, prefix_zero=key[0] == 0):
                        data = owned_pyc(key_source(key, byteorder=order, signed=signed))
                        self.assertEqual(self.execute_owned(data).asset_key(), key)
                        report = self.scan(data, (key,))
                        self.assert_findings(report)
                        self.assert_report_contains_no_key(report, key)

    def test_reference_reuse_needs_one_definition_and_one_finding(self):
        source = key_source(repeat=True)
        v2, v4 = owned_pyc(source, version=2), owned_pyc(source, version=4)
        # The real interpreter's reference sharing makes the v4 artifact smaller;
        # the scanner never follows TYPE_REF indexes or executes its body.
        self.assertLess(len(v4), len(v2))
        for data in (v2, v4):
            module = self.execute_owned(data)
            self.assertEqual(module.asset_key(), module.another_key())
            self.assert_findings(self.scan(data))

    def test_public_pyc_stays_executable_and_unmatched_key_does_not_trigger(self):
        source = "def public_price(quantity):\n    return max(0, quantity) * 7 + 11\n"
        data = owned_pyc(source)
        before = bytes(data)
        self.assert_findings(self.scan(data), ())
        self.assertEqual(data, before)
        module = self.execute_owned(data)
        self.assertEqual(module.public_price(9), 74)
        self.assertIn(b"public_price", data)
        unrelated = owned_pyc(key_source(OTHER_KEY))
        self.assert_findings(self.scan(unrelated), ())
        self.assert_findings(self.scan(unrelated, (KEY, OTHER_KEY)), (1,))

    def test_non_pyc_data_does_not_enter_the_integer_profile(self):
        for data in (b"", b"a", b"ab\r\npublic", b"{}", marshal.dumps(1 << 200),
                     b"\x00\x00\r\n" + bytes(40), b"PK\x03\x04" + bytes(40)):
            with self.subTest(data_prefix=data[:4]):
                self.assertIsNone(self.scan(data))
                self.assertIsNone(self.scan(data, (bytes(32),)))

    def test_short_unsigned_or_signed_alias_is_explicitly_incomplete(self):
        keys = (bytes(32), b"\0" * 31 + b"\1", b"\1" + b"\0" * 31,
                b"\xff" * 32, ((1 << 126) + 3).to_bytes(32, "big"))
        data = owned_pyc("public = 1\n")
        for key in keys:
            with self.subTest(first_byte=key[0], last_byte=key[-1]):
                with self.assertRaisesRegex(GuardError, "short integer representation"):
                    self.scan(data, (key,))

    def test_header_flags_zero_one_two_three_match_interpreter_acceptance(self):
        for flags in range(4):
            data = owned_pyc(key_source(), flags=flags)
            self.assertEqual(self.execute_owned(data).asset_key(), KEY)
            self.assert_findings(self.scan(data))
        data = bytearray(owned_pyc(key_source()))
        for flags in (4, 0xff, 0xffffffff):
            data[4:8] = struct.pack("<I", flags)
            with self.assertRaisesRegex(GuardError, "flags"):
                self.scan(bytes(data))

    def test_magic_profile_recognition_is_distinct_from_marshal_validation(self):
        data = owned_pyc("public = 1\n")
        for magic, version in ((3394, "3.7"), (3413, "3.8"), (3425, "3.9"),
                               (3439, "3.10"), (3495, "3.11"), (3531, "3.12"),
                               (3571, "3.13"), (3627, "3.14")):
            # Header classification only: this intentionally does not claim a
            # 3.12 code-object layout executes under another interpreter version.
            report = self.scan(struct.pack("<H", magic) + data[2:])
            self.assertEqual(report["python_version"], version)
            self.assertIs(report["full_marshal_validation_performed"], False)
        for magic in (3000, 3390, 3391, 3500, 3666, 3999):
            with self.assertRaisesRegex(GuardError, "magic"):
                self.scan(struct.pack("<H", magic) + data[2:])

    def test_truncated_headers_wrong_tag_and_size_changes_are_incomplete(self):
        data = owned_pyc(key_source())
        for length in range(4, 17):
            with self.assertRaisesRegex(GuardError, "truncated"):
                self.scan(data[:length])
        with self.assertRaisesRegex(GuardError, "code-object tag"):
            self.scan(data[:16] + b"N" + data[17:])
        with self.assertRaisesRegex(GuardError, "grew"):
            self.scan(data, size=len(data) - 1)
        with self.assertRaisesRegex(GuardError, "size changed"):
            self.scan(data, size=len(data) + 1)

    def test_exact_profile_does_not_promise_full_marshal_or_code_validation(self):
        # Deliberately malformed synthetic body: no general decoder is invoked.
        # The empty finding set only means the configured canonical record is
        # absent, not that this would be safe or valid to load as Python code.
        data = importlib.util.MAGIC_NUMBER + bytes(12) + b"cnot a code object"
        report = self.scan(data)
        self.assert_findings(report, ())
        self.assertIs(report["full_marshal_validation_performed"], False)

    def test_chunk_boundaries_and_short_reads_do_not_hide_long_records(self):
        data = owned_pyc(key_source(repeat=True))
        for width in (1, 2, 7, 17, 23, 38, 39, 40, 64):
            with patch("releaseguard.encoded_asset_keys._CHUNK_BYTES", width):
                self.assert_findings(self.scan(data))

        class ShortReads(io.BytesIO):
            def read(self, size=-1):
                return super().read(min(size, 2))

        self.assert_findings(scan_pyc_asset_keys(ShortReads(data), len(data), asset_keys=(KEY,)))

    def test_budget_rejection_is_bounded_and_never_executes_or_unmarshals(self):
        data = owned_pyc(key_source())

        class CountingReads(io.BytesIO):
            requested = []

            def read(self, size=-1):
                self.requested.append(size)
                return super().read(size)

        stream = CountingReads(data)
        with self.assertRaisesRegex(GuardError, "byte limit"):
            scan_pyc_asset_keys(stream, MAX_PYC_SCAN_BYTES + 1, asset_keys=(KEY,))
        self.assertEqual(stream.requested, [4])
        with patch("marshal.loads", side_effect=AssertionError("untrusted marshal invoked")), \
                patch("marshal.load", side_effect=AssertionError("untrusted marshal invoked")), \
                patch("builtins.exec", side_effect=AssertionError("examined program executed")):
            self.assert_findings(self.scan(data))
        with patch("releaseguard.encoded_asset_keys.MAX_PYC_SCAN_BYTES", len(data)):
            self.assert_findings(self.scan(data))
        with patch("releaseguard.encoded_asset_keys.MAX_PYC_SCAN_BYTES", len(data) - 1):
            with self.assertRaises(GuardError):
                self.scan(data)

    def test_arguments_are_bounded_and_invalid_streams_fail_closed(self):
        data = owned_pyc(key_source())
        for keys in ([KEY], (KEY[:-1],), (bytearray(KEY),), (KEY,) * (MAX_PYC_ASSET_KEYS + 1)):
            with self.assertRaises(GuardError):
                self.scan(data, keys)
        for size in (-1, True, None, "1"):
            with self.assertRaises(GuardError):
                scan_pyc_asset_keys(io.BytesIO(data), size, asset_keys=(KEY,))
        self.assert_findings(self.scan(data, ()), ())
        self.assertEqual(self.scan(data, ())["keys_checked"], 0)

        class OverReads(io.BytesIO):
            def read(self, size=-1):
                return super().read(size + 1)

        with self.assertRaises(GuardError):
            scan_pyc_asset_keys(OverReads(data), len(data), asset_keys=(KEY,))
        with self.assertRaises(GuardError):
            scan_pyc_asset_keys(io.StringIO("public"), 6, asset_keys=(KEY,))
        closed = io.BytesIO(data)
        closed.close()
        with self.assertRaises(GuardError):
            scan_pyc_asset_keys(closed, len(data), asset_keys=(KEY,))


class PythonAssetKeyReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="pyc-release-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.public = self.work / "public"
        self.public.mkdir()
        self.key = self.work / "configured.key"
        self.key.write_bytes(KEY)
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="ascii")

    def scan(self, name, data, *, configure=True):
        for path in self.public.iterdir():
            path.unlink()
        path = self.public / name
        path.write_bytes(data)
        report = scan_release(self.public, self.policy,
                              asset_key_files=[self.key] if configure else [])
        self.assertEqual(path.read_bytes(), data, "Read-only inspection changed the release")
        return report

    def test_disclosure_and_clean_controls_work_on_disk_renamed_and_in_nested_archives(self):
        for disclosed in (False, True):
            pyc = owned_pyc(key_source() if disclosed else "public = 17\n")
            cases = (
                ("pricing.pyc", pyc, None),
                ("renamed.bin", pyc, None),
                ("application.pyz", zip_archive("__main__.pyc", pyc), ["__main__.pyc"]),
                ("application.asar", asar([("data/module.bin", pyc)]), ["data/module.bin"]),
                ("outer.zip", zip_archive("app.asar", asar([("data/module.bin", pyc)])),
                 ["app.asar", "data/module.bin"]),
            )
            for name, data, members in cases:
                with self.subTest(disclosed=disclosed, container=name):
                    report = self.scan(name, data)
                    self.assertEqual(report["ok"], not disclosed)
                    self.assertEqual(report["checks"]["pyc_asset_key_files_checked"], 1)
                    self.assertTrue(report["checks"]["pyc_asset_key_scan_completed"])
                    self.assertTrue(report["checks"]["structured_secret_scan_completed"])
                    findings = [f for f in report["findings"]
                                if f.get("representation") == "python-marshal-integer"]
                    self.assertEqual(len(findings), int(disclosed))
                    if findings:
                        self.assertEqual(findings[0].get("archive_members"), members)
                        self.assertEqual(findings[0]["rule_index"], 0)
                    self.assertNotIn(KEY.hex(), json.dumps(report))
                    self.assertNotIn(str(int.from_bytes(KEY, "big")), json.dumps(report))

    def test_incomplete_pyc_profile_is_separate_from_json_and_der_completion(self):
        pyc = owned_pyc("public = 17\n")
        unsupported = struct.pack("<H", 3666) + pyc[2:]
        for data in (unsupported, pyc):
            if data == pyc:
                self.key.write_bytes(b"\xff" * 32)
            report = self.scan("application.pyz", zip_archive("__main__.pyc", data))
            self.assertFalse(report["ok"])
            self.assertEqual(report["checks"]["pyc_asset_key_files_checked"], 1)
            self.assertFalse(report["checks"]["pyc_asset_key_scan_completed"])
            self.assertTrue(report["checks"]["structured_secret_scan_completed"])
            self.assertTrue(any(f["code"] == "structured_secret_unverifiable"
                                and f.get("format") == "cpython-pyc"
                                for f in report["findings"]))
            self.assertFalse(any(f["code"] == "asset_key_exposure" for f in report["findings"]))
        self.assertTrue(self.scan("public.txt", b"ordinary public text")["ok"])

    def test_unconfigured_keys_are_an_explicit_boundary_not_general_secret_discovery(self):
        report = self.scan("pricing.pyc", owned_pyc(key_source()), configure=False)
        self.assertTrue(report["ok"])
        self.assertFalse(report["checks"]["pyc_asset_keys_checked"])
        self.assertEqual(report["checks"]["pyc_asset_key_files_checked"], 0)
        self.assertIsNone(report["checks"]["pyc_asset_key_profile"])


if __name__ == "__main__":
    unittest.main()
