"""Real JSON string roots cannot skip configured structured secret checks."""

from __future__ import annotations

import codecs
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard.distribution import scan_release


KEY = bytes(range(32))
PEM = Ed25519PrivateKey.from_private_bytes(KEY).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode("ascii")
ENCODINGS = (("utf-8", codecs.BOM_UTF8), ("utf-16-le", codecs.BOM_UTF16_LE),
             ("utf-16-be", codecs.BOM_UTF16_BE), ("utf-32-le", codecs.BOM_UTF32_LE),
             ("utf-32-be", codecs.BOM_UTF32_BE))


def escaped(value):
    return '"' + "".join("\\u%04x" % ord(character) for character in value) + '"'


class StructuredSecretRoots(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned structured root strings ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "public"
        self.root.mkdir()
        self.target = self.root / "renamed.data"
        self.policy = self.work / "policy.json"
        self.asset_key = self.work / "external.key"
        self.asset_key.write_bytes(KEY)

    def scan(self, data, *, policy=None, keys=True):
        self.target.write_bytes(data)
        self.policy.write_text(json.dumps(policy or {"version": 1}), encoding="utf-8")
        result = scan_release(self.root, self.policy, asset_key_files=[self.asset_key] if keys else [])
        self.assertEqual(self.target.read_bytes(), data)
        self.assertNotIn(KEY.hex(), json.dumps(result))
        return result

    def assert_blocked(self, data, code="asset_key_exposure", **kwargs):
        result = self.scan(data, **kwargs)
        self.assertFalse(result["ok"])
        self.assertTrue(result["checks"]["structured_secret_scan_completed"])
        self.assertTrue(any(item["code"] == code and item.get("representation") == "json-decoded-string"
                            for item in result["findings"]))
        return result

    def test_top_level_escaped_asset_hex_and_private_pem_are_recoverable(self):
        for value, code in ((KEY.hex(), "asset_key_exposure"), (PEM, "private_key_marker")):
            with self.subTest(code=code):
                data = escaped(value).encode("ascii")
                self.assertEqual(json.loads(data), value)
                self.assert_blocked(data, code)

    def test_string_roots_in_each_unicode_encoding_with_and_without_bom(self):
        for encoding, bom in ENCODINGS:
            for prefix in (b"", bom):
                with self.subTest(encoding=encoding, bom=bool(prefix)):
                    data = prefix + escaped(KEY.hex()).encode(encoding)
                    self.assertEqual(json.loads(data), KEY.hex())
                    self.assert_blocked(data)

    def test_xssi_string_roots_use_aligned_encoding_delimiters(self):
        for encoding, bom in ENCODINGS:
            with self.subTest(encoding=encoding):
                data = bom + (")]}'\n" + escaped(KEY.hex())).encode(encoding)
                self.assert_blocked(data)

    def test_private_checks_stay_enabled_when_map_checks_are_disabled(self):
        result = self.assert_blocked(escaped(PEM).encode(), "private_key_marker",
                                     policy={"version": 1, "check_source_maps": False}, keys=False)
        self.assertFalse(result["checks"]["source_map_structures_checked"])

    def test_explicit_opt_out_without_asset_keys_does_not_decode_roots(self):
        result = self.scan(escaped(PEM).encode(), keys=False,
                           policy={"version": 1, "check_private_keys": False, "check_source_maps": False})
        self.assertTrue(result["ok"])
        self.assertFalse(result["checks"]["structured_secrets_checked"])

    def test_asset_key_configuration_survives_private_and_map_optouts(self):
        self.assert_blocked(escaped(KEY.hex()).encode(),
                            policy={"version": 1, "check_private_keys": False, "check_source_maps": False})

    def test_quoted_nonjson_scripts_are_not_evaluated_or_claimed_decoded(self):
        for text in (escaped(KEY.hex()) + ";", escaped(PEM) + " + runtimeValue",
                     '"ordinary unterminated script', "'" + KEY.hex()[::2] + "' + 'rest'"):
            with self.subTest(prefix=text[:12]):
                self.assertTrue(self.scan(text.encode())["ok"])

    def test_json_string_root_beyond_eight_mib_is_unverifiable(self):
        result = self.scan(b'"' + b"x" * (8 << 20) + b'"', keys=False,
                           policy={"version": 1, "check_source_maps": False})
        self.assertFalse(result["ok"])
        self.assertFalse(result["checks"]["structured_secret_scan_completed"])
        self.assertEqual(result["findings"], [{"code": "structured_secret_unverifiable",
                                               "path": self.target.name, "reason": "json_byte_limit"}])


if __name__ == "__main__":
    unittest.main()
