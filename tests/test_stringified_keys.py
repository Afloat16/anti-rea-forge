"""Owned keys recovered by real JSON consumers and bounded nested inspection."""

import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from releaseguard import structured_secrets as secrets
from releaseguard.core import GuardError
from releaseguard.distribution import scan_release
from tests.test_asar import asar, zip_archive


SEED = bytes(range(255, 223, -1))
ASSET_KEY = bytes(range(224, 256))
ISSUER = Ed25519PrivateKey.from_private_bytes(SEED)
MESSAGE = b"owned stringified JSON recovery proof"
PLAINTEXT = b"owned private asset outside release staging"
NONCE = bytes(range(12))
CIPHERTEXT = AESGCM(ASSET_KEY).encrypt(NONCE, PLAINTEXT, MESSAGE)
PUBLIC = ISSUER.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
PEM = ISSUER.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
DER = ISSUER.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
JWK = {"kty": "OKP", "crv": "Ed25519",
       "d": base64.urlsafe_b64encode(SEED).decode().rstrip("="),
       "x": base64.urlsafe_b64encode(PUBLIC).decode().rstrip("=")}
NODE = shutil.which("node")


def serialized(value, layers=1):
    for _ in range(layers):
        value = json.dumps(value, separators=(",", ":"))
    return value


class StringifiedKeyTests(unittest.TestCase):
    def assert_jwk(self, document, layers):
        findings = secrets.scan_json_secrets(document)
        self.assertIn({"code": "private_key_structure", "representation": "json-stringified-jwk",
                       "stringified_layers": layers, "kind": "OKP"}, findings)
        encoded = json.dumps(findings).encode()
        for secret in (SEED, SEED.hex().encode(), JWK["d"].encode(), hashlib.sha256(SEED).hexdigest().encode(),
                       b"signingConfiguration"):
            self.assertNotIn(secret, encoded)

    @unittest.skipUnless(NODE, "Node.js is required for real nested JSON key consumption")
    def test_real_node_json_parse_recovers_signatures_and_known_asset_keys(self):
        program = r"""const fs=require('node:fs'),c=require('node:crypto');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
let key=input.key;
for(let i=0;i<input.layers;i++)key=JSON.parse(key);
if(input.kind==='jwk'){
 console.log(JSON.stringify(c.sign(null,Buffer.from(input.message,'base64'),
 c.createPrivateKey({key,format:'jwk'})).toString('base64')));
}else{
 const ciphertext=Buffer.from(input.ciphertext,'base64');
 const decipher=c.createDecipheriv('aes-256-gcm',Buffer.from(key),Buffer.from(input.nonce,'base64'));
 decipher.setAAD(Buffer.from(input.message,'base64'));
 decipher.setAuthTag(ciphertext.subarray(-16));
 console.log(JSON.stringify(Buffer.concat([decipher.update(ciphertext.subarray(0,-16)),
 decipher.final()]).toString('base64')));
}"""
        unicode_jwk = '"' + "".join("\\u%04x" % ord(c) for c in serialized(JWK)) + '"'
        cases = [(serialized(JWK), 1, "jwk"), (serialized(JWK, 2), 2, "jwk"),
                 (unicode_jwk, 2, "jwk"), (serialized(list(ASSET_KEY)), 1, "asset"),
                 (serialized(list(ASSET_KEY), 2), 2, "asset"),
                 (serialized([float(n) for n in ASSET_KEY]), 1, "asset")]
        for value, layers, kind in cases:
            with self.subTest(layers=layers, kind=kind):
                data = {"key": value, "layers": layers, "kind": kind,
                        "message": base64.b64encode(MESSAGE).decode(),
                        "ciphertext": base64.b64encode(CIPHERTEXT).decode(),
                        "nonce": base64.b64encode(NONCE).decode()}
                result = subprocess.run([NODE, "-e", program], input=json.dumps(data),
                                        text=True, capture_output=True, timeout=15, check=True)
                self.assertEqual(result.stderr, "")
                recovered = base64.b64decode(json.loads(result.stdout))
                if kind == "jwk":
                    ISSUER.public_key().verify(recovered, MESSAGE)
                    self.assert_jwk({"signingConfiguration": value}, layers)
                else:
                    self.assertEqual(recovered, PLAINTEXT)
                    findings = secrets.scan_json_secrets({"configuration": value}, asset_keys=(ASSET_KEY,))
                    self.assertIn({"code": "asset_key_exposure", "rule_index": 0,
                                   "representation": "json-stringified-byte-array",
                                   "stringified_layers": layers}, findings)

    def test_json_keys_roots_nested_members_and_whitespace_share_inspection(self):
        for document, layers in [(serialized(JWK), 1), ({serialized(JWK): "public"}, 1),
                                 ([{"settings": serialized(JWK)}], 1),
                                 (" \t\r\n" + serialized(JWK) + " \t\r\n", 1),
                                 (serialized({"nested": serialized(JWK)}), 2)]:
            with self.subTest(layers=layers):
                self.assert_jwk(document, layers)

    def test_private_pem_and_der_inside_serialized_containers_use_existing_readers(self):
        for value, representation in [(base64.b64encode(PEM).decode(), "json-stringified-base64-pem"),
                                      (DER.hex(), "json-stringified-hex-der-pkcs8")]:
            findings = secrets.scan_json_secrets(serialized({"key": value}))
            self.assertTrue(any(f["representation"] == representation and f["stringified_layers"] == 1
                                for f in findings), findings)

    def test_normal_text_public_jwk_arrays_templates_and_unrelated_large_strings_pass(self):
        public = {key: value for key, value in JWK.items() if key != "d"}
        document = ["ordinary documentation", serialized(public), "[1,2,3,4]",
                    '{"theme":"light","scale":1.25}', "{render at runtime}",
                    '"quoted prose"', "[not valid JSON]", "x" * 300_000,
                    "{render " + "template " * 40000 + "}",
                    "public { embedded template } text", "\u00a0" + serialized(public)]
        with patch.object(secrets, "scan_der_private_key", side_effect=AssertionError("private decoder invoked")):
            self.assertEqual(secrets.scan_json_secrets(document, asset_keys=(ASSET_KEY,)), [])

    def test_known_asset_key_profile_remains_active_when_private_key_policy_is_off(self):
        value = serialized(list(ASSET_KEY), 2)
        self.assertEqual(secrets.scan_json_secrets(value, check_private_keys=False), [])
        report = secrets.scan_json_secrets(value, check_private_keys=False, asset_keys=(ASSET_KEY,))
        self.assertEqual(report, [{"code": "asset_key_exposure", "rule_index": 0,
                                  "representation": "json-stringified-byte-array", "stringified_layers": 2}])
        self.assertEqual(secrets.scan_json_secrets(serialized(JWK), check_private_keys=False), [])

    def test_empty_public_containers_need_no_decode_budget_but_nonempty_containers_do(self):
        with tempfile.TemporaryDirectory(prefix="owned-empty-containers-") as directory:
            work = Path(directory).resolve()
            root = work / "release"
            root.mkdir()
            policy = work / "policy.json"
            policy.write_text('{"version":1}', encoding="ascii")
            empty = ["[]", "{}", '""', " \t[ \r\n ] "] * 65
            cases = [(empty, 0, True, None),
                     ([serialized({"public": index}) for index in range(65)], 3, False,
                      "structured_secret_unverifiable"),
                     (empty + [serialized(JWK)], 3, True, "private_key_structure")]
            for document, expected, completed, code in cases:
                with self.subTest(expected=expected, completed=completed):
                    (root / "settings.json").write_text(json.dumps(document), encoding="ascii")
                    result = subprocess.run([sys.executable, "-I", "-m", "releaseguard", "scan-release",
                        "--root", str(root), "--policy", str(policy)], cwd=work,
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(result.stderr, "")
                    report = json.loads(result.stdout)
                    self.assertEqual(report["ok"], expected == 0)
                    self.assertEqual(report["checks"]["structured_secret_scan_completed"], completed)
                    if expected:
                        self.assertEqual({item["code"] for item in report["findings"]}, {code})

    def test_third_additional_decode_and_raw_utf8_bytes_fail_explicitly(self):
        with self.assertRaisesRegex(GuardError, "decode layer limit"):
            secrets.scan_json_secrets(serialized(JWK, 3))
        for value in (serialized({"data": "x" * secrets.MAX_JSON_STRINGIFIED_TEXT_BYTES}),
                      '{"data":"' + "\U0001f642" * (secrets.MAX_JSON_STRINGIFIED_TEXT_BYTES // 4) + '"}'):
            with self.assertRaisesRegex(GuardError, "raw text limit"):
                secrets.scan_json_secrets(value)

    def test_der_pem_and_json_share_candidate_and_byte_budgets(self):
        text = serialized(JWK)
        values = [text, DER.hex(), base64.b64encode(PEM).decode()]
        with patch.object(secrets, "MAX_JSON_DER_CANDIDATES", 2):
            with self.assertRaisesRegex(GuardError, "JSON decode budget"):
                secrets.scan_json_secrets(values)
        with patch.object(secrets, "MAX_JSON_DER_DECODED_BYTES", len(text.encode()) + len(DER) - 1):
            with self.assertRaisesRegex(GuardError, "JSON decode budget"):
                secrets.scan_json_secrets(values[:2])
        with patch.object(secrets, "MAX_JSON_DER_CANDIDATES", 1):
            with self.assertRaisesRegex(GuardError, "JSON decode budget"):
                secrets.scan_json_secrets(['{"invalid":}', "[tru]"])

    def test_nested_parsed_nodes_and_depth_consume_outer_tree_limits(self):
        with patch.object(secrets, "MAX_JSON_SECRET_NODES", 8):
            with self.assertRaisesRegex(GuardError, "node or depth limit"):
                secrets.scan_json_secrets(["[1,2,3]", "[4,5,6]"])
        with patch.object(secrets, "MAX_JSON_SECRET_DEPTH", 2):
            with self.assertRaisesRegex(GuardError, "node or depth limit"):
                secrets.scan_json_secrets({"data": serialized({"value": "public"})})

    def test_duplicate_fields_nonfinite_numbers_and_huge_integers_fail_without_values(self):
        values = ['{"secretProperty":0,"secretProperty":1}', '[1e999]', '[NaN]', '[Infinity]',
                  '[123' + '4' * 5000 + ']']
        for value in values:
            with self.subTest(prefix=value[:12]):
                with self.assertRaisesRegex(GuardError, "ambiguous or exceeds") as raised:
                    secrets.scan_json_secrets(value)
                self.assertNotIn("secretProperty", str(raised.exception))
                self.assertNotIn("1234", str(raised.exception))

    def test_nested_archives_and_wide_json_use_same_profile_and_incomplete_status(self):
        with tempfile.TemporaryDirectory(prefix="owned-stringified-") as directory:
            work = Path(directory)
            root = work / "release"
            root.mkdir()
            policy = work / "policy.json"
            policy.write_text('{"version":1}', encoding="ascii")
            for encoding in ("utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
                raw = json.dumps({"key": serialized(JWK)}).encode(encoding)
                artifact = root / "data.bin"
                artifact.write_bytes(zip_archive("inner.data", asar([("configuration.data", raw)])))
                report = scan_release(root, policy)
                self.assertFalse(report["ok"])
                self.assertTrue(report["checks"]["structured_secret_scan_completed"])
                self.assertTrue(any(f.get("representation") == "json-stringified-jwk" for f in report["findings"]))
            for value in (serialized(JWK, 3), '{"sensitiveProperty":1,"sensitiveProperty":2}'):
                artifact.write_text(json.dumps({"key": value}))
                report = scan_release(root, policy)
                self.assertFalse(report["ok"])
                self.assertFalse(report["checks"]["structured_secret_scan_completed"])
                self.assertIn("structured_secret_unverifiable", {f["code"] for f in report["findings"]})
                self.assertNotIn("sensitiveProperty", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
