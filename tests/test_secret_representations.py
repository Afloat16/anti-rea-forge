"""Consumer-backed key-recovery regressions and bounded encoded-DER admission."""

import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from releaseguard import structured_secrets as secrets
from releaseguard.core import GuardError
from releaseguard.distribution import scan_release
from tests.test_asar import asar, zip_archive


NODE = shutil.which("node")
KEY = bytes(range(224, 256))  # Public fixture material, never a production key.
ISSUER = Ed25519PrivateKey.from_private_bytes(bytes(range(255, 223, -1)))
DER = ISSUER.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
SPKI = ISSUER.public_key().public_bytes(serialization.Encoding.DER,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
MESSAGE = b"owned consumer recovery proof"
NONCE = bytes(12)
PAYLOAD = b"owned external-key payload"
SEALED = AESGCM(KEY).encrypt(NONCE, PAYLOAD, MESSAGE)
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def jwk():
    return {"kty": "OKP", "crv": "Ed25519", "d": b64(ISSUER.private_bytes_raw()),
            "x": b64(ISSUER.public_key().public_bytes_raw())}


class SecretRepresentationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="owned representation controls ")
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name).resolve()
        self.root = self.work / "public"
        self.root.mkdir()
        self.key = self.work / "known.key"
        self.key.write_bytes(KEY)
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="ascii")

    def scan(self, document, *, keys=False, encoded=None, policy=None):
        data = json.dumps(document).encode() if encoded is None else encoded
        (self.root / "payload.data").write_bytes(data)
        self.policy.write_text(json.dumps(policy or {"version": 1}), encoding="ascii")
        report = scan_release(self.root, self.policy, asset_key_files=[self.key] if keys else [])
        self.assertEqual((self.root / "payload.data").read_bytes(), data)
        return report

    def blocked(self, report, code):
        self.assertFalse(report["ok"])
        self.assertTrue(report["checks"]["structured_secret_scan_completed"])
        self.assertTrue(any(row["code"] == code for row in report["findings"]), report["findings"])

    def node(self, program, value):
        result = subprocess.run([NODE, "-e", program], input=json.dumps(value), text=True,
                                capture_output=True, timeout=15, check=True)
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout)

    @unittest.skipUnless(NODE, "Node.js required for real key-import compatibility")
    def test_real_node_jwk_import_recovers_bounded_consumer_base64_variants(self):
        original = jwk()
        private = original["d"]
        variants = (private.replace("-", "+").replace("_", "/"),
                    private[:15] + "\r\n " + private[15:],
                    private[:-1] + ALPHABET[ALPHABET.index(private[-1]) | 1],
                    private[:10] + "!" + private[10:], "\u00a0" + private, "\0" + private,
                    private + "====", private + "=YWJj",
                    "".join(chr(ord(char) + 256) for char in private),
                    "".join(chr(0x10000 + ord(char)) for char in private),
                    "\ud800" + private)
        script = """const c=require('node:crypto'),fs=require('node:fs');
const k=c.createPrivateKey({format:'jwk',key:JSON.parse(fs.readFileSync(0,'utf8'))});
console.log(JSON.stringify({spki:c.createPublicKey(k).export({type:'spki',format:'der'}).toString('base64'),
 signature:c.sign(null,Buffer.from('owned consumer recovery proof'),k).toString('base64')}));"""
        for text in variants:
            self.assertNotEqual(text, private)
            document = {**original, "d": text}
            result = self.node(script, document)
            self.assertEqual(base64.b64decode(result["spki"]), SPKI)
            signature = base64.b64decode(result["signature"])
            ISSUER.public_key().verify(signature, MESSAGE)
            self.assertEqual(signature, ISSUER.sign(MESSAGE))
            self.blocked(self.scan(document), "private_key_structure")

    @unittest.skipUnless(NODE, "Node.js required for real RSA integer compatibility")
    def test_real_node_rsa_leading_zero_integers_restore_the_same_signing_key(self):
        issuer = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        numbers = issuer.private_numbers()
        values = {"n": numbers.public_numbers.n, "e": numbers.public_numbers.e,
                  "d": numbers.d, "p": numbers.p, "q": numbers.q,
                  "dp": numbers.dmp1, "dq": numbers.dmq1, "qi": numbers.iqmp}
        document = {"kty": "RSA", **{field: b64(b"\0" + value.to_bytes((value.bit_length() + 7) // 8, "big"))
                                      for field, value in values.items()}}
        script = """const c=require('node:crypto'),fs=require('node:fs');
const k=c.createPrivateKey({format:'jwk',key:JSON.parse(fs.readFileSync(0,'utf8'))});
console.log(JSON.stringify(c.sign('sha256',Buffer.from('owned consumer recovery proof'),k).toString('base64')));"""
        signature = base64.b64decode(self.node(script, document))
        issuer.public_key().verify(signature, MESSAGE, padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual(signature, issuer.sign(MESSAGE, padding.PKCS1v15(), hashes.SHA256()))
        self.blocked(self.scan(document), "private_key_structure")

    @unittest.skipUnless(NODE, "Node.js required for real Buffer array compatibility")
    def test_real_node_numeric_equivalence_and_embedded_array_windows_decrypt(self):
        script = """const fs=require('node:fs');const x=JSON.parse(fs.readFileSync(0,'utf8'));
console.log(JSON.stringify(Buffer.from(x.data).subarray(x.start,x.start+32).toString('base64')));"""
        for array, start in (([float(byte) for byte in KEY], 0),
                             ([9, 7, *KEY, 5, 2], 2)):
            document = {"data": array, "start": start}
            recovered = base64.b64decode(self.node(script, document))
            self.assertEqual(AESGCM(recovered).decrypt(NONCE, SEALED, MESSAGE), PAYLOAD)
            self.blocked(self.scan(document, keys=True), "asset_key_exposure")
        # The lexical distinction disappears in real JSON consumers.
        raw = ('{"data":[' + ",".join(str(byte) + "e0" for byte in KEY) + '],"start":0}').encode()
        self.assertEqual(base64.b64decode(self.node(script, json.loads(raw))), KEY)
        self.blocked(self.scan(None, keys=True, encoded=raw), "asset_key_exposure")

    def test_mixed_hex_folding_and_base64_pad_bits_recover_the_known_key(self):
        encoded = base64.b64encode(KEY).decode()
        encoded_url = b64(KEY)
        cases = [
            ("".join(char.upper() if index % 2 else char for index, char in enumerate(KEY.hex())), "hex"),
            (" \t".join(KEY.hex()[i:i+4] for i in range(0, 64, 4)), "hex"),
            (encoded[:20] + "\r\n" + encoded[20:], "base64"),
            (encoded_url[:-1] + ALPHABET[ALPHABET.index(encoded_url[-1]) | 1], "base64"),
        ]
        for value, kind in cases:
            recovered = bytes.fromhex(value) if kind == "hex" else base64.b64decode(
                value + "=" * (-len(value) % 4), altchars=b"-_")
            self.assertEqual(AESGCM(recovered).decrypt(NONCE, SEALED, MESSAGE), PAYLOAD)
            self.blocked(self.scan(value, keys=True), "asset_key_exposure")

    @unittest.skipUnless(NODE, "Node.js required for real over-budget key recovery")
    def test_known_key_consumer_budget_never_silently_allows_ignored_byte_padding(self):
        encoded = base64.b64encode(KEY).decode()
        value = ("!" * 900).join(encoded)
        self.assertGreater(len(value), secrets._MAX_ASSET_KEY_TEXT_CHARS)
        script = """const fs=require('node:fs');const value=JSON.parse(fs.readFileSync(0,'utf8'));
console.log(JSON.stringify(Buffer.from(value,'base64').toString('base64')));"""
        recovered = base64.b64decode(self.node(script, value))
        self.assertEqual(AESGCM(recovered).decrypt(NONCE, SEALED, MESSAGE), PAYLOAD)
        with self.assertRaises(GuardError):
            secrets.scan_json_secrets({"encoded": value}, asset_keys=(KEY,))
        report = self.scan({"encoded": value}, keys=True)
        self.assertFalse(report["ok"])
        self.assertFalse(report["checks"]["structured_secret_scan_completed"])
        self.assertTrue(any(row["code"] == "structured_secret_unverifiable" for row in report["findings"]))
        # Padding already terminates a complete key: the remaining raw text
        # cannot change the consumer result and does not require inspection.
        self.blocked(self.scan(encoded + "!" * 40_000, keys=True), "asset_key_exposure")
        unrelated = base64.b64encode(b"ordinary public bytes" * 4000).decode()
        self.assertEqual(secrets.scan_json_secrets(unrelated, asset_keys=(KEY,)), [])

    def test_private_der_in_base64_hex_and_folded_strings_restores_signing_key(self):
        encoded = base64.b64encode(DER).decode()
        for value, kind in ((encoded, "base64"),
                            (encoded[:10] + "!" + encoded[10:], "base64"),
                            (DER.hex(), "hex"),
                            ("\n".join(DER.hex()[i:i+8].upper() for i in range(0, len(DER)*2, 8)), "hex")):
            raw = bytes.fromhex(value) if kind == "hex" else base64.b64decode(value)
            restored = serialization.load_der_private_key(raw, password=None)
            self.assertEqual(restored.sign(MESSAGE), ISSUER.sign(MESSAGE))
            report = self.scan({"untrusted-property-is-not-logged": value})
            self.blocked(report, "private_key_structure")
            self.assertNotIn("untrusted-property-is-not-logged", json.dumps(report))
            self.assertNotIn(value, json.dumps(report))

    def test_encoded_public_keys_and_unrelated_bytes_remain_accepted(self):
        public = {key: value for key, value in jwk().items() if key != "d"}
        unrelated = hashlib.sha256(b"owned nonsecret data").digest()
        document = {"jwk": public, "spki": [base64.b64encode(SPKI).decode(), SPKI.hex()],
                    "ordinary": [base64.b64encode(unrelated).decode(), unrelated.hex(), list(unrelated)]}
        self.assertTrue(self.scan(document, keys=True)["ok"])

    def test_encoded_der_checks_follow_private_switch_independently_of_known_keys(self):
        encoded = base64.b64encode(DER).decode()
        policy = {"version": 1, "check_private_keys": False, "check_source_maps": False}
        self.assertTrue(self.scan(encoded, keys=True, policy=policy)["ok"])
        self.blocked(self.scan({"key": list(KEY), "issuer": encoded}, keys=True, policy=policy),
                     "asset_key_exposure")

    def test_expanded_representations_inside_zip_asar_use_the_same_scan(self):
        value = jwk()
        value["d"] = value["d"][:12] + "\n" + value["d"][12:]
        contents = json.dumps({"keys": [value], "der": DER.hex()}).encode()
        wrapped = zip_archive("inner.data", asar([("secret.data", contents)]))
        report = self.scan(None, encoded=wrapped)
        self.blocked(report, "private_key_structure")
        self.assertTrue(any(row.get("archive_members") == ["inner.data", "secret.data"]
                            for row in report["findings"]))

    def test_der_candidate_count_is_shared_across_nested_strings_before_crypto(self):
        document = [DER.hex(), {"nested": [base64.b64encode(DER).decode(), DER.hex()]}]
        with patch.object(secrets, "MAX_JSON_DER_CANDIDATES", 2), patch.object(
            secrets, "scan_der_private_key", wraps=secrets.scan_der_private_key
        ) as decoder:
            with self.assertRaises(GuardError):
                secrets.scan_json_secrets(document)
            self.assertEqual(decoder.call_count, 2)
        with patch.object(secrets, "MAX_JSON_DER_CANDIDATES", 2):
            report = self.scan(document)
        self.assertFalse(report["ok"])
        self.assertFalse(report["checks"]["structured_secret_scan_completed"])

    def test_der_decoded_byte_budget_is_global_and_per_field_limit_is_explicit(self):
        for field, limit, document in (("MAX_JSON_DER_DECODED_BYTES", len(DER) * 2 - 1, [DER.hex()] * 2),
                                       ("MAX_DER_PRIVATE_KEY_BYTES", len(DER) - 1, DER.hex()),
                                       ("_MAX_ENCODED_DER_TEXT_CHARS", 64, DER.hex()),
                                       ("_MAX_ENCODED_DER_TEXT_CHARS", 64, "!" * 65 + base64.b64encode(DER).decode())):
            with self.subTest(field=field), patch.object(secrets, field, limit):
                report = self.scan(document)
            self.assertFalse(report["ok"])
            self.assertFalse(report["checks"]["structured_secret_scan_completed"])

    def test_large_unrelated_encoded_text_never_enters_private_key_decoder(self):
        document = {"image": base64.b64encode(b"\x30" + bytes(150_000)).decode(),
                    "other": (b"public binary data" * 10_000).hex()}
        with patch.object(secrets, "scan_der_private_key", side_effect=AssertionError("unexpected crypto decode")):
            self.assertEqual(secrets.scan_json_secrets(document), [])

    def test_jwk_folded_fields_still_have_raw_and_decoded_resource_limits(self):
        for value in ("A" * 12_000, " " * 40_000 + b64(ISSUER.private_bytes_raw())):
            report = self.scan({"kty": "OKP", "crv": "Ed25519", "d": value})
            self.assertFalse(report["ok"])
            self.assertFalse(report["checks"]["structured_secret_scan_completed"])

    def test_byte_windows_do_not_cross_nonbyte_values_or_nested_array_boundaries(self):
        for document in ([*KEY[:16], None, *KEY[16:]], [list(KEY[:16]), list(KEY[16:])],
                         [*KEY[:16], -1, *KEY[16:]], [str(byte) for byte in KEY]):
            self.assertEqual(secrets.scan_json_secrets(document, asset_keys=(KEY,)), [])
        with patch.object(secrets, "MAX_JSON_SECRET_NODES", 16):
            with self.assertRaises(GuardError):
                secrets.scan_json_secrets(list(KEY), asset_keys=(KEY,))


if __name__ == "__main__":
    unittest.main()
