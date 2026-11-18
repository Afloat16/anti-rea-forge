"""Owned PEM wrappers, real key recovery, and bounded publication decisions."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from releaseguard import structured_secrets as secrets
from releaseguard.core import GuardError
from releaseguard.distribution import scan_release
from tests.test_asar import asar, zip_archive


ISSUER = Ed25519PrivateKey.from_private_bytes(bytes(range(255, 223, -1)))
PEM = ISSUER.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
DER = ISSUER.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
MESSAGE = b"owned encoded PEM recovery proof"
NODE = shutil.which("node")


class EncodedPemTests(unittest.TestCase):
    def assert_private(self, value, representation):
        report = secrets.scan_json_secrets({"privateSigningKey": value})
        self.assertIn({"code": "private_key_marker", "representation": representation,
                       "rule_index": 0}, report)
        encoded = json.dumps(report).encode()
        for material in (PEM, PEM.hex().encode(), base64.b64encode(PEM),
                         hashlib.sha256(PEM).hexdigest().encode(), b"privateSigningKey"):
            self.assertNotIn(material, encoded)

    def test_standard_decoders_recover_valid_signatures_for_hex_and_base64(self):
        for prefix in (b"", b"\n", b"\n\n", b"Owned build notes\n" * 40):
            for encoding in ("hex", "base64"):
                raw = prefix + PEM
                value = raw.hex() if encoding == "hex" else base64.b64encode(raw).decode()
                recovered = bytes.fromhex(value) if encoding == "hex" else base64.b64decode(value)
                key = serialization.load_pem_private_key(recovered, password=None)
                ISSUER.public_key().verify(key.sign(MESSAGE), MESSAGE)
                self.assert_private(value, "json-" + encoding + "-pem")

    def test_encoded_markers_in_json_keys_and_all_pem_labels_are_inspected(self):
        for index, marker in enumerate(secrets.PEM_PRIVATE_KEY_MARKERS):
            # Marker evidence is intentionally not a private-key validity claim.
            for encoding in ("hex", "base64"):
                raw = marker.encode()
                value = raw.hex() if encoding == "hex" else base64.b64encode(raw).decode()
                report = secrets.scan_json_secrets({value: "public"})
                self.assertIn({"code": "private_key_marker", "rule_index": index,
                               "representation": "json-" + encoding + "-pem"}, report)

    @unittest.skipUnless(NODE, "Node.js is required for tolerant Base64 consumer controls")
    def test_real_node_recovers_folding_noise_and_utf16_aliases(self):
        text = base64.b64encode(PEM).decode()
        variants = (text[:12] + "\r\n !\0" + text[12:], text.rstrip("="),
                    text + "=ignored-trailing-data", "\ud800" + text,
                    "".join(chr(ord(char) + 256) for char in text),
                    "".join(chr(0x10000 + ord(char)) for char in text))
        program = """const fs=require('node:fs'),c=require('node:crypto');
const raw=Buffer.from(JSON.parse(fs.readFileSync(0,'utf8')),'base64');
console.log(JSON.stringify(c.sign(null,Buffer.from('owned encoded PEM recovery proof'),
c.createPrivateKey(raw)).toString('base64')));"""
        for value in variants:
            result = subprocess.run([NODE, "-e", program], input=json.dumps(value),
                                    text=True, capture_output=True, timeout=15, check=True)
            self.assertEqual(result.stderr, "")
            ISSUER.public_key().verify(base64.b64decode(json.loads(result.stdout)), MESSAGE)
            self.assert_private(value, "json-base64-pem")

    def test_hint_chunk_boundaries_and_byte_alignments_preserve_detection(self):
        for width in (1, 2, 7, 31, 64):
            with patch.object(secrets, "_PEM_HINT_CHARS", width):
                for prefix_length in range(6):
                    raw = b"x" * prefix_length + PEM
                    self.assert_private(base64.b64encode(raw).decode(), "json-base64-pem")
                    text = raw.hex().upper()
                    self.assert_private(" \n".join(text[i:i + 2] for i in range(0, len(text), 2)),
                                        "json-hex-pem")

    def test_public_pem_certificate_and_large_unrelated_data_are_allowed(self):
        public = ISSUER.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "owned.example")])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(ISSUER.public_key()).serial_number(1)
                       .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                       .sign(ISSUER, None).public_bytes(serialization.Encoding.PEM))
        document = [encoded for data in (public, certificate, b"public binary data" * 30_000)
                    for encoded in (data.hex(), base64.b64encode(data).decode())]
        with patch.object(secrets, "scan_der_private_key", side_effect=AssertionError("private parser invoked")):
            self.assertEqual(secrets.scan_json_secrets(document), [])

    def test_der_and_pem_share_candidate_and_decoded_byte_budgets(self):
        values = [base64.b64encode(PEM).decode(), DER.hex(), PEM.hex()]
        with patch.object(secrets, "MAX_JSON_DER_CANDIDATES", 2):
            with self.assertRaisesRegex(GuardError, "JSON decode budget"):
                secrets.scan_json_secrets(values)
        with patch.object(secrets, "MAX_JSON_DER_DECODED_BYTES", len(PEM) + len(DER) - 1):
            with self.assertRaisesRegex(GuardError, "JSON decode budget"):
                secrets.scan_json_secrets(values[:2])

    def test_large_leading_text_and_ignored_prefix_cannot_postpone_inspection(self):
        for data in (b"public notes\n" * 24_000 + PEM, PEM + b"public notes\n" * 24_000):
            for value in (data.hex(), base64.b64encode(data).decode()):
                with self.assertRaisesRegex(GuardError, "raw text limit"):
                    secrets.scan_json_secrets(value)
        with patch.object(secrets, "MAX_DER_PRIVATE_KEY_BYTES", len(PEM) - 1):
            with self.assertRaisesRegex(GuardError, "decoded byte limit"):
                secrets.scan_json_secrets(base64.b64encode(PEM).decode())
        with patch.object(secrets, "MAX_DOCUMENT_BYTES", 32):
            with self.assertRaisesRegex(GuardError, "JSON text limit"):
                secrets.scan_json_secrets(base64.b64encode(PEM).decode())

    def test_padding_terminates_consumer_stream_and_hints_require_decoded_marker(self):
        # The later PEM text is ignored by Node's Base64 consumer, not leaked.
        self.assertEqual(secrets.scan_json_secrets("cHVibGlj=" + base64.b64encode(PEM).decode()), [])
        hint = secrets._PEM_BASE64_HINTS[1].decode()
        # A partial bit-alignment hint is not a full decoded marker.
        self.assertEqual(secrets.scan_json_secrets(hint), [])
        with self.assertRaisesRegex(GuardError, "invalid outer encoding"):
            secrets.scan_json_secrets(PEM.hex() + "not-hex")

    def test_false_hints_consume_the_actual_candidate_and_decoded_byte_budgets(self):
        hint = secrets._PEM_BASE64_HINTS[1].decode()
        self.assertEqual(secrets.scan_json_secrets(hint), [])
        with patch.object(secrets, "MAX_JSON_DER_CANDIDATES", 1):
            with self.assertRaisesRegex(GuardError, "JSON decode budget"):
                secrets.scan_json_secrets([hint, hint])
        with patch.object(secrets, "MAX_JSON_DER_DECODED_BYTES", 1):
            with self.assertRaisesRegex(GuardError, "JSON decode budget"):
                secrets.scan_json_secrets(hint)

    def test_nested_archives_wide_json_and_policy_switch_use_same_inspection(self):
        with tempfile.TemporaryDirectory(prefix="owned-pem-") as directory:
            work = Path(directory)
            root = work / "public"
            root.mkdir()
            policy = work / "policy.json"
            policy.write_text('{"version":1}', encoding="ascii")
            for encoding in ("utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
                raw = json.dumps({"key": base64.b64encode(PEM).decode()}).encode(encoding)
                artifact = zip_archive("inner.data", asar([("settings.data", raw)]))
                path = root / "payload.data"
                path.write_bytes(artifact)
                report = scan_release(root, policy)
                self.assertFalse(report["ok"])
                self.assertTrue(report["checks"]["structured_secret_scan_completed"])
                self.assertTrue(any(row.get("representation") == "json-base64-pem"
                                    and row.get("archive_members") == ["inner.data", "settings.data"]
                                    for row in report["findings"]))
                self.assertEqual(path.read_bytes(), artifact)
            policy.write_text('{"version":1,"check_private_keys":false}', encoding="ascii")
            self.assertTrue(scan_release(root, policy)["ok"])

    def test_budget_rejection_has_incomplete_state_separate_from_positive_findings(self):
        with tempfile.TemporaryDirectory(prefix="owned-pem-budget-") as directory:
            work = Path(directory)
            root = work / "public"
            root.mkdir()
            (root / "settings.json").write_text(json.dumps({"key": PEM.hex()}), encoding="ascii")
            policy = work / "policy.json"
            policy.write_text('{"version":1}', encoding="ascii")
            with patch.object(secrets, "MAX_DER_PRIVATE_KEY_BYTES", len(PEM) - 1):
                report = scan_release(root, policy)
            self.assertFalse(report["ok"])
            self.assertFalse(report["checks"]["structured_secret_scan_completed"])
            self.assertTrue(any(row["code"] == "structured_secret_unverifiable" for row in report["findings"]))


if __name__ == "__main__":
    unittest.main()
