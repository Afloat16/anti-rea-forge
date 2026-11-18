"""Owned, recoverable key disclosures plus public-key compatibility controls."""

import base64
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa, x25519, x448
from cryptography.x509.oid import NameOID

from releaseguard.core import GuardError
from releaseguard.distribution import scan_release
from releaseguard.sealed import open_asset, seal_asset
from releaseguard.structured_secrets import (
    MAX_DER_PRIVATE_KEY_BYTES, MAX_JSON_SECRET_DEPTH, MAX_JSON_SECRET_NODES,
    scan_der_private_key, scan_json_secrets,
)
from tests.test_asar import asar, zip_archive


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def uint(value):
    return b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def escaped(value):
    return "".join("\\u%04x" % ord(character) for character in value)


class StructuredSecrets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.asset_key = bytes(range(32))
        cls.ed = ed25519.Ed25519PrivateKey.generate()
        cls.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.dsa = dsa.generate_private_key(key_size=1024)
        cls.ec = ec.generate_private_key(ec.SECP256R1())
        cls.pkcs8 = cls.ed.private_bytes(serialization.Encoding.DER,
                                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        cls.pem = cls.ed.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="structured secrets ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "public"
        self.root.mkdir()
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="ascii")
        self.key_file = self.work / "external.key"
        self.key_file.write_bytes(self.asset_key)

    def scan(self, data, *, name="data.bin", keys=False, policy=None):
        for previous in self.root.iterdir():
            previous.unlink()
        (self.root / name).write_bytes(data)
        self.policy.write_text(json.dumps(policy or {"version": 1}), encoding="ascii")
        return scan_release(self.root, self.policy,
                            asset_key_files=[self.key_file] if keys else [])

    def assert_private(self, report, code="private_key_structure"):
        self.assertFalse(report["ok"])
        self.assertTrue(any(finding["code"] == code for finding in report["findings"]), report["findings"])
        self.assertTrue(report["checks"]["structured_secret_scan_completed"])

    def assert_no_secret_report(self, report):
        raw = json.dumps(report).encode()
        for private in (self.asset_key, self.ed.private_bytes_raw()):
            for form in (private, private.hex().encode(), base64.b64encode(private), b64url(private).encode()):
                self.assertNotIn(form, raw)

    def test_escaped_known_key_is_recovered_and_release_rejected(self):
        sealed = seal_asset(b"owned secret data", self.asset_key, "fixture", "v1", "data", "one")
        representations = (
            self.asset_key.hex(), self.asset_key.hex().upper(),
            base64.b64encode(self.asset_key).decode(), b64url(self.asset_key),
        )
        for representation in representations:
            with self.subTest(length=len(representation)):
                data = ('{"nested":[{"value":"' + escaped(representation) + '"}]}').encode()
                decoded = json.loads(data)["nested"][0]["value"]
                self.assertEqual(decoded, representation)
                recovered = (bytes.fromhex(decoded) if len(decoded) == 64
                             else base64.urlsafe_b64decode(decoded + "=" * (-len(decoded) % 4)))
                self.assertEqual(open_asset(sealed, recovered, "fixture", "v1", "data", "one"),
                                 b"owned secret data")
                report = self.scan(data, keys=True)
                self.assert_private(report, "asset_key_exposure")
                self.assert_no_secret_report(report)

    def test_exact_byte_array_key_recovers_and_is_rejected(self):
        data = json.dumps({"nested": {"key": list(self.asset_key)}}).encode()
        self.assertEqual(bytes(json.loads(data)["nested"]["key"]), self.asset_key)
        report = self.scan(data, keys=True)
        self.assert_private(report, "asset_key_exposure")
        self.assertTrue(any(f.get("representation") == "json-byte-array" for f in report["findings"]))
        self.assert_no_secret_report(report)

    def test_decoded_raw_string_and_member_name_are_checked_without_recording_names(self):
        key = bytes(range(128, 160))
        for value in (key.decode("latin-1"), key.hex(), b64url(key)):
            document = {"outer": {value: "public"}}
            findings = scan_json_secrets(document, asset_keys=(key,))
            self.assertEqual([row["code"] for row in findings], ["asset_key_exposure"])
            self.assertNotIn(value, json.dumps(findings, ensure_ascii=False))

    def test_decoded_pem_recovers_a_signing_key_and_is_rejected(self):
        data = ('{"issuer":"' + escaped(self.pem) + '"}').encode()
        recovered = serialization.load_pem_private_key(json.loads(data)["issuer"].encode(), None)
        message = b"owned authorization check"
        self.ed.public_key().verify(recovered.sign(message), message)
        report = self.scan(data)
        self.assert_private(report, "private_key_marker")
        self.assert_no_secret_report(report)

    def test_valid_jwk_private_families_are_rejected_and_public_forms_pass(self):
        numbers = self.rsa.private_numbers()
        private_jwks = [{"kty": "RSA", "n": uint(numbers.public_numbers.n), "e": uint(numbers.public_numbers.e),
                         "d": uint(numbers.d), "p": uint(numbers.p), "q": uint(numbers.q),
                         "dp": uint(numbers.dmp1), "dq": uint(numbers.dmq1), "qi": uint(numbers.iqmp)}]
        for name, curve, width in (("P-256", ec.SECP256R1(), 32), ("P-384", ec.SECP384R1(), 48),
                                    ("P-521", ec.SECP521R1(), 66)):
            key = ec.generate_private_key(curve).private_numbers()
            private_jwks.append({"kty": "EC", "crv": name,
                                 "d": b64url(key.private_value.to_bytes(width, "big")),
                                 "x": b64url(key.public_numbers.x.to_bytes(width, "big")),
                                 "y": b64url(key.public_numbers.y.to_bytes(width, "big"))})
        for name, key in (("Ed25519", self.ed), ("Ed448", ed448.Ed448PrivateKey.generate()),
                          ("X25519", x25519.X25519PrivateKey.generate()),
                          ("X448", x448.X448PrivateKey.generate())):
            private_jwks.append({"kty": "OKP", "crv": name, "d": b64url(key.private_bytes_raw()),
                                 "x": b64url(key.public_key().public_bytes_raw())})
        private_jwks.append({"kty": "oct", "k": b64url(self.asset_key)})
        for jwk in private_jwks:
            with self.subTest(kind=jwk["kty"], curve=jwk.get("crv")):
                report = self.scan(json.dumps({"keys": [jwk]}).encode())
                self.assert_private(report)
                public = {key: value for key, value in jwk.items()
                          if key not in {"d", "p", "q", "dp", "dq", "qi", "k"}}
                self.assertTrue(self.scan(json.dumps({"keys": [public]}).encode())["ok"])

    def test_jwk_lookalikes_and_invalid_shapes_are_not_key_claims(self):
        valid = {"kty": "OKP", "crv": "Ed25519", "d": b64url(self.ed.private_bytes_raw()),
                 "x": b64url(self.ed.public_key().public_bytes_raw())}
        cases = [{"kty": "oct", "k": ""}, {"kty": "oct", "k": "a"},
                 {"kty": "oct", "k": "AA="}, {"kty": "oct", "k": "AB"},
                 {"kty": "RSA", "d": "AQAB"}, {"kty": "EC", "d": "AQAB"},
                 {**valid, "d": "AQAB"}, {**valid, "crv": "unknown"},
                 {**valid, "crv": []}, {**valid, "kty": []},
                 {"kty": "EC", "crv": "P-256", "d": b64url(bytes(32)),
                  "x": b64url(bytes(32)), "y": b64url(bytes(32))}]
        for document in cases:
            with self.subTest(document_kind=str(document.get("kty"))):
                self.assertEqual(scan_json_secrets(document), [])

    def test_padded_base64url_private_material_remains_recoverable(self):
        seed = self.ed.private_bytes_raw()
        jwk = {"kty": "OKP", "crv": "Ed25519", "d": base64.urlsafe_b64encode(seed).decode()}
        restored = ed25519.Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(jwk["d"]))
        self.assertEqual(restored.public_key().public_bytes_raw(), self.ed.public_key().public_bytes_raw())
        self.assertEqual(scan_json_secrets(jwk)[0]["kind"], "OKP")
        self.assertEqual(scan_json_secrets({"kty": "oct", "k": "AA=="})[0]["kind"], "oct")

    def test_missing_or_wrong_public_jwk_fields_do_not_hide_recoverable_private_material(self):
        seed = self.ed.private_bytes_raw()
        for extras in ({}, {"x": None}, {"x": "wrong public material"}):
            jwk = {"kty": "OKP", "crv": "Ed25519", "d": b64url(seed), **extras}
            recovered = ed25519.Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(jwk["d"] + "="))
            self.assertEqual(recovered.public_key().public_bytes_raw(), self.ed.public_key().public_bytes_raw())
            self.assertEqual(scan_json_secrets(jwk)[0]["kind"], "OKP")
        scalar = self.ec.private_numbers().private_value
        self.assertEqual(scan_json_secrets({"kty": "EC", "crv": "P-256",
                                           "d": b64url(scalar.to_bytes(32, "big"))})[0]["kind"], "EC")
        numbers = self.rsa.private_numbers()
        for field, factor in (("p", numbers.p), ("q", numbers.q)):
            jwk = {"kty": "RSA", "n": uint(numbers.public_numbers.n), "e": uint(numbers.public_numbers.e),
                   field: uint(factor)}
            self.assertEqual(scan_json_secrets(jwk)[0]["kind"], "RSA")

    def test_private_jwk_resource_limits_are_unverifiable_and_public_values_are_not_parsed(self):
        cases = [{"kty": "oct", "k": "a" * 12000},
                 {"kty": "RSA", "n": "a" * 4000, "e": "AQAB", "d": "AQ"},
                 {"kty": "OKP", "crv": "Ed25519", "d": "a" * 12000}]
        for document in cases:
            with self.subTest(kind=document["kty"]):
                with self.assertRaises(GuardError):
                    scan_json_secrets(document)
                report = self.scan(json.dumps(document).encode())
                self.assertFalse(report["ok"])
                self.assertFalse(report["checks"]["structured_secret_scan_completed"])
        self.assertEqual(scan_json_secrets({"kty": "RSA", "n": "a" * 4000, "e": "AQAB"}), [])

    def test_rsa_factor_pair_without_modulus_recovers_original_signing_key_and_is_rejected(self):
        numbers = self.rsa.private_numbers()
        jwk = {"kty": "RSA", "e": uint(numbers.public_numbers.e), "p": uint(numbers.p), "q": uint(numbers.q)}
        decoded = {name: int.from_bytes(base64.urlsafe_b64decode(jwk[name] + "=" * (-len(jwk[name]) % 4)), "big")
                   for name in ("e", "p", "q")}
        e, p, q = (decoded[name] for name in ("e", "p", "q"))
        d = pow(e, -1, (p - 1) * (q - 1))
        restored = rsa.RSAPrivateNumbers(p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q),
                                         rsa.rsa_crt_iqmp(p, q), rsa.RSAPublicNumbers(e, p * q)).private_key()
        message = b"owned partial JWK recovery proof"
        signature = restored.sign(message, padding.PKCS1v15(), hashes.SHA256())
        self.rsa.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual(signature, self.rsa.sign(message, padding.PKCS1v15(), hashes.SHA256()))
        self.assert_private(self.scan(json.dumps(jwk).encode()))
        # The pair remains disclosed even if the public fields are absent or
        # incorrect; the scanner never performs the reconstruction above.
        for public in ({}, {"n": "wrong", "e": "wrong"}):
            partial = {"kty": "RSA", "p": jwk["p"], "q": jwk["q"], **public}
            self.assertEqual(scan_json_secrets(partial)[0]["kind"], "RSA")

    def test_rsa_factor_pair_limits_and_nonkey_lookalikes(self):
        numbers = self.rsa.private_numbers()
        p, q = uint(numbers.p), uint(numbers.q)
        for values in (("AQ", "Aw"), (p, p), (uint(numbers.p - 1), q), (None, q), ([], q)):
            self.assertEqual(scan_json_secrets({"kty": "RSA", "p": values[0], "q": values[1]}), [])
        for field in ("p", "q", "d"):
            data = {"kty": "RSA", "p": p, "q": q, field: "a" * 3000}
            with self.assertRaises(GuardError):
                scan_json_secrets(data)
            report = self.scan(json.dumps(data).encode())
            self.assertFalse(report["ok"])
            self.assertFalse(report["checks"]["structured_secret_scan_completed"])

    def test_duplicate_findings_are_bounded_and_multiple_configured_keys_keep_indices(self):
        other = bytes(range(32, 64))
        document = {"a": [self.asset_key.hex()] * 50, "b": [list(other), b64url(other)]}
        findings = scan_json_secrets(document, asset_keys=(self.asset_key, other))
        self.assertEqual(len(findings), 2)
        self.assertEqual({row["rule_index"] for row in findings}, {0, 1})

    def test_array_comparisons_require_32_plain_bytes_and_do_not_strip_raw_equals(self):
        lookalikes = [list(self.asset_key[:-1]), list(self.asset_key) + [0],
                      [False, *self.asset_key[1:]], [0.0, *self.asset_key[1:]],
                      [256, *self.asset_key[1:]], [str(item) for item in self.asset_key]]
        for value in lookalikes:
            self.assertEqual(scan_json_secrets({"value": value}, asset_keys=(self.asset_key,)), [])
        self.assertEqual(scan_json_secrets({"value": "ordinary"}, asset_keys=(b"=" * 32,)), [])

    def test_private_optout_does_not_disable_configured_key_checks(self):
        data = ('{"asset":"' + escaped(self.asset_key.hex()) + '","issuer":"' + escaped(self.pem) + '"}').encode()
        policy = {"version": 1, "check_private_keys": False, "check_source_maps": False}
        report = self.scan(data, keys=True, policy=policy)
        self.assert_private(report, "asset_key_exposure")
        self.assertFalse(any(row["code"].startswith("private_key") for row in report["findings"]))
        self.assertTrue(report["checks"]["structured_secrets_checked"])
        self.assertFalse(report["checks"]["der_private_keys_checked"])

    def test_private_json_checks_still_run_when_map_checks_are_disabled(self):
        data = ('{"issuer":"' + escaped(self.pem) + '"}').encode()
        self.assert_private(self.scan(data, policy={"version": 1, "check_source_maps": False}),
                            "private_key_marker")

    def test_json_unicode_encodings_arrays_and_xssi_are_decoded_by_shared_scanner(self):
        text = '[{"secret":"' + escaped(self.asset_key.hex()) + '"}]'
        for encoding in ("utf-8", "utf-16", "utf-16-be", "utf-32", "utf-32-be"):
            for prefix in ("", ")]}'\n"):
                with self.subTest(encoding=encoding, prefix=bool(prefix)):
                    self.assert_private(self.scan((prefix + text).encode(encoding), keys=True),
                                        "asset_key_exposure")

    def test_json_ambiguity_and_budget_failure_cannot_pass_as_no_secret(self):
        for data in (b'{"a":0,"a":1}', b'{"a":1e400}',
                     b'{"a":"' + b"x" * (8 * 1024 * 1024) + b'"}'):
            with self.subTest(size=len(data)):
                report = self.scan(data, policy={"version": 1, "check_source_maps": False})
                self.assertFalse(report["ok"])
                self.assertFalse(report["checks"]["structured_secret_scan_completed"])
                self.assertTrue(any(row["code"] == "structured_secret_unverifiable" for row in report["findings"]))

    def test_direct_json_depth_nodes_cycles_and_configuration_are_bounded(self):
        too_deep = "public"
        for _ in range(MAX_JSON_SECRET_DEPTH + 1):
            too_deep = [too_deep]
        cycle = []
        cycle.append(cycle)
        for document in (too_deep, cycle, [None] * MAX_JSON_SECRET_NODES,
                         {"object": object()}, {1: "not JSON"}):
            with self.assertRaises(GuardError):
                scan_json_secrets(document)
        for kwargs in ({"asset_keys": [self.asset_key]}, {"asset_keys": (b"short",)},
                       {"asset_keys": (self.asset_key,) * 17}, {"check_private_keys": 1}):
            with self.assertRaises(GuardError):
                scan_json_secrets({}, **kwargs)

    def test_pkcs8_and_traditional_der_private_keys_recover_and_are_rejected(self):
        keys = [self.ed, self.rsa, self.dsa, self.ec, ed448.Ed448PrivateKey.generate(),
                x25519.X25519PrivateKey.generate(), x448.X448PrivateKey.generate()]
        for key in keys:
            formats = [serialization.PrivateFormat.PKCS8]
            if isinstance(key, (rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey)):
                formats.append(serialization.PrivateFormat.TraditionalOpenSSL)
            for form in formats:
                with self.subTest(kind=type(key).__name__, form=str(form)):
                    data = key.private_bytes(serialization.Encoding.DER, form, serialization.NoEncryption())
                    recovered = serialization.load_der_private_key(data, None)
                    self.assertEqual(key.public_key().public_bytes(serialization.Encoding.DER,
                                     serialization.PublicFormat.SubjectPublicKeyInfo),
                                     recovered.public_key().public_bytes(serialization.Encoding.DER,
                                     serialization.PublicFormat.SubjectPublicKeyInfo))
                    self.assert_private(self.scan(data))

    def test_public_der_keys_and_certificate_never_enter_private_decoder(self):
        data = [key.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
                for key in (self.ed, self.rsa, self.ec, self.dsa)]
        data.append(self.rsa.public_key().public_bytes(serialization.Encoding.DER,
                                                      serialization.PublicFormat.PKCS1))
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "owned fixture")])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(self.ed.public_key()).serial_number(1)
                       .not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(self.ed, None))
        data.append(certificate.public_bytes(serialization.Encoding.DER))
        with patch("releaseguard.structured_secrets.serialization.load_der_private_key",
                   side_effect=AssertionError("public data entered private decoder")):
            for blob in data:
                with self.subTest(size=len(blob)):
                    self.assertTrue(self.scan(blob)["ok"])

    def test_pkcs8_unknown_algorithm_and_length_changes_are_unverifiable(self):
        unknown = self.pkcs8.replace(bytes.fromhex("06032b6570"), bytes.fromhex("06032b657f"))
        self.assertNotEqual(unknown, self.pkcs8)
        for data in (unknown, self.pkcs8[:-1], self.pkcs8 + b"tail"):
            with self.subTest(size=len(data)):
                report = self.scan(data)
                self.assertFalse(report["ok"])
                self.assertFalse(report["checks"]["structured_secret_scan_completed"])
                self.assertTrue(any(row["code"] == "structured_secret_unverifiable" for row in report["findings"]))

    def test_large_der_candidate_and_unrelated_binary_use_only_prefix_budget(self):
        class CountingStream(io.BytesIO):
            def __init__(self, data):
                super().__init__(data)
                self.reads = []

            def read(self, count=-1):
                self.reads.append(count)
                return super().read(count)

        size = MAX_DER_PRIVATE_KEY_BYTES + 16
        body = self.pkcs8[2:] + bytes(size - 5 - len(self.pkcs8[2:]))
        candidate = b"\x30\x83" + len(body).to_bytes(3, "big") + body
        self.assertEqual(len(candidate), size)
        for data, expected in ((candidate, True), (b"ordinary" + bytes(size), False)):
            stream = CountingStream(data)
            with patch("releaseguard.structured_secrets.serialization.load_der_private_key",
                       side_effect=AssertionError("over-budget input entered decoder")):
                findings = scan_der_private_key(stream, len(data))
            self.assertEqual(bool(findings), expected)
            self.assertEqual(stream.reads, [128])
            if expected:
                self.assertEqual(findings[0]["reason"], "der_byte_limit")

    def test_der_size_input_and_changing_reads_are_rejected_without_key_values(self):
        for size in (-1, True, "48"):
            with self.assertRaises(GuardError):
                scan_der_private_key(io.BytesIO(self.pkcs8), size)
        with self.assertRaises(GuardError):
            scan_der_private_key(io.BytesIO(self.pkcs8), len(self.pkcs8) + 1)

    def test_nested_zip_asar_keys_use_the_same_json_and_der_checks(self):
        encoded = ('{"key":"' + escaped(self.asset_key.hex()) + '"}').encode()
        archive = asar([("config/settings.json", encoded), ("assets/issuer.bin", self.pkcs8)])
        report = self.scan(zip_archive("resources.asar", archive), name="application.zip", keys=True)
        self.assert_private(report)
        self.assert_private(report, "asset_key_exposure")
        self.assertTrue(any(row.get("archive_members") == ["resources.asar", "config/settings.json"]
                            and row["code"] == "asset_key_exposure" for row in report["findings"]))
        self.assertTrue(any(row.get("archive_members") == ["resources.asar", "assets/issuer.bin"]
                            and row["code"] == "private_key_structure" for row in report["findings"]))
        self.assert_no_secret_report(report)

    def test_cli_rejects_decoded_secret_with_exit_three_and_blinded_report(self):
        data = ('{"secret":"' + escaped(self.asset_key.hex()) + '"}').encode()
        (self.root / "configuration.json").write_bytes(data)
        result = subprocess.run([sys.executable, "-I", "-m", "releaseguard", "scan-release",
                                 "--root", str(self.root), "--policy", str(self.policy),
                                 "--asset-key-file", str(self.key_file)],
                                cwd=self.work, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertEqual(result.stderr, b"")
        report = json.loads(result.stdout)
        self.assert_private(report, "asset_key_exposure")
        self.assert_no_secret_report(report)


if __name__ == "__main__":
    unittest.main()
