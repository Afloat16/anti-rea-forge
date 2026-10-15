"""Exercise signed release and license policies with fresh, temporary keys."""

from __future__ import annotations

import base64
import copy
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard import core


class CoreTests(unittest.TestCase):
    def test_oversized_replacement_is_rejected_before_hashing(self) -> None:
        document = self.manifest()
        path = self.release / "demo.exe"
        with path.open("r+b") as handle:
            handle.truncate(16 * 1024 * 1024)
        with patch.object(core.hashlib, "sha256", side_effect=AssertionError("Must not hash oversized replacement")):
            with self.assertRaisesRegex(core.GuardError, "size differs"):
                self.verify_manifest(document)

    def test_directory_inventory_is_bounded(self) -> None:
        with patch.object(core, "MAX_ENTRIES", 2):
            with self.assertRaisesRegex(core.GuardError, "Too many release files and directories"):
                self.manifest()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.release = self.base / "release"
        self.release.mkdir()
        (self.release / "demo.exe").write_bytes(b"MZ\x00example executable\r\n")
        (self.release / "plugins").mkdir()
        (self.release / "plugins" / "engine.dll").write_bytes(b"MZ\x00example library\r\n")
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()
        self.now = datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc)

    def manifest(self) -> dict:
        return core.create_manifest(self.release, "demo", "1.2.3", self.private)

    def license(self) -> dict:
        return core.issue_license(
            "demo", "customer-001", 30, ["basic", "export"],
            self.private, now=self.now,
        )

    def body(self, document: dict, kind: str) -> dict:
        return copy.deepcopy(core.verify_document(document, kind, self.public))

    def signed_raw(self, raw: bytes, kind: str = "manifest") -> dict:
        # Deliberately construct hostile documents using a genuine valid signature.
        signature = self.private.sign(
            b"OpenReleaseGuard\x00" + kind.encode("ascii") + b"\x00v1\x00" + raw
        )
        return {
            "format": core.ENVELOPE,
            "kind": kind,
            "payload": base64.b64encode(raw).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
        }

    def verify_manifest(self, document: dict, **kwargs) -> dict:
        return core.verify_manifest(
            document, self.release, self.public, kwargs.pop("product", "demo"),
            kwargs.pop("release", "1.2.3"), **kwargs,
        )

    def verify_license(self, document: dict, **kwargs) -> dict:
        return core.verify_license(
            document, self.public, kwargs.pop("product", "demo"),
            now=kwargs.pop("now", self.now), **kwargs,
        )

    def test_real_ed25519_manifest_roundtrip(self) -> None:
        document = self.manifest()
        destination = self.base / "manifest.json"
        core.save_document(destination, document)
        body = self.verify_manifest(core.read_document(destination))
        self.assertEqual(body["product"], "demo")
        self.assertEqual(body["release"], "1.2.3")
        self.assertEqual(
            [record["path"] for record in body["files"]],
            ["demo.exe", "plugins/engine.dll"],
        )
        self.assertEqual(len(base64.b64decode(document["signature"])), 64)

    def test_real_ed25519_license_roundtrip(self) -> None:
        document = self.license()
        destination = self.base / "license.json"
        core.save_document(destination, document)
        body = self.verify_license(
            core.read_document(destination), subject="customer-001",
            required_features=["export"], now=self.now + timedelta(days=10),
        )
        self.assertEqual(body["features"], ["basic", "export"])
        self.assertEqual(body["subject"], "customer-001")

    def test_single_byte_modification_is_rejected(self) -> None:
        document = self.manifest()
        path = self.release / "demo.exe"
        original = path.read_bytes()
        path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        with self.assertRaises(core.GuardError):
            self.verify_manifest(document)

    def test_deleted_file_is_rejected(self) -> None:
        document = self.manifest()
        (self.release / "plugins" / "engine.dll").unlink()
        with self.assertRaises(core.GuardError):
            self.verify_manifest(document)

    def test_extra_dll_is_rejected(self) -> None:
        document = self.manifest()
        (self.release / "injected.dll").write_bytes(b"untrusted")
        with self.assertRaises(core.GuardError):
            self.verify_manifest(document)

    def test_wrong_public_key_is_rejected_for_both_document_types(self) -> None:
        other = Ed25519PrivateKey.generate().public_key()
        for kind, document in [("manifest", self.manifest()), ("license", self.license())]:
            with self.subTest(kind=kind), self.assertRaises(core.GuardError):
                core.verify_document(document, kind, other)

    def test_manifest_product_and_release_must_match(self) -> None:
        document = self.manifest()
        for expected in [{"product": "other"}, {"release": "9.9.9"}]:
            with self.subTest(expected=expected), self.assertRaises(core.GuardError):
                self.verify_manifest(document, **expected)

    def test_license_product_and_subject_must_match(self) -> None:
        document = self.license()
        for expected in [{"product": "other"}, {"subject": "customer-002"}]:
            with self.subTest(expected=expected), self.assertRaises(core.GuardError):
                self.verify_license(document, **expected)

    def test_invalid_signature_lengths_are_rejected(self) -> None:
        for length in [0, 1, 63, 65, 128]:
            document = self.manifest()
            document["signature"] = base64.b64encode(bytes(length)).decode("ascii")
            with self.subTest(length=length), self.assertRaises(core.GuardError):
                self.verify_manifest(document)

    def test_modified_payload_is_rejected(self) -> None:
        document = self.manifest()
        body = self.body(document, "manifest")
        body["release"] = "malicious"
        document["payload"] = base64.b64encode(core.canonical(body)).decode("ascii")
        with self.assertRaises(core.GuardError):
            self.verify_manifest(document)

    def test_modified_signature_is_rejected(self) -> None:
        document = self.manifest()
        signature = base64.b64decode(document["signature"])
        document["signature"] = base64.b64encode(
            bytes([signature[0] ^ 1]) + signature[1:]
        ).decode("ascii")
        with self.assertRaises(core.GuardError):
            self.verify_manifest(document)

    def test_manifest_and_license_signature_domains_are_separated(self) -> None:
        body = self.body(self.manifest(), "manifest")
        document = core.sign_document("license", body, self.private)
        with self.assertRaises(core.GuardError):
            self.verify_manifest(document)
        document["kind"] = "manifest"
        with self.assertRaises(core.GuardError):
            self.verify_manifest(document)

    def test_duplicate_envelope_json_fields_are_rejected(self) -> None:
        with self.assertRaises(core.GuardError):
            core.parse_json(b'{"kind":"manifest","kind":"license"}')

    def test_validly_signed_duplicate_payload_fields_are_rejected(self) -> None:
        raw = core.canonical(self.body(self.manifest(), "manifest"))
        duplicate = b'{"version":1,' + raw[1:]
        document = self.signed_raw(duplicate)
        with self.assertRaises(core.GuardError):
            self.verify_manifest(document)

    def test_valid_signature_requires_canonical_json(self) -> None:
        raw = b" " + core.canonical(self.body(self.manifest(), "manifest"))
        with self.assertRaises(core.GuardError):
            self.verify_manifest(self.signed_raw(raw))

    def test_unknown_envelope_and_schema_fields_are_rejected(self) -> None:
        document = self.manifest()
        document["public_key"] = "untrusted key"
        with self.assertRaises(core.GuardError):
            self.verify_manifest(document)
        for kind, original in [("manifest", self.manifest()), ("license", self.license())]:
            body = self.body(original, kind)
            body["future_field"] = "unexpected"
            document = core.sign_document(kind, body, self.private)
            with self.subTest(kind=kind), self.assertRaises(core.GuardError):
                if kind == "manifest":
                    self.verify_manifest(document)
                else:
                    self.verify_license(document)
        body = self.body(self.manifest(), "manifest")
        body["files"][0]["untrusted"] = True
        with self.assertRaises(core.GuardError):
            self.verify_manifest(core.sign_document("manifest", body, self.private))

    def test_bool_is_not_accepted_as_schema_version(self) -> None:
        for kind, original in [("manifest", self.manifest()), ("license", self.license())]:
            body = self.body(original, kind)
            body["version"] = True
            document = core.sign_document(kind, body, self.private)
            with self.subTest(kind=kind), self.assertRaises(core.GuardError):
                if kind == "manifest":
                    self.verify_manifest(document)
                else:
                    self.verify_license(document)

    def test_validly_signed_unsafe_paths_are_rejected(self) -> None:
        original = self.body(self.manifest(), "manifest")
        unsafe = [
            "/absolute.dll", "../escape.dll", "a/../escape.dll", "C:/absolute.dll",
            "engine.dll:stream", "plugins\\engine.dll", "CON.dll", "LPT1",
            "NUL.txt", "CONIN$", "CONOUT$.txt", "NUL .txt", "COM1 .txt",
            "trailing.", "trailing ", "double//slash", ".", "",
        ]
        for name in unsafe:
            body = copy.deepcopy(original)
            body["files"][0]["path"] = name
            document = core.sign_document("manifest", body, self.private)
            with self.subTest(path=name), self.assertRaises(core.GuardError):
                self.verify_manifest(document)

    def test_validly_signed_case_collisions_are_rejected(self) -> None:
        body = self.body(self.manifest(), "manifest")
        duplicate = copy.deepcopy(body["files"][0])
        duplicate["path"] = duplicate["path"].upper()
        body["files"].append(duplicate)
        with self.assertRaises(core.GuardError):
            self.verify_manifest(core.sign_document("manifest", body, self.private))

    def test_actual_case_collisions_are_rejected(self) -> None:
        upper = self.release / "DEMO.EXE"
        try:
            with upper.open("xb") as handle:
                handle.write(b"collision")
        except FileExistsError:
            self.skipTest("Filesystem is case-insensitive")
        with self.assertRaises(core.GuardError):
            self.manifest()

    def make_symlink(self, target: Path, link: Path, *, directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"Symlinks unavailable: {exc}")

    def test_file_symlink_is_rejected_during_signing_and_verification(self) -> None:
        document = self.manifest()
        target = self.base / "outside.dll"
        target.write_bytes(b"outside release")
        self.make_symlink(target, self.release / "linked.dll")
        with self.assertRaises(core.GuardError):
            self.manifest()
        with self.assertRaises(core.GuardError):
            self.verify_manifest(document)

    def test_directory_and_root_symlinks_are_rejected(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        self.make_symlink(outside, self.release / "linked", directory=True)
        with self.assertRaises(core.GuardError):
            self.manifest()
        root_link = self.base / "release-link"
        self.make_symlink(self.release, root_link, directory=True)
        with self.assertRaises(core.GuardError):
            core.create_manifest(root_link, "demo", "1.2.3", self.private)

    def test_empty_release_and_empty_signed_manifest_are_rejected(self) -> None:
        empty = self.base / "empty"
        empty.mkdir()
        with self.assertRaises(core.GuardError):
            core.create_manifest(empty, "demo", "1.2.3", self.private)
        body = self.body(self.manifest(), "manifest")
        body["files"] = []
        with self.assertRaises(core.GuardError):
            core.verify_manifest(
                core.sign_document("manifest", body, self.private), empty,
                self.public, "demo", "1.2.3",
            )

    def test_expired_and_not_yet_valid_licenses_are_rejected(self) -> None:
        document = self.license()
        for current in [self.now - timedelta(seconds=1), self.now + timedelta(days=30)]:
            with self.subTest(now=current), self.assertRaises(core.GuardError):
                self.verify_license(document, now=current)

    def test_missing_license_features_are_rejected(self) -> None:
        with self.assertRaises(core.GuardError):
            self.verify_license(self.license(), required_features=["enterprise"])

    def test_issue_rejects_bare_string_and_bytes_features(self) -> None:
        for features in ["export", b"export"]:
            with self.subTest(features=features), self.assertRaises(core.GuardError):
                core.issue_license("demo", "customer-001", 30, features, self.private,
                                   now=self.now)

    def test_verify_rejects_bare_string_and_bytes_required_features(self) -> None:
        # The character grants must never satisfy a caller's intended "export" grant.
        document = core.issue_license(
            "demo", "customer-001", 30, ["e", "o", "p", "r", "t", "x"],
            self.private, now=self.now,
        )
        for required in ["export", b"export"]:
            with self.subTest(required=required), self.assertRaises(core.GuardError):
                self.verify_license(document, required_features=required)

    def test_feature_iterators_are_bounded_while_collecting(self) -> None:
        document = self.license()
        for operation in ["issue", "verify"]:
            consumed = []

            def unbounded_features():
                for index in range(1000):
                    consumed.append(index)
                    if index > 128:
                        self.fail("Feature collector consumed beyond its limit")
                    yield f"feature_{index}"

            with self.subTest(operation=operation), self.assertRaises(core.GuardError):
                if operation == "issue":
                    core.issue_license(
                        "demo", "customer-001", 30, unbounded_features(),
                        self.private, now=self.now,
                    )
                else:
                    self.verify_license(document, required_features=unbounded_features())
            self.assertEqual(len(consumed), 129)

    def test_128_feature_iterator_can_be_issued_and_verified(self) -> None:
        features = [f"feature_{index}" for index in range(128)]
        document = core.issue_license(
            "demo", "customer-001", 30, iter(features), self.private, now=self.now,
        )
        body = self.verify_license(document, required_features=iter(features))
        self.assertEqual(set(body["features"]), set(features))

    def test_encrypted_key_roundtrip_and_wrong_password(self) -> None:
        private_path = self.base / "issuer-private.pem"
        public_path = self.base / "issuer-public.pem"
        password = b"temporary-test-passphrase"
        identifier = core.generate_keys(private_path, public_path, password)
        self.assertIn(b"ENCRYPTED PRIVATE KEY", private_path.read_bytes())
        private = core.load_private_key(private_path, password)
        public = core.load_public_key(public_path)
        self.assertEqual(identifier, core.key_id(public))
        self.assertEqual(identifier, core.key_id(private.public_key()))
        signature = private.sign(b"roundtrip proof")
        public.verify(signature, b"roundtrip proof")
        with self.assertRaises(core.GuardError):
            core.load_private_key(private_path, b"wrong-passphrase")
        if os.name == "posix":
            self.assertEqual(private_path.stat().st_mode & 0o777, 0o600)

    def test_non_ed25519_public_and_private_keys_are_rejected(self) -> None:
        private = ec.generate_private_key(ec.SECP256R1())
        public_path = self.base / "other-public.pem"
        public_path.write_bytes(private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        with self.assertRaises(core.GuardError):
            core.load_public_key(public_path)
        password = b"temporary-test-passphrase"
        private_path = self.base / "other-private.pem"
        private_path.write_bytes(private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        ))
        with self.assertRaises(core.GuardError):
            core.load_private_key(private_path, password)

    def test_document_and_key_writes_never_overwrite_existing_files(self) -> None:
        existing = self.base / "existing"
        existing.write_bytes(b"keep this exact content")
        with self.assertRaises(FileExistsError):
            core.write_new(existing, b"replacement")
        with self.assertRaises(FileExistsError):
            core.save_document(existing, self.manifest())
        with self.assertRaises(FileExistsError):
            core.generate_keys(existing, self.base / "new-public.pem", b"long-passphrase")
        self.assertEqual(existing.read_bytes(), b"keep this exact content")
        self.assertFalse((self.base / "new-public.pem").exists())

    def test_keygen_public_collision_preserves_original_and_cleans_new_private(self) -> None:
        private_path = self.base / "new-private.pem"
        public_path = self.base / "existing-public.pem"
        public_path.write_bytes(b"original public file")
        with self.assertRaises(FileExistsError):
            core.generate_keys(private_path, public_path, b"long-passphrase")
        self.assertEqual(public_path.read_bytes(), b"original public file")
        self.assertFalse(private_path.exists())

    def test_keygen_failure_does_not_delete_preexisting_private_key(self) -> None:
        private_path = self.base / "existing-private.pem"
        public_path = self.base / "public.pem"
        private_path.write_bytes(b"irreplaceable original")
        with patch.object(core, "write_new", side_effect=FileExistsError("exists")):
            with self.assertRaises(FileExistsError):
                core.generate_keys(private_path, public_path, b"long-passphrase")
        self.assertEqual(private_path.read_bytes(), b"irreplaceable original")

    def test_keygen_rejects_same_path_and_short_passphrase_without_writes(self) -> None:
        destination = self.base / "key.pem"
        with self.assertRaises(core.GuardError):
            core.generate_keys(destination, destination, b"long-passphrase")
        with self.assertRaises(core.GuardError):
            core.generate_keys(destination, self.base / "public.pem", b"short")
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
