"""Real Argon2id round trips and fail-closed hostile verifier validation.

All password values below are synthetic, generated solely for these tests.
No application credential, private key or production password is embedded.
"""

from __future__ import annotations

import base64
import copy
import secrets
import unittest
from unittest.mock import patch

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from releaseguard import passwords
from releaseguard.core import GuardError


class PasswordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.password = secrets.token_bytes(32)
        cls.document = passwords.create_password_verifier(cls.password)

    def test_real_roundtrip_correct_wrong_and_empty_candidates(self) -> None:
        self.assertTrue(passwords.verify_password(self.password, self.document))
        wrong = bytes([self.password[0] ^ 1]) + self.password[1:]
        self.assertFalse(passwords.verify_password(wrong, self.document))
        self.assertFalse(passwords.verify_password(b"", self.document))

    def test_document_uses_standard_phc_and_fixed_rfc_profile(self) -> None:
        self.assertEqual(set(self.document), {"format", "phc"})
        self.assertEqual(self.document["format"], "open-release-guard-password/v1")
        fields = self.document["phc"].split("$")
        self.assertEqual(fields[:4], ["", "argon2id", "v=19", "m=65536,t=3,p=4"])
        self.assertEqual(len(base64.b64decode(fields[4] + "==", validate=True)), 16)
        self.assertEqual(len(base64.b64decode(fields[5] + "=", validate=True)), 32)
        # Interoperability is checked with the real dependency's PHC API too.
        Argon2id.verify_phc_encoded(self.password, self.document["phc"])

    def test_each_creation_uses_a_fresh_random_salt(self) -> None:
        other = passwords.create_password_verifier(self.password)
        self.assertNotEqual(self.document["phc"].split("$")[4], other["phc"].split("$")[4])
        self.assertNotEqual(self.document["phc"], other["phc"])
        self.assertTrue(passwords.verify_password(self.password, other))

    def test_real_creation_at_both_password_length_boundaries(self) -> None:
        for length in (12, 1024):
            with self.subTest(length=length):
                candidate = secrets.token_bytes(length)
                document = passwords.create_password_verifier(candidate)
                self.assertTrue(passwords.verify_password(candidate, document))

    def test_opaque_bytes_include_nul_without_truncation(self) -> None:
        candidate = secrets.token_bytes(12) + b"\0" + secrets.token_bytes(12)
        document = passwords.create_password_verifier(candidate)
        self.assertTrue(passwords.verify_password(candidate, document))
        self.assertFalse(passwords.verify_password(candidate.split(b"\0")[0], document))

    def test_external_fixed_profile_can_verify_an_empty_candidate(self) -> None:
        phc = Argon2id(
            salt=secrets.token_bytes(16), length=32, iterations=3,
            lanes=4, memory_cost=65536,
        ).derive_phc_encoded(b"")
        self.assertTrue(passwords.verify_password(b"", {"format": passwords.FORMAT, "phc": phc}))

    def test_invalid_password_types_and_lengths_never_enter_kdf(self) -> None:
        with patch.object(passwords, "Argon2id") as backend:
            for value in (None, "synthetic text", bytearray(12), memoryview(b""), 12, True):
                with self.subTest(value_type=type(value).__name__):
                    with self.assertRaises(GuardError):
                        passwords.create_password_verifier(value)
                    with self.assertRaises(GuardError):
                        passwords.verify_password(value, self.document)
            for length in (0, 1, 11, 1025):
                with self.subTest(create_length=length), self.assertRaises(GuardError):
                    passwords.create_password_verifier(b"x" * length)
            with self.assertRaises(GuardError):
                passwords.verify_password(b"x" * 1025, self.document)
            backend.assert_not_called()

    def test_exact_document_schema_is_required_before_kdf(self) -> None:
        invalid = [
            None, [], "not an object", {}, {"format": passwords.FORMAT},
            {"phc": self.document["phc"]}, {**self.document, "extra": True},
            {"format": "open-release-guard-password/v2", "phc": self.document["phc"]},
            {"format": True, "phc": self.document["phc"]},
            {"format": passwords.FORMAT, "phc": self.document["phc"].encode()},
            {"format": passwords.FORMAT, "phc": None},
        ]
        with patch.object(passwords, "Argon2id") as backend:
            for index, document in enumerate(invalid):
                with self.subTest(case=index), self.assertRaises(GuardError):
                    passwords.verify_password(self.password, document)
            backend.assert_not_called()

    def test_hostile_or_downgraded_phc_parameters_never_enter_kdf(self) -> None:
        original = self.document["phc"]
        malicious = [
            original.replace("m=65536", "m=4294967295"),
            original.replace("t=3", "t=4294967295"),
            original.replace("p=4", "p=4294967295"),
            original.replace("m=65536", "m=" + "9" * 10000),
            original.replace("m=65536", "m=8"),
            original.replace("m=65536", "m=-65536"),
            original.replace("m=65536", "m=065536"),
            original.replace("t=3", "t=0"), original.replace("t=3", "t=1"),
            original.replace("p=4", "p=0"), original.replace("p=4", "p=1"),
            original.replace("v=19", "v=16"),
            original.replace("argon2id", "argon2d"), original.replace("argon2id", "argon2i"),
            original.replace("m=65536,t=3,p=4", "t=3,m=65536,p=4"),
            original.replace("m=65536,t=3,p=4", "m=65536,t=3,p=4,keyid=1"),
            original + "\n", original + "$extra", "" , "x" * 10000,
        ]
        with patch.object(passwords, "Argon2id") as backend:
            for index, phc in enumerate(malicious):
                with self.subTest(case=index), self.assertRaises(GuardError):
                    passwords.verify_password(self.password, {"format": passwords.FORMAT, "phc": phc})
            backend.assert_not_called()

    def test_salt_and_hash_encoding_and_lengths_checked_before_kdf(self) -> None:
        fields = self.document["phc"].split("$")
        invalid: list[str] = []
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for index in (4, 5):
            original = fields[index]
            # Alter only unused trailing bits, leaving decoded bytes unchanged.
            noncanonical = original[:-1] + alphabet[alphabet.index(original[-1]) | 1]
            for value in (
                original[:-1], original + "A", original + "=", "!" + original[1:],
                "_" + original[1:], "中" + original[1:], noncanonical,
            ):
                changed = fields.copy()
                changed[index] = value
                invalid.append("$".join(changed))
        with patch.object(passwords, "Argon2id") as backend:
            for index, phc in enumerate(invalid):
                with self.subTest(case=index), self.assertRaises(GuardError):
                    passwords.verify_password(self.password, {"format": passwords.FORMAT, "phc": phc})
            backend.assert_not_called()

    def test_changed_salt_or_hash_is_a_real_mismatch(self) -> None:
        for index in (4, 5):
            fields = self.document["phc"].split("$")
            fields[index] = ("A" if fields[index][0] != "A" else "B") + fields[index][1:]
            document = {"format": passwords.FORMAT, "phc": "$".join(fields)}
            with self.subTest(changed_component=index):
                self.assertFalse(passwords.verify_password(self.password, document))

    def test_backend_receives_only_the_trusted_fixed_profile(self) -> None:
        candidate = secrets.token_bytes(24)
        with patch.object(passwords, "Argon2id", wraps=Argon2id) as backend:
            document = passwords.create_password_verifier(candidate)
            self.assertTrue(passwords.verify_password(candidate, document))
        self.assertEqual(backend.call_count, 2)
        for call in backend.call_args_list:
            kwargs = call.kwargs.copy()
            salt = kwargs.pop("salt")
            self.assertEqual(type(salt), bytes)
            self.assertEqual(len(salt), 16)
            self.assertEqual(kwargs, {"length": 32, "iterations": 3, "lanes": 4, "memory_cost": 65536})

    def test_unsupported_backend_fails_closed_without_fallback(self) -> None:
        for replacement in (None, UnsupportedAlgorithm("synthetic backend failure")):
            if replacement is None:
                context = patch.object(passwords, "Argon2id", None)
            else:
                context = patch.object(passwords, "Argon2id", side_effect=replacement)
            with context:
                with self.assertRaisesRegex(GuardError, "unavailable"):
                    passwords.create_password_verifier(self.password)
                with self.assertRaisesRegex(GuardError, "unavailable"):
                    passwords.verify_password(self.password, self.document)

    def test_backend_operation_failures_do_not_become_password_mismatches(self) -> None:
        for error in (UnsupportedAlgorithm("synthetic failure"), MemoryError("synthetic failure")):
            with patch.object(passwords, "Argon2id") as backend:
                backend.return_value.derive_phc_encoded.side_effect = error
                backend.return_value.verify.side_effect = error
                with self.assertRaises(GuardError):
                    passwords.create_password_verifier(self.password)
                with self.assertRaises(GuardError):
                    passwords.verify_password(self.password, self.document)

    def test_verification_does_not_mutate_the_document(self) -> None:
        before = copy.deepcopy(self.document)
        self.assertTrue(passwords.verify_password(self.password, self.document))
        self.assertEqual(self.document, before)

    def test_password_values_are_not_returned_or_echoed_in_errors(self) -> None:
        self.assertNotIn(self.password.hex(), repr(self.document))
        invalid = b"synthetic-private-candidate" * 64
        for operation in (
            lambda: passwords.create_password_verifier(invalid),
            lambda: passwords.verify_password(invalid, self.document),
        ):
            with self.assertRaises(GuardError) as caught:
                operation()
            self.assertNotIn("synthetic-private-candidate", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
