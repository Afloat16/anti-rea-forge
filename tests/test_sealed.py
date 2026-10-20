"""Real AEAD, strict envelopes and external-key file boundary checks."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from releaseguard import core, sealed


class SealedTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.key = secrets.token_bytes(32)
        self.plaintext = b"\x00synthetic private asset\xff\n"
        self.context = {
            "product": "demo", "release": "1.2.3",
            "purpose": "model-weights", "asset_id": "models/speech.bin",
        }

    def seal(self, plaintext: bytes | None = None, **context) -> dict:
        return sealed.seal_asset(
            self.plaintext if plaintext is None else plaintext,
            self.key, **{**self.context, **context},
        )

    def open(self, document: dict, **context) -> bytes:
        return sealed.open_asset(document, self.key, **{**self.context, **context})

    def test_real_binary_roundtrip_and_exact_envelope(self) -> None:
        plaintext = bytes(range(256)) + self.plaintext
        document = self.seal(plaintext)
        self.assertEqual(set(document), {"format", "salt", "nonce", "ciphertext"})
        self.assertEqual(document["format"], sealed.SEALED_FORMAT)
        self.assertTrue(all(type(value) is str for value in document.values()))
        self.assertEqual(len(base64.b64decode(document["salt"])), 32)
        self.assertEqual(len(base64.b64decode(document["nonce"])), 12)
        self.assertEqual(len(base64.b64decode(document["ciphertext"])), len(plaintext) + 16)
        self.assertEqual(self.open(document), plaintext)
        self.assertNotIn("synthetic private asset", json.dumps(document))
        self.assertNotIn("asset_id", document)

    def test_empty_asset_has_only_authenticated_tag(self) -> None:
        document = self.seal(b"")
        self.assertEqual(len(base64.b64decode(document["ciphertext"])), 16)
        self.assertEqual(self.open(document), b"")

    def test_maximum_asset_roundtrips_through_core_json(self) -> None:
        plaintext = b"\xff" * sealed.MAX_ASSET_BYTES
        document = self.seal(plaintext)
        raw = core.canonical(document)
        self.assertLess(len(raw), core.MAX_DOCUMENT_BYTES)
        self.assertEqual(self.open(core.parse_json(raw)), plaintext)
        path = self.base / "asset.json"
        core.save_document(path, document)
        self.assertEqual(self.open(core.read_document(path)), plaintext)

    def test_oversized_plaintext_is_rejected_before_encryption(self) -> None:
        with patch.object(sealed, "AESGCM", side_effect=AssertionError("Must not encrypt")):
            with self.assertRaises(core.GuardError):
                self.seal(b"x" * (sealed.MAX_ASSET_BYTES + 1))

    def test_plaintext_requires_exact_bytes(self) -> None:
        class Bytes(bytes):
            pass
        for value in [None, "secret", 1, True, bytearray(b"secret"), memoryview(b"secret"), Bytes(b"secret")]:
            with self.subTest(kind=type(value).__name__), self.assertRaises(core.GuardError):
                sealed.seal_asset(value, self.key, **self.context)

    def test_key_requires_exactly_32_bytes_for_both_operations(self) -> None:
        document = self.seal()
        for value in [None, "k" * 32, 32, True, bytearray(32), memoryview(bytes(32)), b"", bytes(31), bytes(33)]:
            for operation in [
                lambda: sealed.seal_asset(self.plaintext, value, **self.context),
                lambda: sealed.open_asset(document, value, **self.context),
            ]:
                with self.subTest(kind=type(value).__name__), self.assertRaises(core.GuardError):
                    operation()

    def test_repeated_packages_have_fresh_salts_nonces_and_ciphertexts(self) -> None:
        documents = [self.seal() for _ in range(32)]
        for field in ["salt", "nonce", "ciphertext"]:
            self.assertEqual(len({item[field] for item in documents}), len(documents))
        for document in documents:
            self.assertEqual(self.open(document), self.plaintext)

    def test_wire_format_opens_with_independently_constructed_pyca_context(self) -> None:
        document = self.seal()
        # This is the specified v1 wire contract, not a call to sealed internals.
        domain = b"OpenReleaseGuard\x00sealed-asset\x00v1\x00"
        context = {"format": "open-release-guard-sealed-asset/v1", **self.context}
        canonical = json.dumps(context, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        aad = domain + b"AAD\x00" + canonical
        package_key = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=base64.b64decode(document["salt"]),
            info=domain + b"HKDF-SHA256/AES-256-GCM\x00" + aad,
        ).derive(self.key)
        plaintext = AESGCM(package_key).decrypt(
            base64.b64decode(document["nonce"]),
            base64.b64decode(document["ciphertext"]), aad,
        )
        self.assertEqual(plaintext, self.plaintext)

    def test_wrong_master_key_and_tampering_share_authentication_error(self) -> None:
        document = self.seal()
        wrong_key = bytes([self.key[0] ^ 1]) + self.key[1:]
        failures = [lambda: sealed.open_asset(document, wrong_key, **self.context)]
        for field in ["salt", "nonce", "ciphertext"]:
            changed = dict(document)
            raw = bytearray(base64.b64decode(changed[field]))
            raw[-1] ^= 1
            changed[field] = base64.b64encode(raw).decode("ascii")
            failures.append(lambda changed=changed: self.open(changed))
        for failure in failures:
            with self.assertRaisesRegex(core.GuardError, "^Cannot authenticate sealed asset$"):
                failure()

    def test_ciphertext_body_and_tag_mutations_return_no_plaintext(self) -> None:
        document = self.seal()
        original = base64.b64decode(document["ciphertext"])
        mutations = [original[:-1], original + b"x"]
        for index in [0, len(original) - 16, len(original) - 1]:
            raw = bytearray(original)
            raw[index] ^= 0x80
            mutations.append(bytes(raw))
        for raw in mutations:
            changed = {**document, "ciphertext": base64.b64encode(raw).decode("ascii")}
            with self.subTest(length=len(raw)), self.assertRaises(core.GuardError):
                self.open(changed)

    def test_each_trusted_context_field_is_bound(self) -> None:
        document = self.seal()
        for field in self.context:
            with self.subTest(field=field), self.assertRaisesRegex(core.GuardError, "^Cannot authenticate sealed asset$"):
                self.open(document, **{field: "other"})

    def test_whole_packages_cannot_be_swapped_between_asset_ids(self) -> None:
        first = self.seal(b"first asset", asset_id="first")
        second = self.seal(b"second asset", asset_id="second")
        self.assertEqual(self.open(first, asset_id="first"), b"first asset")
        self.assertEqual(self.open(second, asset_id="second"), b"second asset")
        for document, asset_id in [(first, "second"), (second, "first")]:
            with self.assertRaises(core.GuardError):
                self.open(document, asset_id=asset_id)

    def test_context_encoding_is_unambiguous_and_case_sensitive(self) -> None:
        document = self.seal(product="ab", release="c", purpose="weights", asset_id="data")
        for context in [
            {"product": "a", "release": "bc", "purpose": "weights", "asset_id": "data"},
            {"product": "ab", "release": "c", "purpose": "data", "asset_id": "weights"},
            {"product": "AB", "release": "c", "purpose": "weights", "asset_id": "data"},
        ]:
            with self.assertRaises(core.GuardError):
                self.open(document, **context)

    def test_nfc_international_identifiers_and_visible_interior_spaces(self) -> None:
        context = {"product": "产品 café", "release": "2026.10", "purpose": "模型权重", "asset_id": "数据/🧭.bin"}
        self.assertEqual(self.open(self.seal(**context), **context), self.plaintext)
        maximum = {field: "x" * 128 for field in self.context}
        self.assertEqual(self.open(self.seal(**maximum), **maximum), self.plaintext)

    def test_invalid_context_types_sizes_and_special_unicode(self) -> None:
        class Text(str):
            pass
        invalid = [None, 1, False, b"name", [], Text("name"), "", " ", " name", "name ", "x" * 129,
                   "cafe\u0301", "a\x00b", "a\nb", "a\tb", "a\x7fb", "a\u0085b",
                   "a\u200bb", "a\u202eb", "a\u2066b", "a\ufeffb", "a\u2028b", "a\u2029b",
                   "a\u00a0b", "a\u3000b", "a\ud800b", "a\udfffb", "a\ufffeb", "a\U0010ffffb"]
        document = self.seal()
        for field in self.context:
            for value in invalid:
                for operation in [lambda: self.seal(**{field: value}), lambda: self.open(document, **{field: value})]:
                    with self.subTest(field=field, kind=type(value).__name__), self.assertRaises(core.GuardError):
                        operation()

    def test_envelope_requires_exact_fields_and_plain_dict(self) -> None:
        class Document(dict):
            pass
        document = self.seal()
        invalid = [None, [], True, Document(document)]
        invalid += [{key: value for key, value in document.items() if key != field} for field in document]
        for field in ["algorithm", "key", "product", "release", "purpose", "asset_id", "version"]:
            invalid.append({**document, field: "untrusted"})
        for value in invalid:
            with self.subTest(kind=type(value).__name__), self.assertRaises(core.GuardError):
                self.open(value)

    def test_unknown_format_and_non_string_envelope_values(self) -> None:
        document = self.seal()
        for value in ["other/v1", "open-release-guard-sealed-asset/v2", None, 1, True, []]:
            with self.assertRaises(core.GuardError):
                self.open({**document, "format": value})
        for field in ["salt", "nonce", "ciphertext"]:
            for value in [None, 1, True, [], document[field].encode("ascii")]:
                with self.subTest(field=field), self.assertRaises(core.GuardError):
                    self.open({**document, field: value})

    def test_base64_requires_canonical_standard_alphabet_and_padding(self) -> None:
        document = self.seal(b"x")
        for field in ["salt", "nonce", "ciphertext"]:
            original = document[field]
            for value in ["", "*", "é", original + "=", original + "\n", " " + original, "_" + original[1:]]:
                with self.subTest(field=field), self.assertRaises(core.GuardError):
                    self.open({**document, field: value})
            if original.endswith("="):
                with self.assertRaises(core.GuardError):
                    self.open({**document, field: original.rstrip("=")})
                alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                index = len(original.rstrip("=")) - 1
                alternative = original[:index] + alphabet[alphabet.index(original[index]) ^ 1] + original[index + 1:]
                self.assertEqual(base64.b64decode(original), base64.b64decode(alternative))
                with self.assertRaises(core.GuardError):
                    self.open({**document, field: alternative})

    def test_decoded_lengths_are_bounded(self) -> None:
        document = self.seal()
        cases = {"salt": [0, 31, 33], "nonce": [0, 11, 13],
                 "ciphertext": [0, 15, sealed.MAX_ASSET_BYTES + 17]}
        for field, lengths in cases.items():
            for length in lengths:
                value = base64.b64encode(bytes(length)).decode("ascii")
                with self.subTest(field=field, length=length), self.assertRaises(core.GuardError):
                    self.open({**document, field: value})

    def test_encoded_limits_are_checked_before_base64_allocation(self) -> None:
        document = self.seal()
        for field, maximum in [("salt", 32), ("nonce", 12), ("ciphertext", sealed.MAX_ASSET_BYTES + 16)]:
            oversized = "A" * (4 * ((maximum + 2) // 3) + 1)
            changed = {**document, field: oversized}
            # Earlier legitimate fields may still be decoded, so guard only the
            # hostile value rather than prohibiting every decoder call.
            original = sealed.base64.b64decode
            def bounded(value, *args, **kwargs):
                if len(value) == len(oversized):
                    raise AssertionError("Oversized Base64 must not be decoded")
                return original(value, *args, **kwargs)
            with patch.object(sealed.base64, "b64decode", bounded), self.assertRaises(core.GuardError):
                self.open(changed)

    def test_duplicate_json_fields_use_strict_core_reader(self) -> None:
        raw = core.canonical(self.seal())
        duplicate = b'{"format":"untrusted",' + raw[1:]
        with self.assertRaises(core.GuardError):
            core.parse_json(duplicate)

    def test_errors_do_not_echo_key_plaintext_or_attacker_values(self) -> None:
        document = self.seal()
        marker = "private-attacker-controlled-value"
        for operation in [
            lambda: self.open({**document, "salt": marker}),
            lambda: self.open(document, product=marker),
            lambda: sealed.open_asset(document, secrets.token_bytes(32), **self.context),
        ]:
            with self.assertRaises(core.GuardError) as failure:
                operation()
            message = str(failure.exception)
            for forbidden in [marker, self.key.hex(), base64.b64encode(self.key).decode("ascii"), "synthetic private asset"]:
                self.assertNotIn(forbidden, message)

    def test_generate_and_load_raw_external_keys(self) -> None:
        keys = []
        for name in ["first.key", "second.key"]:
            path = self.base / name
            self.assertIsNone(sealed.generate_asset_key(path))
            raw = path.read_bytes()
            self.assertEqual(len(raw), 32)
            self.assertEqual(sealed.load_asset_key(str(path)), raw)
            keys.append(raw)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)
        self.assertNotEqual(*keys)

    def test_key_creation_never_overwrites_existing_files(self) -> None:
        path = self.base / "existing.key"
        path.write_bytes(b"existing external key")
        with self.assertRaises(core.GuardError):
            sealed.generate_asset_key(path)
        self.assertEqual(path.read_bytes(), b"existing external key")

    def test_key_loader_rejects_short_long_and_large_files_without_reading(self) -> None:
        for length in [0, 1, 31, 33, 16 * 1024 * 1024]:
            path = self.base / f"invalid-{length}.key"
            with path.open("wb") as handle:
                handle.truncate(length)
            with patch.object(sealed.os, "read", side_effect=AssertionError("Invalid-size key must not be read")):
                with self.subTest(length=length), self.assertRaises(core.GuardError):
                    sealed.load_asset_key(path)

    def test_key_loader_rejects_directories_and_missing_paths(self) -> None:
        for path in [self.base, self.base / "missing.key"]:
            with self.assertRaises(core.GuardError):
                sealed.load_asset_key(path)

    def test_key_paths_require_path_or_plain_string(self) -> None:
        for value in [None, 1, True, b"path.key", "", "invalid\x00key"]:
            for operation in [sealed.generate_asset_key, sealed.load_asset_key]:
                with self.subTest(operation=operation.__name__), self.assertRaises(core.GuardError):
                    operation(value)

    def symlink(self, target: Path, link: Path, *, directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (OSError, NotImplementedError):
            self.skipTest("Creating symlinks is unavailable")

    def test_key_loader_and_creator_reject_final_symlinks(self) -> None:
        target = self.base / "real.key"
        target.write_bytes(self.key)
        link = self.base / "link.key"
        self.symlink(target, link)
        for operation in [sealed.load_asset_key, sealed.generate_asset_key]:
            with self.assertRaises(core.GuardError):
                operation(link)
        self.assertEqual(target.read_bytes(), self.key)
        broken = self.base / "broken.key"
        self.symlink(self.base / "nonexistent", broken)
        with self.assertRaises(core.GuardError):
            sealed.load_asset_key(broken)

    def test_key_loader_rejects_symlink_ancestor(self) -> None:
        directory = self.base / "real"
        directory.mkdir()
        (directory / "master.key").write_bytes(self.key)
        alias = self.base / "alias"
        self.symlink(directory, alias, directory=True)
        with self.assertRaises(core.GuardError):
            sealed.load_asset_key(alias / "master.key")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Named pipes are unavailable")
    def test_key_loader_rejects_fifo_without_blocking(self) -> None:
        path = self.base / "pipe.key"
        os.mkfifo(path)
        with self.assertRaises(core.GuardError):
            sealed.load_asset_key(path)

    def test_key_loader_rejects_replacement_between_stat_and_open(self) -> None:
        path = self.base / "race.key"
        replacement = self.base / "replacement.key"
        path.write_bytes(self.key)
        replacement.write_bytes(secrets.token_bytes(32))
        original = sealed.os.open
        replaced = False
        def replace_before_open(name, flags, *args, **kwargs):
            nonlocal replaced
            if Path(name).name == path.name and not replaced:
                os.replace(replacement, path)
                replaced = True
            return original(name, flags, *args, **kwargs)
        with patch.object(sealed.os, "open", replace_before_open), self.assertRaises(core.GuardError):
            sealed.load_asset_key(path)
        self.assertTrue(replaced)

    def test_key_loader_accepts_same_file_with_different_cross_api_ctime(self) -> None:
        path = self.base / "windows-ctime.key"
        path.write_bytes(self.key)
        original = sealed.os.fstat
        def fstat_with_windows_time(descriptor):
            info = original(descriptor)
            return SimpleNamespace(
                st_dev=info.st_dev, st_ino=info.st_ino, st_mode=info.st_mode,
                st_size=info.st_size, st_mtime_ns=info.st_mtime_ns,
                st_ctime_ns=info.st_ctime_ns + 1_000_000_000,
                st_file_attributes=getattr(info, "st_file_attributes", 0),
            )
        with patch.object(sealed.os, "fstat", fstat_with_windows_time):
            self.assertEqual(sealed.load_asset_key(path), self.key)

    def test_key_loader_rejects_change_between_two_fstat_calls(self) -> None:
        path = self.base / "changing-descriptor.key"
        path.write_bytes(self.key)
        original = sealed.os.fstat
        calls = 0
        def changing_fstat(descriptor):
            nonlocal calls
            info = original(descriptor)
            calls += 1
            return SimpleNamespace(
                st_dev=info.st_dev, st_ino=info.st_ino, st_mode=info.st_mode,
                st_size=info.st_size, st_mtime_ns=info.st_mtime_ns,
                st_ctime_ns=info.st_ctime_ns + calls * 1_000_000_000,
                st_file_attributes=getattr(info, "st_file_attributes", 0),
            )
        with patch.object(sealed.os, "fstat", changing_fstat), self.assertRaises(core.GuardError):
            sealed.load_asset_key(path)
        self.assertEqual(calls, 2)

    def test_key_loader_rejects_in_place_mutation_during_read(self) -> None:
        path = self.base / "mutating.key"
        path.write_bytes(self.key)
        original = sealed.os.read
        changed = False
        def mutate_during_read(descriptor, maximum):
            nonlocal changed
            self.assertLessEqual(maximum, 33)
            data = original(descriptor, maximum)
            if not changed:
                info = path.stat()
                path.write_bytes(secrets.token_bytes(32))
                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000_000))
                changed = True
            return data
        with patch.object(sealed.os, "read", mutate_during_read), self.assertRaises(core.GuardError):
            sealed.load_asset_key(path)
        self.assertTrue(changed)

    def test_key_loader_rejects_path_replacement_after_open(self) -> None:
        path = self.base / "replaced.key"
        replacement = self.base / "new.key"
        path.write_bytes(self.key)
        replacement.write_bytes(secrets.token_bytes(32))
        original = sealed.os.read
        changed = False
        def replace_during_read(descriptor, maximum):
            nonlocal changed
            data = original(descriptor, maximum)
            if not changed:
                try:
                    os.replace(replacement, path)
                except PermissionError:
                    self.skipTest("Platform denies replacing an open file")
                changed = True
            return data
        with patch.object(sealed.os, "read", replace_during_read), self.assertRaises(core.GuardError):
            sealed.load_asset_key(path)
        self.assertTrue(changed)

    def test_key_file_errors_do_not_echo_sensitive_path(self) -> None:
        marker = "sensitive-key-location"
        with self.assertRaises(core.GuardError) as failure:
            sealed.load_asset_key(self.base / marker)
        self.assertNotIn(marker, str(failure.exception))


if __name__ == "__main__":
    unittest.main()
