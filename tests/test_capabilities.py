"""Real Ed25519 and durable SQLite tests for server-side capability admission."""

from __future__ import annotations

import base64
import copy
import hashlib
import os
import sqlite3
import stat
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard import capabilities
from releaseguard.capabilities import ReplayStore, consume_capability, issue_capability
from releaseguard.core import GuardError, canonical


class CapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.path = self.base / "replay.sqlite"
        self.store = ReplayStore.create(self.path)
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()
        self.now = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
        self.context = dict(subject="customer-001", audience="compute-server",
                            product="demo", operation="render", request=b"request\0owned-fixture")

    def issue(self, **changes) -> dict:
        return issue_capability(self.private, **{**self.context, "now": self.now, **changes})

    def consume(self, document, *, store=None, public=None, **changes) -> dict:
        return consume_capability(document, self.public if public is None else public,
                                  self.store if store is None else store,
                                  **{**self.context, "now": self.now, **changes})

    def signed(self, document: dict, **changes) -> dict:
        result = copy.deepcopy(document)
        result["claims"].update(changes)
        result["signature"] = base64.b64encode(self.private.sign(
            b"OpenReleaseGuard\0capability\0v1\0" + canonical(result["claims"])
        )).decode("ascii")
        return result

    def state(self, path=None) -> tuple[int, int]:
        with sqlite3.connect(str(self.path if path is None else path)) as connection:
            last_seen = connection.execute("SELECT last_seen FROM capability_state").fetchone()[0]
            count = connection.execute("SELECT COUNT(*) FROM capability_nonces").fetchone()[0]
        return last_seen, count

    def test_real_issue_consume_and_exact_public_claims(self) -> None:
        document = self.issue()
        self.assertEqual(set(document), {"format", "claims", "signature"})
        self.assertEqual(document["format"], "open-release-guard-capability/v1")
        claims = document["claims"]
        self.assertEqual(set(claims), {"version", "subject", "audience", "product", "operation",
                                     "jti", "request_sha256", "iat", "exp"})
        self.assertEqual(claims["request_sha256"], hashlib.sha256(self.context["request"]).hexdigest())
        self.assertRegex(claims["jti"], r"\A[0-9a-f]{64}\Z")
        self.assertEqual(claims["exp"] - claims["iat"], 60)
        self.public.verify(base64.b64decode(document["signature"]),
                           b"OpenReleaseGuard\0capability\0v1\0" + canonical(claims))
        before = copy.deepcopy(document)
        self.assertEqual(self.consume(document), claims)
        self.assertEqual(document, before)
        self.assertEqual(self.state(), (int(self.now.timestamp()), 1))

    def test_jti_is_fresh_random_32_bytes_each_time(self) -> None:
        identifiers = {self.issue()["claims"]["jti"] for _ in range(8)}
        self.assertEqual(len(identifiers), 8)
        self.assertTrue(all(len(bytes.fromhex(value)) == 32 for value in identifiers))

    def test_untrusted_signature_and_every_context_substitution_leave_token_unused(self) -> None:
        document = self.issue()
        for field, value in {"subject": "other", "audience": "other", "product": "other",
                             "operation": "other", "request": b"different"}.items():
            with self.subTest(field=field), self.assertRaises(GuardError):
                self.consume(document, **{field: value}, now=self.now + timedelta(seconds=100))
            self.assertEqual(self.state(), (0, 0))
        wrong_key = Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(GuardError):
            self.consume(document, public=wrong_key)
        self.assertEqual(self.state(), (0, 0))
        self.consume(document)

    def test_claim_tampering_fails_even_with_otherwise_valid_context(self) -> None:
        document = self.issue()
        for field, value in {"subject": "intruder", "jti": "0" * 64,
                             "request_sha256": "0" * 64, "exp": document["claims"]["exp"] + 1}.items():
            changed = copy.deepcopy(document)
            changed["claims"][field] = value
            with self.subTest(field=field), self.assertRaises(GuardError):
                self.consume(changed)
        self.assertEqual(self.state(), (0, 0))

    def test_signature_domain_is_independent_from_other_protocols(self) -> None:
        document = self.issue()
        for domain in (b"OpenReleaseGuard\0license\0v1\0", b"OpenReleaseGuard\0manifest\0v1\0", b""):
            changed = copy.deepcopy(document)
            changed["signature"] = base64.b64encode(
                self.private.sign(domain + canonical(changed["claims"]))
            ).decode("ascii")
            with self.subTest(domain=domain), self.assertRaises(GuardError):
                self.consume(changed)
        self.consume(document)

    def test_envelope_and_claim_schema_are_exact(self) -> None:
        document = self.issue()
        cases = [None, [], {}, {**document, "extra": 1},
                 {key: value for key, value in document.items() if key != "format"},
                 {**document, "format": 1}, {**document, "format": "other"},
                 {**document, "claims": []}, {**document, "claims": {**document["claims"], "extra": 1}}]
        missing_claim = copy.deepcopy(document)
        del missing_claim["claims"]["jti"]
        cases.append(missing_claim)
        for changed in cases:
            with self.subTest(kind=type(changed)), self.assertRaises(GuardError):
                self.consume(changed)
        self.assertEqual(self.state(), (0, 0))

    def test_claim_versions_timestamps_lifetimes_and_digests_are_strict(self) -> None:
        document = self.issue()
        issued = document["claims"]["iat"]
        cases = [dict(version=True), dict(version=1.0), dict(version=2),
                 dict(iat=True), dict(exp=float(issued + 60)), dict(iat=-1),
                 dict(exp=issued), dict(exp=issued + 301), dict(iat=10**100),
                 dict(jti="A" * 64), dict(jti="a" * 63), dict(request_sha256="a" * 63),
                 dict(request_sha256="a" * 64 + "\n")]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(GuardError):
                self.consume(self.signed(document, **changes))
        self.assertEqual(self.state(), (0, 0))

    def test_noncanonical_base64_signature_encodings_are_rejected(self) -> None:
        document = self.issue()
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        signature = document["signature"]
        # These low pad bits do not change decoded bytes; canonical re-encoding
        # must still reject the alternative textual representation.
        altered = signature[:-3] + alphabet[alphabet.index(signature[-3]) | 1] + "=="
        self.assertEqual(base64.b64decode(altered), base64.b64decode(signature))
        for encoded in [None, b"bytes", signature + "=", signature.rstrip("="),
                        "\n" + signature[1:], "!" * 88, altered, "é" * 88]:
            with self.subTest(type=type(encoded)), self.assertRaises(GuardError):
                self.consume({**document, "signature": encoded})
        self.consume(document)

    def test_identifiers_are_bounded_nfc_and_have_no_controls(self) -> None:
        bad_values = [None, True, "", " edge", "edge ", "line\nfeed", "zero\0byte",
                      "e\u0301", "zero\u200bwidth", "line\u2028break", "\ud800",
                      "a" * 129, "保" * 43]
        for field in ("subject", "audience", "product", "operation"):
            for value in bad_values:
                with self.subTest(field=field, type=type(value)), self.assertRaises(GuardError):
                    self.issue(**{field: value})
        document = self.issue(subject="保护用户")
        self.assertEqual(self.consume(document, subject="保护用户")["subject"], "保护用户")

    def test_request_type_size_and_empty_bytes(self) -> None:
        for request in [None, "text", bytearray(b"x"), b"x" * (capabilities.MAX_REQUEST_BYTES + 1)]:
            with self.subTest(type=type(request)), self.assertRaises(GuardError):
                self.issue(request=request)
        boundary = b"x" * capabilities.MAX_REQUEST_BYTES
        self.consume(self.issue(request=boundary), request=boundary)
        self.consume(self.issue(request=b""), request=b"")

    def test_ttl_bounds_bool_rejection_and_timezone_normalization(self) -> None:
        for ttl in [True, 0, -1, 301, 1.0, "60"]:
            with self.subTest(ttl=ttl), self.assertRaises(GuardError):
                self.issue(ttl_seconds=ttl)
        for ttl in [1, 300]:
            self.consume(self.issue(ttl_seconds=ttl))
        offset_now = self.now.astimezone(timezone(timedelta(hours=8)))
        self.assertEqual(self.issue(now=offset_now)["claims"]["iat"], int(self.now.timestamp()))
        for clock in [self.now.replace(tzinfo=None), "today", 1,
                      datetime(1969, 1, 1, tzinfo=timezone.utc)]:
            with self.subTest(clock=clock), self.assertRaises(GuardError):
                self.issue(now=clock)

    def test_expiry_is_exclusive_and_future_tokens_fail_before_store(self) -> None:
        document = self.issue(ttl_seconds=10)
        for clock in (self.now - timedelta(seconds=1), self.now + timedelta(seconds=10)):
            with self.subTest(clock=clock), self.assertRaises(GuardError):
                self.consume(document, now=clock)
            self.assertEqual(self.state(), (0, 0))
        self.consume(document, now=self.now + timedelta(seconds=9))

    def test_clock_is_resampled_inside_transaction_and_expiry_rechecked(self) -> None:
        document = self.issue(ttl_seconds=1)
        current = int(self.now.timestamp())
        with patch.object(capabilities, "_now_seconds", side_effect=[current, current + 1]) as clock, \
                self.assertRaisesRegex(GuardError, "expired"):
            self.consume(document, now=None)
        self.assertEqual(clock.call_count, 2)
        self.assertEqual(self.state(), (0, 0))
        self.consume(document)

    def test_replay_persists_across_store_reopen_and_rejects_repeat(self) -> None:
        document = self.issue()
        self.consume(document)
        reopened = ReplayStore(self.path)
        with self.assertRaisesRegex(GuardError, "replay"):
            self.consume(document, store=reopened)
        self.assertEqual(self.state()[1], 1)

    def test_namespace_uses_issuer_audience_jti_not_subject(self) -> None:
        with patch.object(capabilities.secrets, "token_hex", return_value="f" * 64):
            original = self.issue()
            other_subject = self.issue(subject="different-subject")
            other_audience = self.issue(audience="second-server")
            other_private = Ed25519PrivateKey.generate()
            other_issuer = issue_capability(other_private, **self.context, now=self.now)
        self.consume(original)
        self.consume(other_audience, audience="second-server")
        self.consume(other_issuer, public=other_private.public_key())
        with self.assertRaisesRegex(GuardError, "replay"):
            self.consume(other_subject, subject="different-subject")
        self.assertEqual(self.state()[1], 3)

    def test_concurrent_consumers_allow_exactly_one_admission(self) -> None:
        document = self.issue()
        barrier = threading.Barrier(8)

        def worker() -> bool:
            store = ReplayStore(self.path)
            barrier.wait(timeout=10)
            try:
                self.consume(document, store=store)
                return True
            except GuardError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: worker(), range(8)))
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 7)
        self.assertEqual(self.state()[1], 1)

    def test_capacity_fails_closed_without_evicting_live_nonce(self) -> None:
        path = self.base / "small.sqlite"
        store = ReplayStore.create(path, max_entries=1)
        original, second = self.issue(ttl_seconds=300), self.issue(ttl_seconds=300)
        self.consume(original, store=store)
        with self.assertRaisesRegex(GuardError, "capacity"):
            self.consume(second, store=store, now=self.now + timedelta(seconds=10))
        self.assertEqual(self.state(path), (int(self.now.timestamp()) + 10, 1))
        with self.assertRaisesRegex(GuardError, "replay"):
            self.consume(original, store=ReplayStore(path, max_entries=1), now=self.now + timedelta(seconds=10))

    def test_clock_rollback_is_rejected_after_expired_nonce_purge_and_reopen(self) -> None:
        path = self.base / "purge.sqlite"
        store = ReplayStore.create(path, max_entries=1)
        self.consume(self.issue(ttl_seconds=1), store=store)
        later = self.now + timedelta(seconds=2)
        self.consume(self.issue(now=later), store=store, now=later)
        self.assertEqual(self.state(path), (int(later.timestamp()), 1))
        earlier = self.now + timedelta(seconds=1)
        with self.assertRaisesRegex(GuardError, "rollback"):
            self.consume(self.issue(now=earlier), store=ReplayStore(path, max_entries=1), now=earlier)
        self.assertEqual(self.state(path), (int(later.timestamp()), 1))

    def test_replay_and_capacity_denials_preserve_observed_clock_floor(self) -> None:
        document = self.issue(ttl_seconds=300)
        self.consume(document)
        later = self.now + timedelta(seconds=20)
        with self.assertRaisesRegex(GuardError, "replay"):
            self.consume(document, now=later)
        with self.assertRaisesRegex(GuardError, "rollback"):
            self.consume(self.issue(), now=self.now + timedelta(seconds=10))
        self.assertEqual(self.state()[0], int(later.timestamp()))

    def test_create_is_exclusive_and_private_and_reopen_capacity_must_match(self) -> None:
        original = self.path.read_bytes()
        with self.assertRaises(GuardError):
            ReplayStore.create(self.path)
        self.assertEqual(self.path.read_bytes(), original)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        with self.assertRaises(GuardError):
            ReplayStore(self.path, max_entries=1)
        for maximum in [True, 0, -1, 1_000_001, "10000"]:
            with self.subTest(maximum=maximum), self.assertRaises(GuardError):
                ReplayStore.create(self.base / "invalid.sqlite", max_entries=maximum)

    def test_initialization_failure_removes_only_its_new_file(self) -> None:
        path = self.base / "failed.sqlite"
        with patch.object(ReplayStore, "_validate", side_effect=GuardError("test initialization failure")), \
                self.assertRaises(GuardError):
            ReplayStore.create(path)
        self.assertFalse(path.exists())
        self.assertFalse(Path(str(path) + "-journal").exists())
        existing = self.base / "existing.sqlite"
        existing.write_bytes(b"must remain unchanged")
        with self.assertRaises(GuardError):
            ReplayStore.create(existing)
        self.assertEqual(existing.read_bytes(), b"must remain unchanged")

    def test_missing_parent_and_stale_sidecar_do_not_create_a_store(self) -> None:
        path = self.base / "missing-parent" / "new.sqlite"
        with self.assertRaises(GuardError):
            ReplayStore.create(path)
        self.assertFalse(path.parent.exists())
        path = self.base / "stale.sqlite"
        journal = Path(str(path) + "-journal")
        journal.write_bytes(b"old unrelated journal")
        with self.assertRaises(GuardError):
            ReplayStore.create(path)
        self.assertFalse(path.exists())
        self.assertEqual(journal.read_bytes(), b"old unrelated journal")

    def test_missing_store_never_gets_recreated_in_constructor_or_consume(self) -> None:
        missing = self.base / "missing.sqlite"
        with self.assertRaises(GuardError):
            ReplayStore(missing)
        self.assertFalse(missing.exists())
        self.path.unlink()
        with self.assertRaises(GuardError):
            self.consume(self.issue())
        self.assertFalse(self.path.exists())

    def test_corrupt_store_and_wrong_marker_fail_closed(self) -> None:
        with sqlite3.connect(str(self.path)) as connection:
            connection.execute("PRAGMA application_id = 1")
        with self.assertRaises(GuardError):
            ReplayStore(self.path)
        with self.assertRaises(GuardError):
            self.consume(self.issue())
        self.path.write_bytes(b"not a SQLite database")
        with self.assertRaises(GuardError):
            ReplayStore(self.path)

    def test_every_extra_trigger_or_view_is_rejected_including_sqlite_like_prefix(self) -> None:
        with sqlite3.connect(str(self.path)) as connection:
            connection.execute("CREATE TRIGGER sqlitex_replay_escape AFTER INSERT ON capability_nonces "
                               "BEGIN DELETE FROM capability_nonces; END")
        with self.assertRaisesRegex(GuardError, "schema"):
            ReplayStore(self.path)
        with self.assertRaisesRegex(GuardError, "schema"):
            self.consume(self.issue())
        self.assertEqual(self.state(), (0, 0))

    def test_store_missing_extension_api_is_not_a_security_dependency(self) -> None:
        real_connect = sqlite3.connect

        class WithoutExtensions:
            def __init__(self, connection):
                self.connection = connection

            def __getattr__(self, name):
                if name == "enable_load_extension":
                    raise AttributeError(name)
                return getattr(self.connection, name)

        def connect(*args, **kwargs):
            return WithoutExtensions(real_connect(*args, **kwargs))

        with patch.object(capabilities.sqlite3, "connect", side_effect=connect):
            self.consume(self.issue(), store=ReplayStore(self.path))

    def test_sqlite_errors_are_guard_errors_and_do_not_consume(self) -> None:
        document = self.issue()
        with patch.object(capabilities.sqlite3, "connect", side_effect=sqlite3.OperationalError("test outage")), \
                self.assertRaises(GuardError):
            self.consume(document)
        self.assertEqual(self.state(), (0, 0))
        self.consume(document)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions and special files")
    def test_links_special_files_and_public_permissions_are_rejected(self) -> None:
        link = self.base / "link.sqlite"
        link.symlink_to(self.path)
        with self.assertRaises(GuardError):
            ReplayStore(link)
        with self.assertRaises(GuardError):
            ReplayStore.create(link)
        fifo = self.base / "pipe.sqlite"
        os.mkfifo(fifo)
        with self.assertRaises(GuardError):
            ReplayStore(fifo)
        self.path.chmod(0o644)
        with self.assertRaises(GuardError):
            ReplayStore(self.path)


if __name__ == "__main__":
    unittest.main()
