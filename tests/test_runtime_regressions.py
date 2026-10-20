"""Independent adversarial regressions for the v0.4 replay authority."""

from __future__ import annotations

import concurrent.futures
import copy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard.capabilities import ReplayStore, consume_capability, issue_capability
from releaseguard.core import GuardError


class RuntimeRegressions(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="runtime-regression-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()
        self.now = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
        self.context = dict(subject="customer", audience="trusted-server", product="demo",
                            operation="export", request=b"exact immutable request")

    def issue(self, *, now=None, ttl=60):
        return issue_capability(self.private, **self.context,
                                now=self.now if now is None else now, ttl_seconds=ttl)

    def consume(self, document, store, *, now=None, **changes):
        context = dict(self.context, **changes)
        return consume_capability(document, self.public, store, **context,
                                  now=self.now if now is None else now)

    def state(self, path):
        with sqlite3.connect(path) as connection:
            return (connection.execute("SELECT last_seen FROM capability_state").fetchone()[0],
                    connection.execute("SELECT COUNT(*) FROM capability_nonces").fetchone()[0])

    def install_deleting_trigger(self, path, *, reserved_name=False):
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TRIGGER sqlitex_replay_escape AFTER INSERT ON "
                               "capability_nonces BEGIN DELETE FROM capability_nonces; END")
            if reserved_name:
                # A file can contain this schema despite SQLite rejecting this
                # reserved name through ordinary CREATE TRIGGER syntax.
                connection.execute("PRAGMA writable_schema=ON")
                connection.execute(
                    "UPDATE sqlite_schema SET name='sqlite_replay_escape', "
                    "sql='CREATE TRIGGER sqlite_replay_escape AFTER INSERT ON "
                    "capability_nonces BEGIN DELETE FROM capability_nonces; END' "
                    "WHERE name='sqlitex_replay_escape'"
                )
                connection.execute("PRAGMA writable_schema=OFF")

    def test_schema_rejects_trigger_hidden_by_sql_like_underscore_wildcard(self):
        path = self.base / "store.sqlite"
        store = ReplayStore.create(path)
        self.install_deleting_trigger(path)
        with self.assertRaises(GuardError):
            ReplayStore(path)
        with self.assertRaises(GuardError):
            self.consume(self.issue(), store)

    def test_schema_rejects_manually_inserted_reserved_sqlite_trigger(self):
        path = self.base / "store.sqlite"
        store = ReplayStore.create(path)
        self.install_deleting_trigger(path, reserved_name=True)
        with self.assertRaises(GuardError):
            ReplayStore(path)
        with self.assertRaises(GuardError):
            self.consume(self.issue(), store)

    def test_schema_rejects_unexpected_sqlitex_table_and_index(self):
        statements = [
            "CREATE TABLE sqlitex_extra(data TEXT)",
            "CREATE INDEX sqlitex_extra ON capability_nonces(jti)",
        ]
        for index, statement in enumerate(statements):
            path = self.base / f"store-{index}.sqlite"
            ReplayStore.create(path)
            with sqlite3.connect(path) as connection:
                connection.execute(statement)
            with self.subTest(statement=statement), self.assertRaises(GuardError):
                ReplayStore(path)

    def test_single_use_is_persisted_across_new_store_instances(self):
        path = self.base / "store.sqlite"
        document = self.issue()
        self.consume(document, ReplayStore.create(path))
        for _ in range(3):
            with self.assertRaisesRegex(GuardError, "replay|consumed"):
                self.consume(document, ReplayStore(path))
        self.assertEqual(self.state(path)[1], 1)

    def test_one_of_twelve_simultaneous_connections_can_consume(self):
        path = self.base / "store.sqlite"
        store = ReplayStore.create(path)
        document = self.issue()
        barrier = threading.Barrier(12)

        def attempt(_):
            barrier.wait(timeout=10)
            try:
                self.consume(document, store)
                return "authorized"
            except GuardError as exc:
                self.assertRegex(str(exc), "replay|consumed")
                return "rejected"

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            results = list(executor.map(attempt, range(12)))
        self.assertEqual(results.count("authorized"), 1, results)
        self.assertEqual(results.count("rejected"), 11, results)
        self.assertEqual(self.state(path)[1], 1)

    def test_clock_rollback_cannot_revive_nonce_after_expired_rows_are_purged(self):
        path = self.base / "store.sqlite"
        first = self.issue(ttl=1)
        self.consume(first, ReplayStore.create(path))
        later = self.now + timedelta(seconds=2)
        second = self.issue(now=later)
        self.consume(second, ReplayStore(path), now=later)
        before = self.state(path)
        self.assertEqual(before[1], 1)  # The first nonce was actually purged.
        with self.assertRaisesRegex(GuardError, "clock rollback"):
            self.consume(first, ReplayStore(path), now=self.now)
        self.assertEqual(self.state(path), before)

    def test_invalid_signature_context_and_expiry_do_not_advance_clock_or_consume(self):
        for kind in ["signature", "context", "expired"]:
            path = self.base / f"{kind}.sqlite"
            store = ReplayStore.create(path)
            original = self.issue()
            future = self.now + timedelta(seconds=100)
            context_changes = {}
            if kind == "expired":
                rejected = self.issue(ttl=1)
            else:
                rejected = self.issue(now=future)
            if kind == "signature":
                rejected = copy.deepcopy(rejected)
                signature = rejected["signature"]
                rejected["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
            if kind == "context":
                context_changes["subject"] = "wrong-customer"
            with self.subTest(kind=kind):
                before = self.state(path)
                with self.assertRaises(GuardError):
                    self.consume(rejected, store, now=future, **context_changes)
                self.assertEqual(self.state(path), before)
                self.consume(original, ReplayStore(path))
                self.assertEqual(self.state(path)[1], 1)

    def test_capacity_failure_keeps_live_nonce_and_persists_clock_floor(self):
        path = self.base / "store.sqlite"
        store = ReplayStore.create(path, max_entries=1)
        first = self.issue(ttl=300)
        self.consume(first, store)
        later = self.now + timedelta(seconds=1)
        with self.assertRaisesRegex(GuardError, "capacity"):
            self.consume(self.issue(now=later), store, now=later)
        self.assertEqual(self.state(path)[1], 1)
        with self.assertRaisesRegex(GuardError, "clock rollback"):
            self.consume(first, ReplayStore(path, max_entries=1))

    def test_missing_database_is_not_recreated_for_new_or_existing_store(self):
        path = self.base / "store.sqlite"
        store = ReplayStore.create(path)
        path.unlink()
        with self.assertRaises(GuardError):
            ReplayStore(path)
        self.assertFalse(path.exists())
        with self.assertRaises(GuardError):
            self.consume(self.issue(), store)
        self.assertFalse(path.exists())

    def test_sqlite_uri_metacharacters_in_filename_do_not_redirect_store(self):
        names = ["store # % 空格.sqlite"]
        # Question marks are valid POSIX filenames, but forbidden on Windows.
        if os.name == "posix":
            names.append("store ?# 空格.sqlite")
        expected_files = set()
        for name in names:
            path = self.base / name
            document = self.issue()
            with self.subTest(name=name):
                self.consume(document, ReplayStore.create(path))
                with self.assertRaisesRegex(GuardError, "replay|consumed"):
                    self.consume(document, ReplayStore(path))
                expected_files.add(name)
                self.assertEqual({p.name for p in self.base.iterdir()}, expected_files)


if __name__ == "__main__":
    unittest.main()
