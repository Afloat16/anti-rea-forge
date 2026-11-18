"""Capability admission stays current through durable consumption and DB reuse."""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard import capabilities
from releaseguard.capabilities import (
    ReplayStore, consume_capability, issue_capability, run_authorized_operation,
)
from releaseguard.core import GuardError


class CapabilityCompletionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned capability completion ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.path = self.work / "replay.sqlite"
        self.store = ReplayStore.create(self.path)
        self.private = Ed25519PrivateKey.generate()
        self.now = datetime(2026, 11, 18, tzinfo=timezone.utc)
        self.context = dict(subject="owned-subject", audience="owned-service", product="owned-product",
                            operation="owned-operation", request=b"owned synthetic request")

    def issue(self):
        return issue_capability(self.private, **self.context, now=self.now, ttl_seconds=20)

    def consume(self, grant, store=None):
        return consume_capability(grant, self.private.public_key(), self.store if store is None else store,
                                  **self.context, now=self.now)

    def count(self):
        with closing(sqlite3.connect(self.path)) as connection:
            return connection.execute("SELECT COUNT(*) FROM capability_nonces").fetchone()[0]

    def delayed_admission(self, stage, final_time):
        grant = self.issue()
        current = {"value": grant["claims"]["iat"] + 10}
        connect = sqlite3.connect
        calls = []

        class DelayedConnection:
            def __init__(self, connection):
                self.connection = connection

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def commit(self):
                self.connection.commit()
                if stage == "commit":
                    current["value"] = final_time(grant)

            def close(self):
                self.connection.close()
                if stage == "close":
                    current["value"] = final_time(grant)

        with patch.object(capabilities.sqlite3, "connect",
                          side_effect=lambda *args, **kwargs: DelayedConnection(connect(*args, **kwargs))), \
                patch.object(capabilities, "_now_seconds", side_effect=lambda _: current["value"]):
            with self.assertRaises(GuardError):
                run_authorized_operation(grant, self.private.public_key(), self.store,
                                         **self.context, handler=lambda request: calls.append(request))
        self.assertEqual(calls, [], "A delayed/rolled-back admission must never reach the handler")
        self.assertEqual(self.count(), 1, "Durably consumed tokens stay spent after a final denial")
        with self.assertRaisesRegex(GuardError, "replay|rollback"):
            self.consume(grant)

    def test_expiry_during_real_commit_prevents_handler_and_keeps_nonce_spent(self):
        self.delayed_admission("commit", lambda grant: grant["claims"]["exp"])

    def test_expiry_during_real_connection_close_prevents_handler(self):
        self.delayed_admission("close", lambda grant: grant["claims"]["exp"])

    def test_clock_rollback_after_commit_is_rejected_even_within_valid_interval(self):
        self.delayed_admission("commit", lambda grant: grant["claims"]["iat"] + 8)

    def test_clock_before_not_before_after_consumption_never_reaches_handler(self):
        self.delayed_admission("close", lambda grant: grant["claims"]["iat"] - 1)

    def replace_store(self, *, identical=False):
        target = self.work / "replacement.sqlite"
        if identical:
            target.write_bytes(self.path.read_bytes())
            target.chmod(0o600)
        else:
            ReplayStore.create(target)
        before, after = self.path.stat(), target.stat()
        if (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino):
            self.skipTest("Filesystem does not expose distinct identities for this replacement fixture")
        os.replace(target, self.path)

    def test_created_instance_rejects_fresh_store_replacement_before_replay(self):
        grant = self.issue()
        self.consume(grant)
        self.replace_store()
        replacement = self.path.read_bytes()
        with self.assertRaisesRegex(GuardError, "replaced"):
            self.consume(grant)
        self.assertEqual(self.path.read_bytes(), replacement)
        self.assertEqual(self.count(), 0)

    def test_reopened_instance_rejects_byte_identical_replacement(self):
        opened = ReplayStore(self.path)
        self.replace_store(identical=True)
        replacement = self.path.read_bytes()
        with self.assertRaisesRegex(GuardError, "replaced"):
            self.consume(self.issue(), opened)
        self.assertEqual(self.path.read_bytes(), replacement)

    def test_unreplaced_stores_share_persistent_replay_state_across_normal_writes(self):
        opened = ReplayStore(self.path)
        first, second = self.issue(), self.issue()
        self.assertEqual(self.consume(first), first["claims"])
        self.assertEqual(self.consume(second, opened), second["claims"])
        self.assertEqual(self.count(), 2)
        for store in (self.store, opened, ReplayStore(self.path)):
            with self.subTest(store=store), self.assertRaisesRegex(GuardError, "replay"):
                self.consume(first, store)


if __name__ == "__main__":
    unittest.main()
