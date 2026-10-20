#!/usr/bin/env python3
"""Probe one synthetic capability authority using real SQLite locking/processes.

Install this checkout or run with PYTHONPATH=src. The script creates fresh keys,
capabilities, requests and databases in a temporary directory. No external
token, database, target program or service can be selected. Only metadata and
counts are reported; all synthetic credentials and state are removed.

This tests lock-wait expiry and at-most-once admission in a local replay store.
It is not a REA/Frida, network, TEE, database-rollback or business-handler test.
Exit 0 means both scoped probes completed; incomplete/failed probes exit 2.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import multiprocessing
from pathlib import Path
import platform
import sqlite3
import sys
import tempfile
import threading
import time
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from releaseguard import __version__
from releaseguard.capabilities import ReplayStore, consume_capability, issue_capability
from releaseguard.core import GuardError, write_new

CONTEXT = dict(subject="fixture-user", audience="fixture-authority", product="fixture",
               operation="one-operation", request=b"exact fixture request")


class ExperimentIncomplete(RuntimeError):
    """A scoped check did not establish its expected observation."""


def require(condition: bool, label: str) -> None:
    # These observations must remain checked even under python -O.
    if not condition:
        raise ExperimentIncomplete(label)


def process_worker(path, document, raw_public, now, ready, go, results):
    try:
        store = ReplayStore(path)
        public = Ed25519PublicKey.from_public_bytes(raw_public)
        ready.put(True)
        require(go.wait(10), "worker barrier timed out")
        try:
            consume_capability(document, public, store, **CONTEXT, now=now)
            results.put({"outcome": "authorized"})
        except GuardError as error:
            require("replay" in str(error) or "consumed" in str(error),
                    "worker rejected for a reason other than replay")
            results.put({"outcome": "rejected-replay"})
    except Exception as error:
        # Never return raw exception messages, credentials or request contents.
        results.put({"outcome": "error", "error_type": type(error).__name__})


def real_lock_expiry(base: Path, private: Ed25519PrivateKey) -> dict:
    path = base / "expiry.sqlite"
    store = ReplayStore.create(path)
    document = issue_capability(private, **CONTEXT, ttl_seconds=2)
    entered = threading.Event()
    original_connection = ReplayStore._connection

    @contextmanager
    def observed_connection(self):
        # Observe entry only; preserve the actual connection, validation,
        # transaction, clock and signature-verification implementations.
        with original_connection(self) as connection:
            if self is store:
                entered.set()
            yield connection

    def consume():
        try:
            consume_capability(document, private.public_key(), store, **CONTEXT)
            return "authorized"
        except GuardError as error:
            return str(error)

    lock = sqlite3.connect(path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        with patch.object(ReplayStore, "_connection", observed_connection), \
                ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(consume)
            try:
                require(entered.wait(2), "request did not reach its connection after validation")
                time.sleep(max(0, document["claims"]["exp"] + 0.15 - time.time()))
                require(not pending.done(), "request was not waiting for the SQLite write lock")
            finally:
                lock.commit()
            result = pending.result(timeout=7)
    finally:
        lock.close()
    require("expired" in result, "expired lock-wait request was not rejected as expired")
    with sqlite3.connect(path) as connection:
        floor = connection.execute("SELECT last_seen FROM capability_state").fetchone()[0]
        count = connection.execute("SELECT COUNT(*) FROM capability_nonces").fetchone()[0]
    require((floor, count) == (0, 0), "expired lock-wait request changed authority state")
    return {"completed": True, "ttl_seconds": 2, "real_write_lock_wait_observed": True,
            "expired_rejected": True, "last_seen_after": floor, "nonce_count_after": count,
            "connection_observation_only": True}


def process_race(base: Path, private: Ed25519PrivateKey) -> dict:
    path = base / "process.sqlite"
    ReplayStore.create(path)
    # A fixed trusted test clock isolates replay concurrency from token expiry.
    now = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
    document = issue_capability(private, **CONTEXT, now=now)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    context = multiprocessing.get_context("spawn")
    ready, results = context.Queue(), context.Queue()
    go = context.Event()
    children = [context.Process(target=process_worker,
                args=(path, document, public, now, ready, go, results)) for _ in range(6)]
    try:
        for child in children:
            child.start()
        for _ in children:
            require(ready.get(timeout=10) is True, "a worker did not reach the barrier")
        go.set()
        outcomes = [results.get(timeout=10) for _ in children]
        for child in children:
            child.join(timeout=5)
            require(child.exitcode == 0, "a worker did not exit normally")
        authorized = sum(item["outcome"] == "authorized" for item in outcomes)
        rejected = sum(item["outcome"] == "rejected-replay" for item in outcomes)
        require(authorized == 1 and rejected == 5, "concurrent single-use admission counts differ")
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
                child.join(timeout=5)
        for queue in (ready, results):
            queue.close()
            queue.join_thread()
    with sqlite3.connect(path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM capability_nonces").fetchone()[0]
    require(count == 1, "concurrent authority did not persist exactly one nonce")
    return {"completed": True, "start_method": "spawn", "processes": len(children),
            "authorized": authorized, "rejected_replay": rejected,
            "persisted_nonce_count": count, "fixed_trusted_test_clock": True}


def experiment() -> dict:
    started = time.monotonic()
    report = {"format": "open-release-guard-capability-process-boundary/v1",
              "package_version": __version__, "experiment_completed": False,
              "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
              "platform": platform.system(), "python_version": platform.python_version(),
              "sqlite_version": sqlite3.sqlite_version,
              "scope": "own synthetic requests, ephemeral keys and local SQLite stores only",
              "rea_evaluated": False, "frida_evaluated": False,
              "network_evaluated": False, "tee_evaluated": False,
              "database_rollback_evaluated": False, "business_handler_evaluated": False}
    try:
        with tempfile.TemporaryDirectory(prefix="capability-process-boundary-") as directory:
            base = Path(directory).resolve()
            private = Ed25519PrivateKey.generate()
            report["real_sqlite_lock_expiry"] = real_lock_expiry(base, private)
            report["cross_process_replay_race"] = process_race(base, private)
        report["experiment_completed"] = True
    except Exception as error:
        report["error"] = "scoped experiment incomplete"
        report["error_type"] = type(error).__name__
    report["elapsed_seconds"] = round(time.monotonic() - started, 6)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="exclusively create JSON here; default: stdout")
    args = parser.parse_args()
    try:
        if args.out is not None and (args.out.exists() or args.out.is_symlink()):
            raise FileExistsError("output already exists")
        report = experiment()
        content = (json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True) + "\n").encode("ascii")
        if args.out is None:
            sys.stdout.buffer.write(content)
        else:
            write_new(args.out, content)
    except (GuardError, OSError):
        print("capability process experiment could not create its report", file=sys.stderr)
        return 2
    return 0 if report["experiment_completed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
