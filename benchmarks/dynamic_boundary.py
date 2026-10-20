#!/usr/bin/env python3
"""Synthetic server-authorization functional controls on fresh, own fixtures.

Install this checkout or run with PYTHONPATH=src. A client boolean is forced
in Python; this is NOT a REA, Frida or native instrumentation run. No network,
TLS, TEE or deployed server is exercised, and no arbitrary binary is accepted.
Fresh signing keys, capabilities, requests and a temporary SQLite replay store
remain inside the fixture. Only counts, booleans and scope notes are exported.

Exit 0 means these functional checks passed; it is not an anti-REA result or a
deployment security claim. A controlled client with a valid active delegated
capability can still exercise that capability's bound rights.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import secrets
import sys
import tempfile
import threading
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from releaseguard import __version__
    from releaseguard.capabilities import ReplayStore, consume_capability, issue_capability
    from releaseguard.core import GuardError, write_new
except ImportError as exc:
    raise SystemExit(
        "The capability API is unavailable; install this checkout or run with PYTHONPATH=src."
    ) from exc


REPLAY_ATTEMPTS = 32


class BoundaryCheckFailed(RuntimeError):
    """A controlled observation contradicted its stated functional boundary."""


class _SyntheticService:
    """Local stand-in for a trusted server; never a client trust mechanism."""

    def __init__(self, public, expected: dict[str, str], now: datetime):
        self.public = public
        self.expected = dict(expected)
        self.now = now
        self._lock = threading.Lock()
        self._handled_request_hashes: list[str] = []

    @property
    def handler_calls(self) -> int:
        with self._lock:
            return len(self._handled_request_hashes)

    def handle(self, document: Any, request: bytes, store: ReplayStore, *, client_authorized: bool) -> None:
        # Simulates a patched UI boolean. The server does not trust this flag.
        del client_authorized
        consume_capability(
            document, self.public, store, **self.expected, request=request, now=self.now,
        )
        # Execute exactly the immutable bytes just checked, not another request.
        self._handler(request)

    def _handler(self, request: bytes) -> None:
        with self._lock:
            self._handled_request_hashes.append(hashlib.sha256(request).hexdigest())


def _attempt(service: _SyntheticService, document: Any, request: bytes,
             store: ReplayStore, *, client_authorized: bool = True) -> bool:
    try:
        service.handle(document, request, store, client_authorized=client_authorized)
    except GuardError:
        return False
    return True


def experiment() -> dict[str, Any]:
    started = time.perf_counter()
    report: dict[str, Any] = {
        "format": "open-release-guard-dynamic-boundary/v1",
        "releaseguard_version": __version__,
        "scope": "synthetic_server_authorization_functional_controls_only",
        "experiment_completed": False,
        "all_functional_checks_passed": None,
        "rea_evaluated": False,
        "frida_evaluated": False,
        "native_instrumentation_evaluated": False,
        "network_tls_deployment_evaluated": False,
        "tee_evaluated": False,
        "client_boolean_patch_is_simulated": True,
        "environment": {"python": platform.python_version(), "system": platform.system()},
        "cases": {},
        "notes": [
            "These are synthetic functional boundary tests, NOT a REA or Frida run or a decompilation-resistance score.",
            "The client boolean is forced in Python; no native hooks or arbitrary binaries are used.",
            "The trusted server is a local fixture. No network, TLS, TEE, authentication session or production deployment is tested.",
            "A client-controlled active authorized session can still use its valid delegated rights; one successful use is demonstrated.",
            "Signing keys and replay state must live on a trusted service, not a client the adversary controls.",
            "Consumption precedes the handler. A crash between them burns authorization without completing work; this does not prove exactly-once business effects.",
            "Multiple production service instances need shared durable replay state; database rollback, failover, clock trust and recovery are not tested.",
            "The exact immutable request bytes checked by consumption are passed to the handler.",
            "Fresh private keys, token documents, request bodies, signatures and token identifiers are not exported.",
            "Exit 0 means the stated functional controls passed, not that general software protection passed.",
        ],
    }
    try:
        private = Ed25519PrivateKey.generate()
        attacker_private = Ed25519PrivateKey.generate()
        expected = {"subject": "synthetic-user", "audience": "synthetic-service",
                    "product": "own-fixture", "operation": "render-report"}
        now = datetime.now(timezone.utc).replace(microsecond=0)
        request = b"own-fixture-request\x00" + secrets.token_bytes(32)
        swapped_request = b"different-own-fixture-request\x00" + secrets.token_bytes(32)
        service = _SyntheticService(private.public_key(), expected, now)
        with tempfile.TemporaryDirectory(prefix="rg-dynamic-boundary-") as temporary:
            store_path = Path(temporary).resolve() / "replay.sqlite3"
            store = ReplayStore.create(store_path)

            def check(name: str, document: Any, body: bytes, *, should_accept: bool,
                      candidate_store: ReplayStore = store, client_authorized: bool = True) -> None:
                before = service.handler_calls
                accepted = _attempt(service, document, body, candidate_store,
                                    client_authorized=client_authorized)
                added = service.handler_calls - before
                report["cases"][name] = {
                    "accepted": accepted, "handler_calls_added": added,
                    "client_authorized_boolean": client_authorized,
                }
                if accepted != should_accept or added != int(should_accept):
                    report["all_functional_checks_passed"] = False
                    raise BoundaryCheckFailed(f"Functional control failed: {name}")

            check("patched_boolean_missing_capability", None, request, should_accept=False)
            forged = issue_capability(attacker_private, **expected, request=request, now=now)
            check("patched_boolean_forged_capability", forged, request, should_accept=False)

            bound = issue_capability(private, **expected, request=request, now=now)
            check("swapped_request", bound, swapped_request, should_accept=False)
            check("valid_bound_request_after_rejected_swap", bound, request, should_accept=True)
            check("persistent_replay_after_reopen", bound, request, should_accept=False,
                  candidate_store=ReplayStore(store_path))

            concurrent_request = b"own-fixture-concurrent\x00" + secrets.token_bytes(32)
            concurrent_document = issue_capability(private, **expected, request=concurrent_request, now=now)
            barrier = threading.Barrier(REPLAY_ATTEMPTS)

            def concurrent_attempt() -> bool:
                independent_store = ReplayStore(store_path)
                barrier.wait(timeout=10)
                return _attempt(service, concurrent_document, concurrent_request, independent_store)

            before = service.handler_calls
            with ThreadPoolExecutor(max_workers=REPLAY_ATTEMPTS) as executor:
                pending = [executor.submit(concurrent_attempt) for _ in range(REPLAY_ATTEMPTS)]
                outcomes = [future.result(timeout=20) for future in pending]
            accepted = outcomes.count(True)
            rejected = outcomes.count(False)
            added = service.handler_calls - before
            report["cases"]["concurrent_replay"] = {
                "attempts": REPLAY_ATTEMPTS, "accepted": accepted, "rejected": rejected,
                "handler_calls_added": added, "independent_store_instances": REPLAY_ATTEMPTS,
            }
            if (accepted, rejected, added) != (1, REPLAY_ATTEMPTS - 1, 1):
                report["all_functional_checks_passed"] = False
                raise BoundaryCheckFailed("Functional control failed: concurrent_replay")
            check("persistent_replay_after_concurrent_use", concurrent_document, concurrent_request,
                  should_accept=False, candidate_store=ReplayStore(store_path))

            delegated = issue_capability(private, **expected, request=request, now=now)
            check("active_delegated_rights_remain_usable", delegated, request,
                  should_accept=True, client_authorized=False)
            report["handler_calls_total"] = service.handler_calls
        report["experiment_completed"] = True
        report["all_functional_checks_passed"] = True
    except BoundaryCheckFailed as exc:
        report["error"] = str(exc)
    except Exception as exc:
        # Dependency errors may include token bodies/SQL parameters: export
        # only their type, never their message, traceback or repr.
        report["error"] = "The controlled fixture could not complete its required observations"
        report["error_type"] = type(exc).__name__
    report["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path,
                        help="exclusively create JSON here; never overwrite (default: stdout)")
    args = parser.parse_args(argv)
    try:
        if args.out is not None and (args.out.exists() or args.out.is_symlink()):
            raise FileExistsError
        report = experiment()
        raw = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("ascii")
        if args.out is None:
            sys.stdout.buffer.write(raw)
        else:
            write_new(args.out, raw)
    except (GuardError, OSError):
        print("Cannot exclusively create the functional-boundary report", file=sys.stderr)
        return 2
    return 0 if report["experiment_completed"] and report["all_functional_checks_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
