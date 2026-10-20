"""Request-bound capabilities consumed by a trusted server, outside the client.

The replay database and every ancestor directory must be controlled by the
server operator. They must not be replaced concurrently, restored from an older
backup, or reset while outstanding capabilities exist. File identity checks
detect ordinary replacement; they are not protection against a malicious
directory owner or rollback of the database/storage itself. Use local storage
with working SQLite locking and durability guarantees. POSIX creates use 0600;
on Windows the operator must also protect the directory with an appropriate ACL.

``now`` is the trusted server clock, or a test seam, never client-provided time.
Consume before invoking the protected operation. A successful consume is final:
a later handler failure must not make the capability reusable. This provides
at-most-once admission, not atomicity with an application's external effects.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import sqlite3
import stat
import unicodedata
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .core import GuardError, _is_link, canonical

MAX_REQUEST_BYTES = 1024 * 1024
MAX_TTL_SECONDS = 300
MAX_IDENTIFIER_BYTES = 128
MAX_STORE_ENTRIES = 1_000_000
MAX_STORE_BYTES = 512 * 1024 * 1024
_MAX_TIMESTAMP = 253402300799  # Last whole UTC second representable by datetime.
_DOMAIN = b"OpenReleaseGuard\0capability\0v1\0"
_FORMAT = "open-release-guard-capability/v1"
_STORE_MARKER = "open-release-guard-capability-store/v1"
_APPLICATION_ID = 0x52474331
_CLAIM_FIELDS = {
    "version", "subject", "audience", "product", "operation", "jti",
    "request_sha256", "iat", "exp",
}
_IDENTIFIER_FIELDS = ("subject", "audience", "product", "operation")
_HEX256 = re.compile(r"[0-9a-f]{64}\Z")
_STATE_SQL = """CREATE TABLE capability_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    marker TEXT NOT NULL,
    capacity INTEGER NOT NULL CHECK(typeof(capacity) = 'integer' AND capacity BETWEEN 1 AND 1000000),
    last_seen INTEGER NOT NULL CHECK(typeof(last_seen) = 'integer' AND last_seen BETWEEN 0 AND 253402300799)
)"""
_NONCE_SQL = """CREATE TABLE capability_nonces (
    protocol TEXT NOT NULL,
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    jti TEXT NOT NULL,
    expires_at INTEGER NOT NULL CHECK(typeof(expires_at) = 'integer' AND expires_at BETWEEN 0 AND 253402300799),
    PRIMARY KEY (protocol, issuer, audience, jti)
) WITHOUT ROWID"""
_EXPIRY_SQL = "CREATE INDEX capability_expiry ON capability_nonces(expires_at)"
_EXPECTED_SCHEMA = {
    ("table", "capability_state", "capability_state", _STATE_SQL),
    ("table", "capability_nonces", "capability_nonces", _NONCE_SQL),
    ("index", "capability_expiry", "capability_nonces", _EXPIRY_SQL),
}


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise GuardError(f"Invalid capability {label}")
    if unicodedata.normalize("NFC", value) != value or any(
        unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for char in value
    ):
        raise GuardError(f"Capability {label} must be normalized and contain no controls")
    try:
        if len(value.encode("utf-8")) > MAX_IDENTIFIER_BYTES:
            raise GuardError(f"Capability {label} exceeds the identifier limit")
    except UnicodeError as exc:
        raise GuardError(f"Invalid capability {label}") from exc
    return value


def _request_digest(request: bytes) -> str:
    if type(request) is not bytes or len(request) > MAX_REQUEST_BYTES:
        raise GuardError("Capability request must be bytes of at most 1048576 bytes")
    return hashlib.sha256(request).hexdigest()


def _now_seconds(now: datetime | None) -> int:
    value = datetime.now(timezone.utc) if now is None else now
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise GuardError("Capability clock must be a timezone-aware trusted datetime")
    try:
        elapsed = value.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
        seconds = elapsed.days * 86400 + elapsed.seconds
    except (OverflowError, ValueError) as exc:
        raise GuardError("Capability clock is out of range") from exc
    if not 0 <= seconds <= _MAX_TIMESTAMP:
        raise GuardError("Capability clock is out of range")
    return seconds


def _claims(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _CLAIM_FIELDS:
        raise GuardError("Missing, unexpected or invalid capability claims")
    claims = dict(value)
    if type(claims["version"]) is not int or claims["version"] != 1:
        raise GuardError("Unsupported capability claim version")
    for field in _IDENTIFIER_FIELDS:
        _identifier(claims[field], field)
    for field in ("jti", "request_sha256"):
        if type(claims[field]) is not str or not _HEX256.fullmatch(claims[field]):
            raise GuardError(f"Invalid capability {field}")
    if any(type(claims[field]) is not int or not 0 <= claims[field] <= _MAX_TIMESTAMP
           for field in ("iat", "exp")):
        raise GuardError("Capability timestamps must be bounded UTC integer seconds")
    if not 1 <= claims["exp"] - claims["iat"] <= MAX_TTL_SECONDS:
        raise GuardError("Capability lifetime must be in 1..300 seconds")
    return claims


def issue_capability(private: Ed25519PrivateKey, *, subject: str, audience: str,
                     product: str, operation: str, request: bytes,
                     ttl_seconds: int = 60, now: datetime | None = None) -> dict[str, Any]:
    """Issue a request-bound token; keep this signing key on the trusted issuer."""
    if not isinstance(private, Ed25519PrivateKey):
        raise GuardError("Capability issuer requires an Ed25519 private key")
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise GuardError("Capability lifetime must be an integer in 1..300 seconds")
    issued = _now_seconds(now)
    claims = _claims({
        "version": 1, "subject": subject, "audience": audience, "product": product,
        "operation": operation, "jti": secrets.token_hex(32),
        "request_sha256": _request_digest(request), "iat": issued, "exp": issued + ttl_seconds,
    })
    try:
        signature = private.sign(_DOMAIN + canonical(claims))
    except Exception as exc:
        raise GuardError("Capability signing failed") from exc
    return {"format": _FORMAT, "claims": claims,
            "signature": base64.b64encode(signature).decode("ascii")}


def consume_capability(document: dict[str, Any], public: Ed25519PublicKey,
                       store: ReplayStore, *, subject: str, audience: str,
                       product: str, operation: str, request: bytes,
                       now: datetime | None = None) -> dict[str, Any]:
    """Verify trusted context and atomically consume once before doing work."""
    if not isinstance(public, Ed25519PublicKey) or not isinstance(store, ReplayStore):
        raise GuardError("Capability verification requires a trusted Ed25519 key and replay store")
    expected = {"subject": subject, "audience": audience, "product": product, "operation": operation}
    for field, value in expected.items():
        _identifier(value, field)
    request_sha256 = _request_digest(request)
    timestamp = _now_seconds(now)
    if type(document) is not dict or set(document) != {"format", "claims", "signature"}:
        raise GuardError("Missing, unexpected or invalid capability envelope")
    if type(document["format"]) is not str or document["format"] != _FORMAT:
        raise GuardError("Unsupported capability envelope")
    claims = _claims(document["claims"])
    encoded = document["signature"]
    if type(encoded) is not str or len(encoded) != 88:
        raise GuardError("Invalid capability signature encoding")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise GuardError("Invalid capability signature encoding") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != encoded:
        raise GuardError("Invalid capability signature encoding")
    try:
        public.verify(signature, _DOMAIN + canonical(claims))
    except InvalidSignature as exc:
        raise GuardError("Capability signature verification failed") from exc
    except Exception as exc:
        raise GuardError("Capability signature verification unavailable") from exc
    if any(claims[field] != value for field, value in expected.items()):
        raise GuardError("Capability does not match the trusted request context")
    if claims["request_sha256"] != request_sha256:
        raise GuardError("Capability does not match the request bytes")
    if not claims["iat"] <= timestamp < claims["exp"]:
        raise GuardError("Capability is expired or not yet valid")
    try:
        raw_public = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except Exception as exc:
        raise GuardError("Capability issuer identity unavailable") from exc
    store._consume_nonce(hashlib.sha256(raw_public).hexdigest(), expected["audience"],
                         claims["jti"], claims["iat"], claims["exp"], now)
    return claims


def _capacity(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= MAX_STORE_ENTRIES:
        raise GuardError("Replay store capacity must be an integer in 1..1000000")
    return value


def _check_file(path: Path) -> os.stat_result:
    info = path.lstat()
    if _is_link(info) or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_STORE_BYTES:
        raise GuardError("Replay store must be a bounded regular file, not a link or special file")
    if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
        raise GuardError("Replay store permissions must be private (0600)")
    return info


def _check_identity(path: Path, expected: os.stat_result) -> None:
    checked = _check_file(path)
    if (checked.st_dev, checked.st_ino) != (expected.st_dev, expected.st_ino):
        raise GuardError("Replay store file was replaced")


def _sync_parent(path: Path) -> None:
    if os.name == "posix":
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class ReplayStore:
    """An existing, versioned SQLite replay store in a trusted directory.

    Capacity is persisted and must match on reopen. Connections are per call,
    with a five-second SQLite lock wait; unavailable/corrupt/missing stores fail
    closed. Never delete or restore this database to recover capacity. Rejected
    replays and capacity failures still commit the observed trusted clock and
    expired-row purge; a clock rollback performs neither operation.
    """

    def __init__(self, path: Path | str, max_entries: int = 10000):
        self.path = Path(path).absolute()
        self.max_entries = _capacity(max_entries)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._validate(connection)
            connection.commit()

    @classmethod
    def create(cls, path: Path | str, max_entries: int = 10000) -> ReplayStore:
        """Exclusively create a private store; never overwrite another file."""
        maximum = _capacity(max_entries)
        target = Path(path).absolute()
        descriptor: int | None = None
        created: os.stat_result | None = None
        try:
            # SQLite must not recover an unrelated old journal into a new DB.
            for suffix in ("-journal", "-wal", "-shm"):
                try:
                    target.with_name(target.name + suffix).lstat()
                except FileNotFoundError:
                    continue
                raise GuardError("Replay store sidecar already exists; use a fresh trusted location")
            descriptor = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL
                                 | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
            created = os.fstat(descriptor)
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            store = object.__new__(cls)
            store.path, store.max_entries = target, maximum
            with store._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("PRAGMA application_id = 0x52474331")
                connection.execute("PRAGMA user_version = 1")
                for sql in (_STATE_SQL, _NONCE_SQL, _EXPIRY_SQL):
                    connection.execute(sql)
                connection.execute(
                    "INSERT INTO capability_state(singleton, marker, capacity, last_seen) VALUES(1, ?, ?, 0)",
                    (_STORE_MARKER, maximum),
                )
                store._validate(connection)
                connection.commit()
            os.fsync(descriptor)
            _sync_parent(target)
            return store
        except Exception as exc:
            # Remove only the file this invocation exclusively created. SQLite
            # rollback/close removes its own transaction journal on normal error.
            if descriptor is not None:
                os.close(descriptor)
                descriptor = None
            if created is not None:
                try:
                    current = target.lstat()
                    if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                        target.unlink()
                        _sync_parent(target)
                except OSError:
                    pass
            if isinstance(exc, GuardError):
                raise
            raise GuardError("Cannot create capability replay store") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        descriptor: int | None = None
        try:
            before = _check_file(self.path)
            descriptor = os.open(self.path, os.O_RDWR | getattr(os, "O_BINARY", 0)
                                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            opened = os.fstat(descriptor)
            if _is_link(opened) or not stat.S_ISREG(opened.st_mode) or (
                opened.st_dev, opened.st_ino
            ) != (before.st_dev, before.st_ino):
                raise GuardError("Replay store file changed before opening")
            # mode=rw is essential: losing the store must not reset replay state.
            connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True,
                                         timeout=5.0, isolation_level=None)
            _check_identity(self.path, opened)
            disable_extensions = getattr(connection, "enable_load_extension", None)
            if disable_extensions is not None:
                try:
                    disable_extensions(False)
                except sqlite3.NotSupportedError:
                    # Some Python/SQLite builds omit extension support. Loading
                    # is disabled by default; never enable it for this store.
                    pass
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA synchronous = EXTRA")
            connection.execute("PRAGMA temp_store = MEMORY")
            if connection.execute("PRAGMA journal_mode").fetchone() != ("delete",):
                raise GuardError("Replay store requires SQLite DELETE journal mode")
            yield connection
            _check_identity(self.path, opened)
        except GuardError:
            raise
        except (OSError, sqlite3.Error, ValueError, UnicodeError, OverflowError) as exc:
            raise GuardError("Capability replay store is unavailable or invalid") from exc
        finally:
            cleanup_error: Exception | None = None
            if connection is not None:
                try:
                    if connection.in_transaction:
                        connection.rollback()
                except sqlite3.Error as exc:
                    cleanup_error = exc
                try:
                    connection.close()
                except sqlite3.Error as exc:
                    cleanup_error = exc
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    cleanup_error = exc
            if cleanup_error is not None:
                raise GuardError("Capability replay store cleanup failed") from cleanup_error

    def _validate(self, connection: sqlite3.Connection) -> tuple[int, int]:
        if connection.execute("PRAGMA application_id").fetchone() != (_APPLICATION_ID,) or \
                connection.execute("PRAGMA user_version").fetchone() != (1,):
            raise GuardError("Unsupported capability replay store marker")
        # This schema uses INTEGER PRIMARY KEY and WITHOUT ROWID, so it has no
        # implicit sqlite_autoindex rows. Accept exactly the complete schema;
        # even a supposedly "internal" name must not hide a trigger or view.
        objects = set(connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_schema"))
        if objects != _EXPECTED_SCHEMA:
            raise GuardError("Capability replay store schema does not match")
        if connection.execute("PRAGMA quick_check(1)").fetchone() != ("ok",):
            raise GuardError("Capability replay store integrity check failed")
        rows = connection.execute("SELECT singleton, marker, capacity, last_seen FROM capability_state")
        state = rows.fetchone()
        if state is None or rows.fetchone() is not None or state[:3] != (1, _STORE_MARKER, self.max_entries) or \
                type(state[3]) is not int or not 0 <= state[3] <= _MAX_TIMESTAMP:
            raise GuardError("Capability replay store metadata is invalid")
        count = connection.execute("SELECT COUNT(*) FROM capability_nonces").fetchone()[0]
        if type(count) is not int or not 0 <= count <= self.max_entries:
            raise GuardError("Capability replay store capacity is invalid")
        invalid = connection.execute(
            "SELECT 1 FROM capability_nonces WHERE protocol != ? OR typeof(protocol) != 'text' "
            "OR typeof(issuer) != 'text' OR length(issuer) != 64 OR issuer GLOB '*[^0-9a-f]*' "
            "OR typeof(jti) != 'text' OR length(jti) != 64 OR jti GLOB '*[^0-9a-f]*' "
            "OR typeof(audience) != 'text' OR length(CAST(audience AS BLOB)) NOT BETWEEN 1 AND 128 "
            "OR typeof(expires_at) != 'integer' OR expires_at NOT BETWEEN 0 AND 253402300799 LIMIT 1",
            (_FORMAT,),
        ).fetchone()
        if invalid is not None:
            raise GuardError("Capability replay store contains invalid nonce records")
        for (audience,) in connection.execute("SELECT DISTINCT audience FROM capability_nonces"):
            _identifier(audience, "stored audience")
        return state[3], count

    def _consume_nonce(self, issuer: str, audience: str, jti: str,
                       issued_at: int, expires_at: int, now: datetime | None) -> None:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            last_seen, _ = self._validate(connection)
            # Lock contention must not extend token lifetime or make a queued
            # request use a stale clock sample. Explicit now is a fixed test seam.
            timestamp = _now_seconds(now)
            if not issued_at <= timestamp < expires_at:
                raise GuardError("Capability is expired or not yet valid")
            if timestamp < last_seen:
                raise GuardError("Trusted capability server clock rollback detected")
            connection.execute("UPDATE capability_state SET last_seen = ? WHERE singleton = 1", (timestamp,))
            connection.execute("DELETE FROM capability_nonces WHERE expires_at <= ?", (timestamp,))
            namespace = (_FORMAT, issuer, audience, jti)
            if connection.execute(
                "SELECT 1 FROM capability_nonces WHERE protocol = ? AND issuer = ? AND audience = ? AND jti = ?",
                namespace,
            ).fetchone() is not None:
                connection.commit()
                raise GuardError("Capability replay rejected: token already consumed")
            count = connection.execute("SELECT COUNT(*) FROM capability_nonces").fetchone()[0]
            if count >= self.max_entries:
                connection.commit()
                raise GuardError("Capability replay store is at capacity")
            try:
                connection.execute(
                    "INSERT INTO capability_nonces(protocol, issuer, audience, jti, expires_at) VALUES(?, ?, ?, ?, ?)",
                    (*namespace, expires_at),
                )
            except sqlite3.IntegrityError as exc:
                connection.commit()
                raise GuardError("Capability replay rejected") from exc
            connection.commit()
