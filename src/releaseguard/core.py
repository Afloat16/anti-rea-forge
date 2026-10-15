"""Versioned Ed25519 documents and fail-closed release/license validation.

The caller supplies a trusted public key. Documents never supply their own key.
This module does not execute the inspected application or modify PE files.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_FILES = 20_000
MAX_ENTRIES = 40_000
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
FEATURE = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
ENVELOPE = "open-release-guard/v1"


class GuardError(ValueError):
    """Input cannot be authenticated or does not satisfy the expected policy."""


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise GuardError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def _no_number(value: str) -> None:
    raise GuardError("Floating-point and non-finite JSON values are not supported")


def parse_json(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise GuardError("Document exceeds the 8 MiB limit")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_float=_no_number, parse_constant=_no_number,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise GuardError("Invalid or ambiguous JSON document") from exc
    if type(value) is not dict:
        raise GuardError("Expected a JSON object")
    return value


def canonical(value: dict[str, Any]) -> bytes:
    # Payload schemas permit only strings, bounded integers, lists and objects.
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError) as exc:
        raise GuardError("Cannot encode document") from exc


def read_limited(path: Path | str, limit: int = MAX_DOCUMENT_BYTES) -> bytes:
    with Path(path).open("rb") as handle:
        value = handle.read(limit + 1)
    if len(value) > limit:
        raise GuardError(f"File exceeds the {limit}-byte limit")
    return value


def read_document(path: Path | str) -> dict[str, Any]:
    return parse_json(read_limited(path))


def _fields(obj: Any, names: set[str]) -> None:
    if type(obj) is not dict or set(obj) != names:
        raise GuardError("Missing, unsupported or unexpected document fields")


def _text(value: Any, label: str, maximum: int = 128) -> str:
    if type(value) is not str or not value.strip() or len(value) > maximum:
        raise GuardError(f"Invalid {label}")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise GuardError(f"Control character in {label}")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise GuardError(f"Invalid Unicode in {label}") from exc
    return value


def _version(value: Any) -> None:
    if type(value) is not int or value != 1:
        raise GuardError("Unsupported schema version")


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise GuardError("Timezone-aware UTC time is required")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime) -> str:
    return _utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value: Any) -> datetime:
    if type(value) is not str or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ):
        raise GuardError("Expected a UTC timestamp such as 2026-10-15T10:00:00Z")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise GuardError("Invalid UTC timestamp") from exc


def write_new(path: Path | str, content: bytes, *, secret: bool = False) -> None:
    """Exclusive creation: never overwrite an existing file or follow its link."""
    destination = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(destination, flags, 0o600 if secret else 0o644)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def save_document(path: Path | str, document: dict[str, Any]) -> None:
    content = json.dumps(document, ensure_ascii=True, indent=2).encode("ascii") + b"\n"
    if len(content) > MAX_DOCUMENT_BYTES:
        raise GuardError("Document exceeds the 8 MiB limit")
    write_new(path, content)


def generate_keys(private_path: Path | str, public_path: Path | str, password: bytes) -> str:
    if not isinstance(password, bytes) or len(password) < 12:
        raise GuardError("Use a passphrase of at least 12 UTF-8 bytes")
    if Path(private_path).absolute() == Path(public_path).absolute():
        raise GuardError("Private and public key paths must be different")
    private = Ed25519PrivateKey.generate()
    encoded = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    write_new(private_path, encoded, secret=True)
    try:
        write_new(public_path, public)
    except BaseException:
        Path(private_path).unlink(missing_ok=True)
        raise
    return key_id(private.public_key())


def load_private_key(path: Path | str, password: bytes) -> Ed25519PrivateKey:
    try:
        value = serialization.load_pem_private_key(read_limited(path, 16_384), password)
    except (ValueError, TypeError) as exc:
        raise GuardError("Cannot load encrypted private key; check its type and passphrase") from exc
    if not isinstance(value, Ed25519PrivateKey):
        raise GuardError("Expected an Ed25519 private key")
    return value


def load_public_key(path: Path | str) -> Ed25519PublicKey:
    try:
        value = serialization.load_pem_public_key(read_limited(path, 16_384))
    except (ValueError, TypeError) as exc:
        raise GuardError("Cannot load public key") from exc
    if not isinstance(value, Ed25519PublicKey):
        raise GuardError("Expected an Ed25519 public key")
    return value


def key_id(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def _domain(kind: str) -> bytes:
    if kind not in {"manifest", "license"}:
        raise GuardError("Unsupported document kind")
    return b"OpenReleaseGuard\x00" + kind.encode("ascii") + b"\x00v1\x00"


def sign_document(kind: str, body: dict[str, Any], private: Ed25519PrivateKey) -> dict[str, Any]:
    raw = canonical(body)
    if len(raw) > MAX_DOCUMENT_BYTES // 2:
        raise GuardError("Payload too large")
    signature = private.sign(_domain(kind) + raw)
    return {"format": ENVELOPE, "kind": kind,
            "payload": base64.b64encode(raw).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii")}


def verify_document(document: dict[str, Any], kind: str,
                    public: Ed25519PublicKey) -> dict[str, Any]:
    _fields(document, {"format", "kind", "payload", "signature"})
    if document["format"] != ENVELOPE or document["kind"] != kind:
        raise GuardError("Wrong envelope version or document kind")
    for name in ("payload", "signature"):
        if type(document[name]) is not str or len(document[name]) > MAX_DOCUMENT_BYTES:
            raise GuardError(f"Invalid {name}")
    try:
        raw = base64.b64decode(document["payload"], validate=True)
        signature = base64.b64decode(document["signature"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise GuardError("Invalid base64 encoding") from exc
    if len(signature) != 64 or len(raw) > MAX_DOCUMENT_BYTES // 2:
        raise GuardError("Invalid signature or payload length")
    try:
        public.verify(signature, _domain(kind) + raw)
    except InvalidSignature as exc:
        raise GuardError("Signature verification failed") from exc
    body = parse_json(raw)
    if canonical(body) != raw:
        raise GuardError("Payload must use the v1 canonical JSON encoding")
    return body


def safe_relative_path(value: Any) -> str:
    name = _text(value, "relative path", 1024)
    if unicodedata.normalize("NFC", name) != name:
        raise GuardError("Paths must use NFC Unicode normalization")
    reserved = {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"}
    reserved |= {prefix + digit for prefix in ("COM", "LPT") for digit in "123456789¹²³"}
    for part in name.split("/"):
        if (not part or part in {".", ".."} or len(part.encode("utf-8")) > 255
                or part.endswith((".", " "))
                or any(c in part for c in '\\:<>"|?*')
                or part.partition(".")[0].rstrip(" ").upper() in reserved):
            raise GuardError(f"Unsafe or ambiguous Windows path: {name!r}")
    return name


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x400  # FILE_ATTRIBUTE_REPARSE_POINT
    )


def _root(path: Path | str) -> Path:
    root = Path(path).absolute()
    info = root.lstat()
    if _is_link(info) or not stat.S_ISDIR(info.st_mode):
        raise GuardError("Release root must be a regular directory, not a link/reparse point")
    return root.resolve(strict=True)


def _inventory(root: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    aliases: set[str] = set()
    directories = [root]
    while directories:
        current = directories.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                if _is_link(info):
                    raise GuardError(f"Links/reparse points are not allowed: {entry.name}")
                path = Path(entry.path)
                relative = safe_relative_path(path.relative_to(root).as_posix())
                alias = relative.casefold()
                if alias in aliases:
                    raise GuardError(f"Case-insensitive path collision: {relative}")
                if len(aliases) >= MAX_ENTRIES:
                    raise GuardError("Too many release files and directories")
                aliases.add(alias)
                if stat.S_ISDIR(info.st_mode):
                    directories.append(path)
                elif stat.S_ISREG(info.st_mode):
                    if len(result) >= MAX_FILES:
                        raise GuardError("Too many release files")
                    result[relative] = path
                else:
                    raise GuardError(f"Only regular files are allowed: {relative}")
    return result


def _digest(path: Path, expected_size: int | None = None) -> tuple[int, str]:
    before = path.lstat()
    if _is_link(before) or not stat.S_ISREG(before.st_mode):
        raise GuardError("Release file became a link or special file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise GuardError("Release file changed during inspection")
        if expected_size is not None and opened.st_size != expected_size:
            raise GuardError(f"Release file size differs: {path.name}")
        digest = hashlib.sha256()
        size = 0
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            if expected_size is not None and size > expected_size:
                raise GuardError("Release file grew during verification")
            digest.update(chunk)
        after = os.fstat(handle.fileno())
    if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
        after.st_size, after.st_mtime_ns, after.st_ctime_ns
    ) or size != after.st_size:
        raise GuardError("Release file changed while hashing")
    return size, digest.hexdigest()


def create_manifest(root_path: Path | str, product: str, release: str,
                    private: Ed25519PrivateKey) -> dict[str, Any]:
    _text(product, "product")
    _text(release, "release")
    root = _root(root_path)
    inventory = _inventory(root)
    if not inventory:
        raise GuardError("Cannot sign an empty release")
    files = []
    for relative, path in sorted(inventory.items()):
        if (path.suffix.lower() in {".key", ".pfx", ".p12"}
                or path.name.lower() in {".env", "private.pem", "issuer-private.pem"}):
            raise GuardError(f"Potential secret in release directory: {relative}")
        size, digest = _digest(path)
        files.append({"path": relative, "size": size, "sha256": digest})
    return sign_document("manifest", {
        "version": 1, "product": product, "release": release,
        "created_at": _timestamp(utc_now()), "files": files,
    }, private)


def verify_manifest(document: dict[str, Any], root_path: Path | str,
                    public: Ed25519PublicKey, product: str,
                    release: str | None = None) -> dict[str, Any]:
    _text(product, "expected product")
    if release is not None:
        _text(release, "expected release")
    body = verify_document(document, "manifest", public)
    _fields(body, {"version", "product", "release", "created_at", "files"})
    _version(body["version"])
    _text(body["product"], "product")
    _text(body["release"], "release")
    _parse_time(body["created_at"])
    if body["product"] != product or (release is not None and body["release"] != release):
        raise GuardError("Unexpected product or release")
    if type(body["files"]) is not list or not 1 <= len(body["files"]) <= MAX_FILES:
        raise GuardError("Invalid release file list")
    expected: dict[str, dict[str, Any]] = {}
    aliases: set[str] = set()
    for record in body["files"]:
        _fields(record, {"path", "size", "sha256"})
        relative = safe_relative_path(record["path"])
        if relative.casefold() in aliases:
            raise GuardError("Duplicate or ambiguous release path")
        aliases.add(relative.casefold())
        if type(record["size"]) is not int or not 0 <= record["size"] <= (1 << 63) - 1:
            raise GuardError("Invalid file size")
        if type(record["sha256"]) is not str or not HEX256.fullmatch(record["sha256"]):
            raise GuardError("Invalid SHA-256 digest")
        expected[relative] = record
    actual = _inventory(_root(root_path))
    if set(expected) != set(actual):
        missing = sorted(set(expected) - set(actual))[:10]
        extra = sorted(set(actual) - set(expected))[:10]
        raise GuardError(f"Release contents differ; missing={missing!r}, extra={extra!r}")
    for relative, path in actual.items():
        size, digest = _digest(path, expected_size=expected[relative]["size"])
        if size != expected[relative]["size"] or digest != expected[relative]["sha256"]:
            raise GuardError(f"Release file was modified: {relative}")
    return body


def _features(value: Any) -> list[str]:
    if type(value) is not list or len(value) > 128:
        raise GuardError("Invalid feature list")
    if any(type(x) is not str or not FEATURE.fullmatch(x) for x in value):
        raise GuardError("Invalid feature identifier")
    if len(set(value)) != len(value):
        raise GuardError("Duplicate feature identifier")
    return value


def _collect_features(value: Iterable[str]) -> list[str]:
    # A bare string must never silently become a set of single-letter grants.
    if isinstance(value, (str, bytes)):
        raise GuardError("Features must be a collection of identifiers, not a string")
    try:
        iterator = iter(value)
    except TypeError as exc:
        raise GuardError("Features must be an iterable of identifiers") from exc
    collected: list[str] = []
    for item in iterator:
        if len(collected) >= 128:
            raise GuardError("Too many feature identifiers")
        collected.append(item)
    return _features(collected)


def issue_license(product: str, subject: str, days: int, features: Iterable[str],
                  private: Ed25519PrivateKey, *, now: datetime | None = None) -> dict[str, Any]:
    _text(product, "product")
    _text(subject, "subject", 256)
    if type(days) is not int or not 1 <= days <= 3650:
        raise GuardError("License duration must be 1..3650 days")
    feature_list = sorted(_collect_features(features))
    issued = _utc(now) if now is not None else utc_now()
    return sign_document("license", {
        "version": 1, "product": product, "subject": subject,
        "license_id": str(uuid.uuid4()), "issued_at": _timestamp(issued),
        "not_before": _timestamp(issued),
        "expires_at": _timestamp(issued + timedelta(days=days)), "features": feature_list,
    }, private)


def verify_license(document: dict[str, Any], public: Ed25519PublicKey, product: str,
                   *, required_features: Iterable[str] = (), subject: str | None = None,
                   now: datetime | None = None) -> dict[str, Any]:
    _text(product, "expected product")
    if subject is not None:
        _text(subject, "expected subject", 256)
    body = verify_document(document, "license", public)
    _fields(body, {"version", "product", "subject", "license_id", "issued_at",
                   "not_before", "expires_at", "features"})
    _version(body["version"])
    _text(body["product"], "product")
    _text(body["subject"], "subject", 256)
    if type(body["license_id"]) is not str:
        raise GuardError("Invalid license ID")
    try:
        if str(uuid.UUID(body["license_id"])) != body["license_id"]:
            raise ValueError("Non-canonical UUID")
    except ValueError as exc:
        raise GuardError("Invalid license ID") from exc
    if body["product"] != product or (subject is not None and body["subject"] != subject):
        raise GuardError("Unexpected license product or subject")
    issued, start, end = (_parse_time(body[x]) for x in ("issued_at", "not_before", "expires_at"))
    if not issued <= start < end:
        raise GuardError("Invalid license validity interval")
    current = _utc(now) if now is not None else utc_now()
    if current < start:
        raise GuardError("License is not valid yet; check the system clock")
    if current >= end:
        raise GuardError("License expired")
    granted = _features(body["features"])
    required = _collect_features(required_features)
    if not set(required).issubset(granted):
        raise GuardError("License does not grant the required features")
    return body
