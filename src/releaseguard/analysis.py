"""Explicit authorization for a cooperating, operator-controlled analysis gateway.

The gateway supplies the trusted public key, authenticated subject, audience and
requested operation. None of those values is discovered from an analysis target.
The release and all ancestor directories must be immutable and controlled by the
operator until the admitted operation finishes. This check does not lock files,
sandbox a tool, authenticate a caller, or change a third-party agent's policy.

Grants are reusable within their short validity interval. There is no online
revocation, replay database, or cached allow decision. Check before each tool
invocation and retain the ordinary service authentication and authorization.
The now argument is a trusted clock/test seam, never a value supplied by the
analysis client. All work occurs in the gateway; a protected application need
not import this module.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .core import (
    GuardError, HEX256, MAX_DOCUMENT_BYTES, MAX_FILES, _fields, _parse_time,
    _text, _timestamp, _version, canonical, key_id, parse_json, safe_relative_path,
    sign_document, utc_now, verify_document, verify_manifest,
)

ANALYSIS_OPERATIONS = ("inspect", "decompile", "instrument")
MAX_ANALYSIS_TTL_SECONDS = 86_400
MAX_ANALYSIS_GRANT_BYTES = 16_384
_KIND = "analysis-grant"
_ENVELOPE_FIELDS = {"format", "kind", "payload", "signature"}
_CLAIM_FIELDS = {
    "version", "grant_id", "product", "release", "manifest_sha256", "subject",
    "audience", "operations", "issued_at", "not_before", "expires_at",
}
_LIMITATIONS = (
    "Enforced only by a trusted gateway that checks before each tool invocation.",
    "The trusted key, caller identity, audience and operation come from operator configuration.",
    "Keep the release and its ancestor directories immutable through the admitted operation.",
    "Grants are reusable until expiry; no online revocation or replay prevention is provided.",
    "Target notices cannot force an independent AI agent or analysis tool to refuse.",
)


def _identifier(value: Any, label: str) -> str:
    _text(value, label)
    if value != value.strip() or unicodedata.normalize("NFC", value) != value:
        raise GuardError(f"Analysis {label} must be normalized without surrounding whitespace")
    if len(value.encode("utf-8")) > 256 or any(
        unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for char in value
    ):
        raise GuardError(f"Invalid or oversized analysis {label}")
    return value


def _operation(value: Any) -> str:
    if type(value) is not str or value not in ANALYSIS_OPERATIONS:
        raise GuardError("Analysis operation must be inspect, decompile or instrument")
    return value


def _operations(value: Iterable[str], *, claims: bool = False) -> list[str]:
    if (claims and type(value) is not list) or isinstance(value, (str, bytes, dict)):
        raise GuardError("Analysis operations must be a nonempty collection of explicit scopes")
    try:
        iterator = iter(value)
    except TypeError as exc:
        raise GuardError("Analysis operations must be iterable") from exc
    result: list[str] = []
    for item in iterator:
        if len(result) >= len(ANALYSIS_OPERATIONS):
            raise GuardError("Too many analysis operations")
        operation = _operation(item)
        if operation in result:
            raise GuardError("Duplicate analysis operation")
        result.append(operation)
    if not result:
        raise GuardError("At least one analysis operation is required")
    return sorted(result)


def _clock(now: datetime | None) -> datetime:
    value = utc_now() if now is None else now
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise GuardError("Analysis clock must be a timezone-aware trusted datetime")
    try:
        value = value.astimezone(timezone.utc).replace(microsecond=0)
    except (OverflowError, ValueError) as exc:
        raise GuardError("Analysis clock is out of range") from exc
    if value.year < 1970:
        raise GuardError("Analysis clock must be on or after 1970-01-01 UTC")
    return value


def _bounded_envelope(document: Any, limit: int) -> bytes:
    """Bound an envelope before canonicalization, hashing, or signature parsing."""
    _fields(document, _ENVELOPE_FIELDS)
    for field, maximum in (("format", 64), ("kind", 64),
                           ("payload", limit), ("signature", 88)):
        value = document[field]
        if type(value) is not str or not value.isascii() or len(value) > maximum:
            raise GuardError("Invalid or oversized analysis document envelope")
    for field in ("payload", "signature"):
        try:
            decoded = base64.b64decode(document[field], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise GuardError("Invalid analysis document base64") from exc
        if base64.b64encode(decoded).decode("ascii") != document[field]:
            raise GuardError("Analysis document base64 must use its canonical encoding")
    raw = canonical(document)
    if len(raw) > limit:
        raise GuardError("Analysis document exceeds its byte limit")
    return raw


def _manifest_claims(document: dict[str, Any], public: Ed25519PublicKey) -> dict[str, Any]:
    """Validate the existing manifest v1 schema without touching release files.

    File integrity is checked by core.verify_manifest only after a grant passes.
    This mirrors that manifest schema using its existing validation primitives;
    it neither introduces a new manifest format nor signs unchecked file records.
    """
    body = verify_document(document, "manifest", public)
    _fields(body, {"version", "product", "release", "created_at", "files"})
    _version(body["version"])
    _identifier(body["product"], "product")
    _identifier(body["release"], "release")
    _parse_time(body["created_at"])
    if type(body["files"]) is not list or not 1 <= len(body["files"]) <= MAX_FILES:
        raise GuardError("Invalid release file list")
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
    return body


def _grant_claims(body: dict[str, Any]) -> tuple[datetime, datetime]:
    _fields(body, _CLAIM_FIELDS)
    _version(body["version"])
    for field in ("product", "release", "subject", "audience"):
        _identifier(body[field], field)
    if type(body["grant_id"]) is not str:
        raise GuardError("Invalid analysis grant ID")
    try:
        if str(uuid.UUID(body["grant_id"])) != body["grant_id"]:
            raise ValueError("Noncanonical grant ID")
    except ValueError as exc:
        raise GuardError("Invalid analysis grant ID") from exc
    if type(body["manifest_sha256"]) is not str or not HEX256.fullmatch(body["manifest_sha256"]):
        raise GuardError("Invalid analysis manifest digest")
    _operations(body["operations"], claims=True)
    issued, start, end = (_parse_time(body[field]) for field in
                          ("issued_at", "not_before", "expires_at"))
    if issued.year < 1970 or not issued <= start < end or not (
        1 <= (end - issued).total_seconds() <= MAX_ANALYSIS_TTL_SECONDS
    ):
        raise GuardError("Invalid analysis grant validity interval")
    return start, end


def issue_analysis_grant(
    private: Ed25519PrivateKey,
    manifest: dict[str, Any],
    *,
    product: str,
    release: str,
    subject: str,
    audience: str,
    operations: Iterable[str],
    ttl_seconds: int = 3600,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Issuer only: grant independent scopes for one exact signed manifest.

    The issuer must already have authorized the subject and requested scopes.
    The manifest signature/schema is verified using this issuer's public key;
    issuance does not read, execute, or modify any release artifact.
    """
    if not isinstance(private, Ed25519PrivateKey):
        raise GuardError("Expected an Ed25519 analysis issuer private key")
    for field, value in (("product", product), ("release", release),
                         ("subject", subject), ("audience", audience)):
        _identifier(value, field)
    scopes = _operations(operations)
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_ANALYSIS_TTL_SECONDS:
        raise GuardError("Analysis grant lifetime must be 1..86400 seconds")
    issued = _clock(now)
    try:
        expires = issued + timedelta(seconds=ttl_seconds)
    except OverflowError as exc:
        raise GuardError("Analysis grant expiry is out of range") from exc
    raw = _bounded_envelope(manifest, MAX_DOCUMENT_BYTES)
    manifest_body = _manifest_claims(parse_json(raw), private.public_key())
    if manifest_body["product"] != product or manifest_body["release"] != release:
        raise GuardError("Unexpected manifest product or release")
    body = {
        "version": 1, "grant_id": str(uuid.uuid4()), "product": product,
        "release": release, "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "subject": subject, "audience": audience, "operations": scopes,
        "issued_at": _timestamp(issued), "not_before": _timestamp(issued),
        "expires_at": _timestamp(expires),
    }
    document = sign_document(_KIND, body, private)
    _bounded_envelope(document, MAX_ANALYSIS_GRANT_BYTES)
    return document


def check_analysis_authorization(
    manifest: dict[str, Any],
    root: Path | str,
    public: Ed25519PublicKey,
    *,
    product: str,
    release: str,
    subject: str,
    audience: str,
    operation: str,
    grant: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a bounded decision; never execute the requested analysis operation.

    Invalid caller configuration raises GuardError. Untrusted documents, absent
    grants, wrong scope/time and release mismatches return a denial with a fixed
    reason code. Denied grants never trigger a scan of the release directory.
    The gateway must require an allow decision immediately before its own tool
    callback; returning this report alone does not enforce that integration.
    """
    if not isinstance(public, Ed25519PublicKey):
        raise GuardError("Expected a previously trusted Ed25519 issuer public key")
    for field, value in (("product", product), ("release", release),
                         ("subject", subject), ("audience", audience)):
        _identifier(value, field)
    _operation(operation)
    if not isinstance(root, (str, Path)) or (isinstance(root, str) and not root):
        raise GuardError("Analysis release root must be an explicit path")
    current = _clock(now)
    checks = {"grant_signature": False, "grant_scope": False,
              "grant_time": False, "release_integrity": False}
    report: dict[str, Any] = {
        "ok": False, "authorized": False, "decision": "deny", "reason": "manifest_invalid",
        "product": product, "release": release, "subject": subject,
        "audience": audience, "operation": operation, "manifest_sha256": None,
        "issuer_key_sha256": key_id(public), "validity": None, "checks": checks,
        "limitations": list(_LIMITATIONS),
    }

    def deny(reason: str) -> dict[str, Any]:
        report["reason"] = reason
        return report

    try:
        raw = _bounded_envelope(manifest, MAX_DOCUMENT_BYTES)
        report["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        manifest_document = parse_json(raw)
        manifest_body = _manifest_claims(manifest_document, public)
    except GuardError:
        return deny("manifest_invalid")
    if manifest_body["product"] != product or manifest_body["release"] != release:
        return deny("context_mismatch")
    if grant is None:
        return deny("grant_required")
    try:
        grant_document = parse_json(_bounded_envelope(grant, MAX_ANALYSIS_GRANT_BYTES))
        claims = verify_document(grant_document, _KIND, public)
        start, end = _grant_claims(claims)
    except GuardError:
        return deny("grant_invalid")
    checks["grant_signature"] = True
    # Expose only authenticated, schema-checked validity. A gateway may need to
    # recheck it if process/transport scheduling delays its callback admission.
    report["validity"] = {"not_before": claims["not_before"], "expires_at": claims["expires_at"]}
    if any(claims[field] != report[field] for field in
           ("product", "release", "subject", "audience", "manifest_sha256")):
        return deny("context_mismatch")
    if operation not in claims["operations"]:
        return deny("operation_not_granted")
    checks["grant_scope"] = True
    if current < start:
        return deny("grant_not_yet_valid")
    if current >= end:
        return deny("grant_expired")
    checks["grant_time"] = True
    try:
        verify_manifest(manifest_document, root, public, product, release)
    except (GuardError, OSError, ValueError):
        return deny("release_mismatch")
    checks["release_integrity"] = True
    # Hashing a large release can outlast a short grant. The allow decision must
    # still be current when returned; the now seam keeps this testable without sleeps.
    current = _clock(now)
    if current < start or current >= end:
        checks["grant_time"] = False
        return deny("grant_not_yet_valid" if current < start else "grant_expired")
    report.update(ok=True, authorized=True, decision="allow", reason="authorized")
    return report
