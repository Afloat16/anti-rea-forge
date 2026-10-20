"""Bounded, one-way password verification with a fixed Argon2id profile.

This replaces storing a recoverable password with a salted verifier. It is not
a native protection SDK: it cannot prevent a client patch, keyboard/memory
observation, or guessing a low-entropy password. Callers must protect verifier
integrity and apply their own authentication rate/concurrency limits. The fixed
profile bounds one operation; it does not limit the number of operations.

Profile: RFC 9106 section 4's second recommended option, with 64 MiB of memory,
3 iterations, 4 lanes, a 16-byte random salt and a 32-byte output. Passwords are
opaque bytes; this module neither normalizes text nor records password values.
"""

from __future__ import annotations

import base64
import binascii
import re
import secrets

from cryptography.exceptions import InvalidKey, UnsupportedAlgorithm

from .core import GuardError

try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ImportError:
    # A missing/unsupported backend must fail closed when an API is called.
    # There is intentionally no lower-cost or alternate-algorithm fallback.
    Argon2id = None  # type: ignore[assignment,misc]


FORMAT = "open-release-guard-password/v1"
_MEMORY_KIB = 64 * 1024
_ITERATIONS = 3
_LANES = 4
_SALT_BYTES = 16
_VERIFIER_BYTES = 32
_MAX_PASSWORD_BYTES = 1024
_PREFIX = "$argon2id$v=19$m=65536,t=3,p=4$"
_PHC_LENGTH = len(_PREFIX) + 22 + 1 + 43
_PHC = re.compile(
    re.escape(_PREFIX) + r"([A-Za-z0-9+/]{22})\$([A-Za-z0-9+/]{43})\Z",
    re.ASCII,
)
_BACKEND_ERRORS = (UnsupportedAlgorithm, AttributeError, TypeError, ValueError, MemoryError)


def _password(password: bytes, minimum: int) -> None:
    if type(password) is not bytes or not minimum <= len(password) <= _MAX_PASSWORD_BYTES:
        raise GuardError(f"Password must be bytes with length {minimum}..{_MAX_PASSWORD_BYTES}")


def _decode(segment: str, length: int) -> bytes:
    try:
        raw = base64.b64decode(segment + "=" * (-len(segment) % 4), validate=True)
    except (binascii.Error, ValueError):
        raise GuardError("Invalid password verifier encoding") from None
    # Reject noncanonical trailing bits as well as wrong decoded lengths. PHC
    # uses standard Base64 without '=' padding, not URL-safe Base64.
    if len(raw) != length or base64.b64encode(raw).rstrip(b"=").decode("ascii") != segment:
        raise GuardError("Invalid password verifier encoding")
    return raw


def _document(document: dict) -> tuple[bytes, bytes]:
    if (type(document) is not dict or len(document) != 2 or
            any(type(key) is not str for key in document) or
            set(document) != {"format", "phc"}):
        raise GuardError("Missing, unsupported or unexpected password verifier fields")
    if type(document["format"]) is not str or document["format"] != FORMAT:
        raise GuardError("Unsupported password verifier format")
    phc = document["phc"]
    # Bound the string before parsing; no untrusted integer is converted or
    # passed to a KDF. Only our exact canonical fixed-cost profile is accepted.
    if type(phc) is not str or len(phc) != _PHC_LENGTH:
        raise GuardError("Unsupported or malformed Argon2id verifier profile")
    match = _PHC.fullmatch(phc)
    if match is None:
        raise GuardError("Unsupported or malformed Argon2id verifier profile")
    return _decode(match[1], _SALT_BYTES), _decode(match[2], _VERIFIER_BYTES)


def _kdf(salt: bytes):
    if Argon2id is None:
        raise GuardError("Argon2id password verification is unavailable; no fallback is permitted")
    try:
        return Argon2id(
            salt=salt, length=_VERIFIER_BYTES, iterations=_ITERATIONS,
            lanes=_LANES, memory_cost=_MEMORY_KIB,
        )
    except _BACKEND_ERRORS:
        raise GuardError("Argon2id password verification is unavailable") from None


def create_password_verifier(password: bytes) -> dict:
    """Create a public PHC verifier for a 12..1024-byte password.

    Salt and verifier are public. A length floor is not an entropy guarantee.
    Invalid input or unavailable cryptography raises GuardError; no password
    value is included in errors. No plaintext password is stored in the result.
    """
    _password(password, 12)
    try:
        salt = secrets.token_bytes(_SALT_BYTES)
    except OSError:
        raise GuardError("Secure password salt generation is unavailable") from None
    kdf = _kdf(salt)
    try:
        phc = kdf.derive_phc_encoded(password)
    except _BACKEND_ERRORS:
        raise GuardError("Argon2id password verifier creation failed") from None
    document = {"format": FORMAT, "phc": phc}
    _document(document)
    return document


def verify_password(password: bytes, document: dict) -> bool:
    """Verify a 0..1024-byte candidate, returning False only for a mismatch.

    Malformed documents, unsupported profiles/backends and invalid candidates
    raise GuardError. The document is validated before KDF construction. The
    backend receives fixed trusted parameters, never a profile chosen by a
    potentially hostile PHC string.
    """
    _password(password, 0)
    salt, expected = _document(document)
    kdf = _kdf(salt)
    try:
        # cryptography performs the verifier comparison. Do not replace this
        # with a Python equality check of derived bytes.
        kdf.verify(password, expected)
    except InvalidKey:
        return False
    except _BACKEND_ERRORS:
        raise GuardError("Argon2id password verification failed") from None
    return True
