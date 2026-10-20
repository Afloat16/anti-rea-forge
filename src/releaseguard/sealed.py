"""Authenticated encryption of data assets with an externally held master key.

The exact v1 envelope fields are ``format``, ``salt``, ``nonce`` and
``ciphertext``. Binary fields use canonical, padded standard Base64; ciphertext
includes the 16-byte GCM tag. A random 32-byte salt feeds HKDF-SHA256 to derive
a 32-byte package key; AES-256-GCM uses a fresh random 12-byte nonce.

The caller supplies trusted product/release/purpose/asset_id identifiers. They
are bound by both HKDF info and AEAD associated data, never taken from the
untrusted envelope. Identifiers are NFC, 1..128 characters, without leading or
trailing whitespace, Unicode C-category characters or non-ASCII separators.

Keep the master key with the user, a server or a KMS; do not bundle it with a
client release or its sealed assets. Once a controlled client receives a key
or plaintext, its memory can be inspected or dumped. Python/pyca buffers have
no zeroization guarantee. This module loads/decrypts data only, never code,
and supplies no freshness or replay protection within an identical context.
"""

from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path
import secrets
import stat
from typing import Any
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .core import GuardError, canonical, write_new

SEALED_FORMAT = "open-release-guard-sealed-asset/v1"
ASSET_KEY_BYTES = 32
MAX_ASSET_BYTES = 1024 * 1024
MAX_CONTEXT_CHARACTERS = 128
_SALT_BYTES = 32
_NONCE_BYTES = 12
_TAG_BYTES = 16
_FIELDS = {"format", "salt", "nonce", "ciphertext"}
_DOMAIN = b"OpenReleaseGuard\x00sealed-asset\x00v1\x00"


def _key(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) != ASSET_KEY_BYTES:
        raise GuardError("Asset key must be exactly 32 bytes")
    return value


def _context(product: str, release: str, purpose: str, asset_id: str) -> bytes:
    values = {"product": product, "release": release,
              "purpose": purpose, "asset_id": asset_id}
    for value in values.values():
        if (type(value) is not str or not 1 <= len(value) <= MAX_CONTEXT_CHARACTERS
                or value != value.strip() or unicodedata.normalize("NFC", value) != value):
            raise GuardError("Invalid trusted asset context")
        for char in value:
            category = unicodedata.category(char)
            if category.startswith("C") or (category.startswith("Z") and char != " "):
                raise GuardError("Invalid trusted asset context")
    return _DOMAIN + b"AAD\x00" + canonical({"format": SEALED_FORMAT, **values})


def _derive(key: bytes, salt: bytes, aad: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=ASSET_KEY_BYTES, salt=salt,
        info=_DOMAIN + b"HKDF-SHA256/AES-256-GCM\x00" + aad,
    ).derive(key)


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: Any, minimum: int, maximum: int) -> bytes:
    if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
        raise GuardError("Invalid sealed asset encoding or length")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeError, ValueError, binascii.Error):
        raise GuardError("Invalid sealed asset encoding or length") from None
    if not minimum <= len(raw) <= maximum or _encode(raw) != value:
        raise GuardError("Invalid sealed asset encoding or length")
    return raw


def seal_asset(plaintext: bytes, key: bytes, product: str, release: str,
               purpose: str, asset_id: str) -> dict[str, str]:
    """Encrypt at most 1 MiB of data under an external 32-byte master key.

    Both random values are generated internally; callers cannot supply a nonce
    or salt. The trusted context is required again to open the resulting data.
    """
    if type(plaintext) is not bytes or len(plaintext) > MAX_ASSET_BYTES:
        raise GuardError("Asset plaintext must be bytes of at most 1 MiB")
    master = _key(key)
    aad = _context(product, release, purpose, asset_id)
    salt = secrets.token_bytes(_SALT_BYTES)
    nonce = secrets.token_bytes(_NONCE_BYTES)
    ciphertext = AESGCM(_derive(master, salt, aad)).encrypt(nonce, plaintext, aad)
    return {"format": SEALED_FORMAT, "salt": _encode(salt),
            "nonce": _encode(nonce), "ciphertext": _encode(ciphertext)}


def open_asset(document: dict, key: bytes, product: str, release: str,
               purpose: str, asset_id: str) -> bytes:
    """Authenticate the whole package before returning any plaintext bytes.

    Wrong keys, substituted assets, changed context and tampering raise
    GuardError. The envelope cannot choose its own trusted context.
    """
    master = _key(key)
    aad = _context(product, release, purpose, asset_id)
    if (type(document) is not dict or any(type(name) is not str for name in document)
            or set(document) != _FIELDS):
        raise GuardError("Invalid sealed asset fields")
    if type(document["format"]) is not str or document["format"] != SEALED_FORMAT:
        raise GuardError("Unsupported sealed asset format")
    salt = _decode(document["salt"], _SALT_BYTES, _SALT_BYTES)
    nonce = _decode(document["nonce"], _NONCE_BYTES, _NONCE_BYTES)
    ciphertext = _decode(document["ciphertext"], _TAG_BYTES, MAX_ASSET_BYTES + _TAG_BYTES)
    try:
        return AESGCM(_derive(master, salt, aad)).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise GuardError("Cannot authenticate sealed asset") from None


def _key_path(value: Path | str) -> Path:
    if not isinstance(value, Path) and type(value) is not str:
        raise GuardError("Invalid asset key path")
    if not str(value) or "\x00" in str(value):
        raise GuardError("Invalid asset key path")
    return Path(value).absolute()


def generate_asset_key(path: Path | str) -> None:
    """Exclusively create a raw random 32-byte master-key file (mode 0600).

    Existing files or links are never overwritten. Parent directories must
    already exist and be trusted. Keep this file outside client releases.
    """
    destination = _key_path(path)
    try:
        write_new(destination, secrets.token_bytes(ASSET_KEY_BYTES), secret=True)
    except OSError:
        raise GuardError("Cannot create a new asset key file") from None


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        (getattr(info, "st_file_attributes", 0) or 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _identity(info: os.stat_result) -> tuple[int, ...]:
    # Cross-API identity only: Windows path stat and fstat can expose different
    # creation/change-time semantics. Compare timestamps within each API below.
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_size


def _stamp(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns,
            getattr(info, "st_file_attributes", 0) or 0)


def _check_key_file(info: os.stat_result) -> None:
    if (_is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode)
            or info.st_size != ASSET_KEY_BYTES):
        raise GuardError("Asset key must be an unchanged regular 32-byte file")


def load_asset_key(path: Path | str) -> bytes:
    """Read one bounded regular key file, rejecting links and identity changes.

    Where supported, each path component is opened relative to a directory
    descriptor with O_NOFOLLOW. Other platforms use lstat/fstat plus reparse
    and before/after identity checks; they cannot fully eliminate directory
    races. Ancestor directories must remain under trusted control.
    """
    destination = _key_path(path)
    directory_fd: int | None = None
    descriptor: int | None = None
    try:
        relative = (os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
                    and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"))
        flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0))
        if relative:
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            directory_fd = os.open(destination.anchor, directory_flags)
            for component in destination.parts[1:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            before = os.stat(destination.name, dir_fd=directory_fd, follow_symlinks=False)
        else:
            for parent in destination.parents:
                info = parent.lstat()
                if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
                    raise GuardError("Asset key directories must not be links")
            before = destination.lstat()
        _check_key_file(before)
        if directory_fd is None:
            descriptor = os.open(destination, flags)
        else:
            descriptor = os.open(destination.name, flags, dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        _check_key_file(opened)
        if _identity(before) != _identity(opened):
            raise GuardError("Asset key file changed while opening")
        data = bytearray()
        while len(data) <= ASSET_KEY_BYTES:
            block = os.read(descriptor, ASSET_KEY_BYTES + 1 - len(data))
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        final = (destination.lstat() if directory_fd is None else os.stat(
            destination.name, dir_fd=directory_fd, follow_symlinks=False,
        ))
        if (len(data) != ASSET_KEY_BYTES or _stamp(opened) != _stamp(after)
                or _stamp(before) != _stamp(final)):
            raise GuardError("Asset key file changed while reading")
        return bytes(data)
    except OSError:
        raise GuardError("Cannot load asset key from a regular unchanged file") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_fd is not None:
            os.close(directory_fd)
