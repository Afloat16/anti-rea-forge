"""Bounded exact configured-key patterns in recognized CPython PYC payloads.

A 32-byte asset key can be stored as a Python integer, then reconstructed with
``int.to_bytes(32, byteorder, signed=...)``. Its canonical marshal LONG encoding
contains neither the original bytes nor their hexadecimal/Base64 text. This
reader generates that encoding for the four signed/unsigned, big/little-endian
interpretations of each configured key and searches for both reference-flag
forms. It never unmarshals code objects, walks a reference graph, or executes
the examined input.

This is an exact-pattern inspection profile, not general marshal validation,
decompilation protection, or proof that a program contains no secret. A match
can also occur inside another marshalled value; it still exposes the configured
integer representation. Noncanonical integers, computed/split constants,
other encodings, unknown keys, and arbitrary application logic are outside the
profile. Code, names, filenames, ordinary constants, and behavior are unchanged.

Only recognized CPython 3 framing enters the scan. CR LF plus a magic number in
3000..3999 identifies a candidate; unsupported magics, invalid/truncated headers,
short integer aliases, and resource limits raise ``GuardError``. Other prefixes
return ``None``. The supported stable magics use a 16-byte PEP 552 header and
canonical base-2**15 marshal LONG records. Header acceptance does not validate
the code-object body or make a different Python version executable locally.

Every configured key interpretation must have at least 128 significant bits.
Short integer encodings are too ambiguous for this pattern-only profile, so
they produce incomplete inspection rather than a false claim of full coverage.
Reports contain only fixed metadata and configured-key indexes; no key, key
digest, integer value, source name, or byte offset is returned.
"""

from __future__ import annotations

from typing import Any, BinaryIO

from .core import GuardError

MAX_PYC_SCAN_BYTES = 64 * 1024 * 1024
MAX_PYC_ASSET_KEYS = 16
MIN_PYC_KEY_INTEGER_BITS = 128
_CHUNK_BYTES = 64 * 1024
_PROFILE = "canonical-marshal-integer/v1"
_STABLE_MAGICS = {
    3394: "3.7", 3413: "3.8", 3425: "3.9", 3439: "3.10",
    3495: "3.11", 3531: "3.12", 3571: "3.13", 3627: "3.14",
}


def _read_at_most(stream: BinaryIO, length: int) -> bytes:
    """Allow short reads without accepting an over-reading/invalid stream."""
    parts = bytearray()
    while len(parts) < length:
        remaining = length - len(parts)
        part = stream.read(remaining)
        if not isinstance(part, bytes) or len(part) > remaining:
            raise GuardError("PYC inspection requires a bounded binary stream")
        if not part:
            break
        parts.extend(part)
    return bytes(parts)


def _key_patterns(key: bytes) -> tuple[bytes, ...]:
    integers = {int.from_bytes(key, byteorder, signed=signed)
                for byteorder in ("big", "little") for signed in (False, True)}
    if any(abs(integer).bit_length() < MIN_PYC_KEY_INTEGER_BITS for integer in integers):
        raise GuardError("PYC configured key has a short integer representation outside the inspection profile")
    patterns = set()
    for integer in integers:
        value = abs(integer)
        digits = bytearray()
        while value:
            digits.extend((value & 0x7fff).to_bytes(2, "little"))
            value >>= 15
        count = len(digits) // 2
        record = (count if integer > 0 else -count).to_bytes(4, "little", signed=True) + digits
        # Marshal v0-v2 emits an ordinary LONG; v3+ can add FLAG_REF. A later
        # TYPE_REF needs an earlier definition, which contains this same record.
        patterns.add(b"l" + record)
        patterns.add(b"\xec" + record)
    return tuple(sorted(patterns))


def scan_pyc_asset_keys(stream: BinaryIO, file_size: int, *,
                        asset_keys: tuple[bytes, ...]) -> dict[str, Any] | None:
    """Scan a seekable PYC stream for canonical configured-key integer records.

    A returned object means this bounded exact-pattern profile completed. The
    caller must report ``GuardError`` as incomplete inspection, never as an
    absent key. ``None`` means the prefix is outside CPython 3 candidate framing.
    The caller owns the input snapshot and checks any other secret encodings.
    """
    if (type(file_size) is not int or file_size < 0
            or type(asset_keys) is not tuple or len(asset_keys) > MAX_PYC_ASSET_KEYS
            or any(type(key) is not bytes or len(key) != 32 for key in asset_keys)):
        raise GuardError("Invalid PYC asset-key inspection arguments")
    try:
        stream.seek(0)
        prefix = _read_at_most(stream, 4)
        if len(prefix) != 4 or prefix[2:] != b"\r\n":
            return None
        magic = int.from_bytes(prefix[:2], "little")
        if not 3000 <= magic <= 3999:
            return None
        if magic not in _STABLE_MAGICS:
            raise GuardError("PYC magic is outside the supported stable inspection profiles")
        if file_size > MAX_PYC_SCAN_BYTES:
            raise GuardError("PYC payload exceeds its exact-pattern inspection byte limit")
        if file_size < 17:
            raise GuardError("PYC header or code-object tag is truncated")
        header = prefix + _read_at_most(stream, 13)
        if len(header) != 17:
            raise GuardError("PYC header or code-object tag is truncated")
        # CPython classifies only bits 0 and 1: flags=2 is accepted as a
        # timestamp-based header even though ordinary writers emit 0, 1 or 3.
        if int.from_bytes(header[4:8], "little") & ~3:
            raise GuardError("PYC header flags are outside the inspection profile")
        if header[16] not in (ord("c"), ord("c") | 0x80):
            raise GuardError("PYC payload does not start with a canonical code-object tag")
        patterns = tuple(_key_patterns(key) for key in asset_keys)
        overlap = max((len(pattern) for group in patterns for pattern in group), default=1) - 1
        seen: set[int] = set()
        total = len(header)
        tail = header[16:]
        while True:
            request = min(_CHUNK_BYTES, file_size - total + 1)
            chunk = stream.read(request)
            if not isinstance(chunk, bytes) or len(chunk) > request:
                raise GuardError("PYC inspection requires a bounded binary stream")
            if not chunk:
                break
            total += len(chunk)
            if total > file_size:
                raise GuardError("PYC payload grew during exact-pattern inspection")
            window = tail + chunk
            for index, group in enumerate(patterns):
                if index not in seen and any(pattern in window for pattern in group):
                    seen.add(index)
            tail = window[-overlap:] if overlap else b""
        if total != file_size:
            raise GuardError("PYC payload size changed during exact-pattern inspection")
    except GuardError:
        raise
    except (OSError, ValueError, OverflowError) as exc:
        raise GuardError("Cannot read PYC payload for exact-pattern inspection") from exc
    return {
        "format": "cpython-pyc", "profile": _PROFILE,
        "magic": magic, "python_version": _STABLE_MAGICS[magic],
        "bytes_scanned": total, "keys_checked": len(asset_keys),
        "full_marshal_validation_performed": False,
        "findings": [{"code": "asset_key_exposure", "rule_index": index,
                      "representation": "python-marshal-integer"} for index in sorted(seen)],
    }
