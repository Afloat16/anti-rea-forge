"""Bounded recognition of directly recoverable key material in release data.

``scan_json_secrets`` consumes an already parsed JSON value.  It recognizes PEM
markers in decoded strings, exact configured asset keys in common string forms
and contiguous byte-array windows, and supported private JWK material.  Bounded
hex/Base64 strings whose decoded prefix identifies a private DER structure are
checked by the same DER reader. Wrapped private PEM markers are recognized
through a bounded streaming hint scan, including after leading text. DER and
PEM candidates and at most two additional JSON string-container decodes share
per-document count and decoded-byte budgets. It does not
execute JavaScript, evaluate expressions, or discover arbitrary application
secrets.  A finding contains only a fixed code/representation/kind or the index
of an operator-supplied key; no value, digest, JSON property name or path escapes.

``scan_der_private_key`` first checks a small ASN.1 prefix.  Only recognizable
private-key candidates are read, with a 64 KiB limit.  Public key/certificate
structures never enter the private-key decoder.  RSA arithmetic validation is
deliberately skipped: this is disclosure recognition, never permission to use a
key.  A recognized but undecodable or oversized private structure is reported as
unverifiable and must fail the caller's release gate.
"""

from __future__ import annotations

import base64
import binascii
import io
import json
import math
import re
from typing import Any, BinaryIO

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa, x25519, x448

from .core import MAX_DOCUMENT_BYTES, GuardError, _no_number, _pairs

MAX_JSON_SECRET_NODES = 100_000
MAX_JSON_SECRET_DEPTH = 64
MAX_DER_PRIVATE_KEY_BYTES = 64 * 1024
MAX_JSON_DER_CANDIDATES = 64
MAX_JSON_DER_DECODED_BYTES = 256 * 1024
MAX_JSON_STRINGIFIED_LAYERS = 2
MAX_JSON_STRINGIFIED_TEXT_BYTES = 64 * 1024
_DER_PREFIX_BYTES = 128
_BASE64_NOISE = re.compile(rb"[^A-Za-z0-9+/_-]")
_ASCII_FOLDING = str.maketrans("", "", " \t\r\n\v\f")
_MAX_JWK_FIELD_TEXT_BYTES = 32 * 1024
_MAX_ASSET_KEY_TEXT_CHARS = 32 * 1024
_MAX_ENCODED_DER_TEXT_CHARS = 256 * 1024
_PEM_HINT_CHARS = 32 * 1024
_JSON_CONTAINER_CLOSERS = {"{": "}", "[": "]", '"': '"'}
PEM_PRIVATE_KEY_MARKERS = (
    "-----BEGIN PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----",
)
_PEM_HEX_HINTS = tuple(marker.encode("ascii").hex() for marker in PEM_PRIVATE_KEY_MARKERS)
# Keep only sextets wholly inside a marker, for every possible byte alignment.
# A hint is not a finding: a bounded full decode must confirm the actual marker.
_PEM_BASE64_HINTS = tuple(
    base64.b64encode(bytes(shift) + marker.encode("ascii"))[
        (8 * shift + 5) // 6:(8 * (shift + len(marker))) // 6]
    for marker in PEM_PRIVATE_KEY_MARKERS for shift in range(3)
)
_PEM_HINT_OVERLAP = max(map(len, (*_PEM_HEX_HINTS, *_PEM_BASE64_HINTS))) - 1
_OKP_LENGTHS = {"Ed25519": 32, "X25519": 32, "Ed448": 57, "X448": 56}
_EC_CURVES = {"P-256": (32, ec.SECP256R1), "P-384": (48, ec.SECP384R1),
              "P-521": (66, ec.SECP521R1)}


def _consumer_base64_parts(value: str) -> tuple[bytes, bool]:
    """Normalize Node's bounded Base64 consumer representation, not JWK syntax.

    Node uses the low eight bits of each UTF-16 code unit, ignores nonalphabet
    bytes, and stops at the first padding byte. Encoding with surrogatepass
    models non-BMP and lone-surrogate JSON strings without executing JavaScript.
    Callers must bound the raw string before using this allocating helper.
    """
    units = value.encode("utf-16-le", errors="surrogatepass")[::2]
    head, padding, _ = units.partition(b"=")
    return _BASE64_NOISE.sub(b"", head), bool(padding)


def _consumer_base64_text(value: str) -> bytes:
    return _consumer_base64_parts(value)[0]


def _consumer_base64_bytes(encoded: bytes) -> bytes:
    # A dangling single sextet contributes no complete byte in Node's decoder.
    if len(encoded) % 4 == 1:
        encoded = encoded[:-1]
    return base64.b64decode(encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True)


def _asset_key_bytes(value: str) -> bytes | None:
    """Decode a whole 32-byte consumer key, or explicitly stop at its budget.

    Forty-four significant Base64 characters already produce at least 33
    bytes, so such ordinary long strings cannot be an exact 32-byte key. If
    the bounded prefix has fewer characters and no terminating padding, more
    ignored bytes may conceal a real key; that is incomplete inspection.
    """
    encoded, terminated = _consumer_base64_parts(value[:_MAX_ASSET_KEY_TEXT_CHARS])
    if len(encoded) >= 44:
        return None
    if len(value) > _MAX_ASSET_KEY_TEXT_CHARS and not terminated:
        raise GuardError("Known-key Base64 exceeds its raw inspection limit")
    decoded = _consumer_base64_bytes(encoded)
    return decoded if len(decoded) == 32 else None


def _jwk_bytes(value: Any, minimum: int, maximum: int, *, integer: bool = False) -> bytes | None:
    """Decode the bounded Base64 forms accepted by ordinary key consumers.

    JWK specifies unpadded Base64url, but Node's real key importer also accepts
    the classic alphabet, ignored bytes, padding and nonzero unused pad bits.
    This is disclosure recognition, not validation of a canonical JWK document.
    """
    if type(value) is not str or len(value) > _MAX_JWK_FIELD_TEXT_BYTES:
        return None
    encoded = _consumer_base64_text(value)
    # Leading zero bytes are ordinary integer aliases in RSA consumers. The
    # overall field bound remains in force before stripping those zero bytes.
    encoded_limit = 8192 if integer else maximum
    if not minimum * 4 // 3 <= len(encoded) <= (encoded_limit * 4 + 2) // 3 + 2:
        return None
    try:
        decoded = _consumer_base64_bytes(encoded)
    except (ValueError, binascii.Error):
        return None
    if integer:
        decoded = decoded.lstrip(b"\0")
    if not minimum <= len(decoded) <= maximum:
        return None
    return decoded


def _private_jwk_kind(value: dict[str, Any]) -> str | None:
    """Recognize recoverable private material in the declared JWK family.

    This is a bounded structural check, not mathematical key-pair validation.
    In particular, a disclosed private member remains sensitive if its public
    coordinates are missing or have been copied incorrectly.  Optional JWK
    metadata is allowed.  Supported private families exceeding a resource limit
    raise instead of being mistaken for a public JWK.
    """
    kind = value.get("kty")
    private_fields = ()
    if type(kind) is str and kind in {"oct", "OKP", "EC", "RSA"}:
        private_fields = ("k",) if kind == "oct" else ("d", "p", "q") if kind == "RSA" else ("d",)
        if any(type(value.get(field)) is str and (
                len(value[field]) > _MAX_JWK_FIELD_TEXT_BYTES
                or len(_consumer_base64_text(value[field])) > (8192 * 4 + 2) // 3 + 2)
               for field in private_fields):
            raise GuardError("Private JWK exceeds its field byte limit")
    if kind == "oct" and _jwk_bytes(value.get("k"), 1, 8192) is not None:
        return "oct"
    if kind == "OKP":
        length = _OKP_LENGTHS.get(value.get("crv")) if type(value.get("crv")) is str else None
        if length and _jwk_bytes(value.get("d"), length, length) is not None:
            return "OKP"
    elif kind == "EC":
        curve_spec = _EC_CURVES.get(value.get("crv")) if type(value.get("crv")) is str else None
        if curve_spec is not None:
            length, curve = curve_spec
            private = _jwk_bytes(value.get("d"), length, length)
            if private is not None:
                try:
                    # A bounded named-curve operation rejects an impossible
                    # scalar. Public coordinates cannot hide the private value.
                    ec.derive_private_key(int.from_bytes(private, "big"), curve())
                except (ValueError, UnsupportedAlgorithm):
                    pass
                else:
                    return "EC"
    elif kind == "RSA":
        if any(field in value for field in ("d", "p", "q")) and any(
            type(value.get(field)) is str and (len(value[field]) > _MAX_JWK_FIELD_TEXT_BYTES
                or len(_consumer_base64_text(value[field])) > (maximum * 4 + 2) // 3 + 2)
            for field, maximum in (("n", 2048), ("e", 8), ("d", 2048), ("p", 2048), ("q", 2048))
        ):
            raise GuardError("Private RSA JWK exceeds its field byte limit")
        # Both factors are sufficient private material even when public n/e or
        # private d are omitted. Recognize the bounded, decoded integer pair
        # without prime testing, multiplication or private-key reconstruction.
        # Incorrect public metadata must not hide independently disclosed p/q.
        p = _jwk_bytes(value.get("p"), 32, 2048, integer=True)
        q = _jwk_bytes(value.get("q"), 32, 2048, integer=True)
        if p is not None and q is not None and p != q and p[-1] & 1 and q[-1] & 1:
            return "RSA"
        modulus = _jwk_bytes(value.get("n"), 64, 2048, integer=True)
        exponent = _jwk_bytes(value.get("e"), 1, 8, integer=True)
        if modulus is not None and exponent is not None:
            n, e = int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")
            if n.bit_length() >= 512 and n % 2 == 1 and 3 <= e < n and e % 2 == 1:
                private = _jwk_bytes(value.get("d"), 1, len(modulus), integer=True)
                if private is not None and 1 < int.from_bytes(private, "big") < n:
                    return "RSA"
                for field in ("p", "q"):
                    factor = _jwk_bytes(value.get(field), 1, len(modulus), integer=True)
                    if factor is not None:
                        prime = int.from_bytes(factor, "big")
                        if 1 < prime < n and n % prime == 0:
                            return "RSA"
    if any(type(value.get(field)) is str and value[field] for field in private_fields):
        raise GuardError("Declared private JWK material could not be completely inspected")
    return None


def _asset_patterns(keys: tuple[bytes, ...]) -> tuple[tuple[str, ...], ...]:
    patterns = []
    for key in keys:
        encoded = {base64.b64encode(key).decode("ascii"), base64.urlsafe_b64encode(key).decode("ascii")}
        forms = {key.hex(), key.hex().upper(), key.decode("latin-1"),
                 *encoded, *(value.rstrip("=") for value in encoded)}
        try:
            forms.add(key.decode("utf-8"))
        except UnicodeError:
            pass
        patterns.append(tuple(sorted(forms)))
    return tuple(patterns)


def _encoded_der(value: str) -> tuple[str, bytes] | None:
    """Admit only whole hex/Base64 strings with a private ASN.1 prefix.

    Probe text, decoding and full candidates have separate limits. Large
    unrelated strings are never handed to a cryptographic parser. A private
    candidate or undecidable ignored prefix exceeding the text budget fails
    explicitly, so padding cannot postpone inspection beyond the raw bound.
    """
    sample = value[:_MAX_ENCODED_DER_TEXT_CHARS]
    compact = sample.translate(_ASCII_FOLDING)
    candidates = []
    if compact[:2].lower() == "30":
        probe_text = compact[:_DER_PREFIX_BYTES * 2]
        try:
            probe = binascii.unhexlify(probe_text[:len(probe_text) // 2 * 2])
        except (ValueError, binascii.Error):
            pass
        else:
            if _der_prefix_kind(probe) is not None:
                candidates.append("hex")
    encoded = _consumer_base64_text(sample)
    if encoded.startswith(b"M"):
        probe_text = encoded[:((_DER_PREFIX_BYTES + 2) // 3) * 4]
        try:
            probe = _consumer_base64_bytes(probe_text)
        except (ValueError, binascii.Error):
            pass
        else:
            if _der_prefix_kind(probe[:_DER_PREFIX_BYTES]) is not None:
                candidates.append("base64")
    if not candidates:
        if len(value) > _MAX_ENCODED_DER_TEXT_CHARS and len(encoded) < ((_DER_PREFIX_BYTES + 2) // 3) * 4:
            raise GuardError("Encoded key text exceeds its raw inspection limit")
        return None
    if len(value) > _MAX_ENCODED_DER_TEXT_CHARS:
        raise GuardError("Encoded private DER exceeds its raw text limit")
    encoding = candidates[0]
    maximum = MAX_DER_PRIVATE_KEY_BYTES * 2 if encoding == "hex" else (MAX_DER_PRIVATE_KEY_BYTES * 4 + 2) // 3 + 2
    if len(compact if encoding == "hex" else encoded) > maximum:
        raise GuardError("Encoded private DER exceeds its decoded byte limit")
    try:
        if encoding == "hex":
            data = binascii.unhexlify(compact)
        else:
            data = _consumer_base64_bytes(encoded)
    except (ValueError, binascii.Error):
        raise GuardError("Recognized private DER has an invalid outer encoding") from None
    if len(data) > MAX_DER_PRIVATE_KEY_BYTES:
        raise GuardError("Encoded private DER exceeds its decoded byte limit")
    return encoding, data


def _encoded_pem(value: str) -> tuple[str, bytes] | None:
    """Find one outer hex/Base64 wrapper without decoding unrelated payloads.

    PEM readers can accept leading notes, so a prefix-only probe is insufficient.
    Scan hints across the whole JSON-bounded string with constant-size tails.
    Large unrelated data remains allowed; a recognized candidate outside the
    smaller decode budget fails explicitly. No nested encoding is evaluated.
    """
    if len(value) > MAX_DOCUMENT_BYTES:
        raise GuardError("Encoded PEM inspection exceeds the JSON text limit")
    hex_tail, b64_tail = "", b""
    hex_candidate = b64_candidate = b64_terminated = False
    for offset in range(0, len(value), _PEM_HINT_CHARS):
        chunk = value[offset:offset + _PEM_HINT_CHARS]
        if not hex_candidate:
            window = hex_tail + chunk.translate(_ASCII_FOLDING).lower()
            hex_candidate = any(hint in window for hint in _PEM_HEX_HINTS)
            hex_tail = window[-_PEM_HINT_OVERLAP:]
        if not b64_candidate and not b64_terminated:
            normalized, b64_terminated = _consumer_base64_parts(chunk)
            window = b64_tail + normalized.replace(b"-", b"+").replace(b"_", b"/")
            b64_candidate = any(hint in window for hint in _PEM_BASE64_HINTS)
            b64_tail = window[-_PEM_HINT_OVERLAP:]
        if hex_candidate or b64_candidate:
            break
    if not (hex_candidate or b64_candidate):
        return None
    if len(value) > _MAX_ENCODED_DER_TEXT_CHARS:
        raise GuardError("Encoded private PEM exceeds its raw text limit")
    encoding = "hex" if hex_candidate else "base64"
    encoded = value.translate(_ASCII_FOLDING) if hex_candidate else _consumer_base64_text(value)
    maximum = MAX_DER_PRIVATE_KEY_BYTES * 2 if hex_candidate else (MAX_DER_PRIVATE_KEY_BYTES * 4 + 2) // 3 + 2
    if len(encoded) > maximum:
        raise GuardError("Encoded private PEM exceeds its decoded byte limit")
    try:
        data = binascii.unhexlify(encoded) if hex_candidate else _consumer_base64_bytes(encoded)
    except (ValueError, binascii.Error):
        raise GuardError("Recognized private PEM has an invalid outer encoding") from None
    if len(data) > MAX_DER_PRIVATE_KEY_BYTES:
        raise GuardError("Encoded private PEM exceeds its decoded byte limit")
    # Charge every actual decode to the shared budget, even when the hint was
    # an alignment coincidence. The caller confirms markers before reporting.
    return encoding, data


def _stringified_container(value: str) -> bool:
    """Recognize only complete-looking JSON object, array or string envelopes.

    Ordinary text never enters the JSON parser. Invalid template text within a
    small envelope can be rejected as syntax without becoming a finding. The
    caller charges every attempted parse, including invalid syntax, and treats
    an oversized or overdeep recognizable envelope as incomplete inspection.
    JSON whitespace is deliberately narrower than Python's Unicode whitespace.
    """
    first, last = 0, len(value) - 1
    while first <= last and value[first] in " \t\r\n":
        first += 1
    if first >= last:
        return False
    opener = value[first]
    closer = _JSON_CONTAINER_CLOSERS.get(opener)
    if closer is None:
        return False
    while last > first and value[last] in " \t\r\n":
        last -= 1
    if value[last] != closer:
        return False
    if opener == '"' and last == first + 1:
        return False  # An empty string cannot contain structured private data.
    if opener != '"':
        position = first + 1
        while position < last and value[position] in " \t\r\n":
            position += 1
        if position == last:
            # Empty object/array envelopes are conclusive without JSON parsing.
            # Do not exhaust the decode budget on ordinary empty placeholders.
            return False
        # Most brace-delimited templates are plainly not JSON containers. The
        # first member/value token is enough to avoid parsing those strings.
        allowed = '"}' if opener == "{" else '{["-0123456789tfnNI]'
        if value[position] not in allowed:
            return False
    return True


def _stringified_json(value: str) -> Any:
    """Parse one already bounded container with the outer JSON number rules."""
    def finite_float(text: str) -> float:
        number = float(text)
        if not math.isfinite(number):
            raise ValueError("Non-finite JSON number")
        return number

    try:
        return json.loads(value, object_pairs_hook=_pairs, parse_constant=_no_number,
                          parse_float=finite_float)
    except json.JSONDecodeError:
        return None
    except (ValueError, RecursionError):
        # Neither a duplicate field name nor a numeric token may enter reports.
        raise GuardError("Stringified JSON is ambiguous or exceeds its parse profile") from None


def scan_json_secrets(document: Any, *, asset_keys: tuple[bytes, ...] = (),
                      check_private_keys: bool = True) -> list[dict[str, Any]]:
    """Inspect a bounded parsed JSON tree and return non-secret finding records.

    The caller owns the outer JSON decoding, its byte limit and duplicate-member
    policy. Up to two additional JSON string-container decodes use the same
    strict member/finite-number rules. They share count/byte budgets with DER
    and PEM decoding, and all parsed nodes share the node/depth limits, including
    cycles passed by a direct Python caller. Invalid/unbounded input raises
    ``GuardError``.
    """
    if (type(asset_keys) is not tuple or len(asset_keys) > 16
            or any(type(key) is not bytes or len(key) != 32 for key in asset_keys)
            or type(check_private_keys) is not bool):
        raise GuardError("Invalid structured secret scan configuration")
    patterns = _asset_patterns(asset_keys)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, Any]] = set()

    def add(code: str, identity: Any, *, stringified_layers: int = 0, **details: Any) -> None:
        if stringified_layers:
            representation = details["representation"]
            details["representation"] = "json-stringified-" + representation.removeprefix("json-")
            details["stringified_layers"] = stringified_layers
            identity = (stringified_layers, identity)
        if (code, identity) not in seen:
            seen.add((code, identity))
            findings.append({"code": code, **details})

    pending = [(document, 0, 0)]
    visited = 0
    encoded_candidates = decoded_private_bytes = 0

    def charge_decode(size: int) -> None:
        nonlocal encoded_candidates, decoded_private_bytes
        encoded_candidates += 1
        decoded_private_bytes += size
        # The historical constant names are retained for callers, but all
        # structured string decodes use this one per-document resource budget.
        if (encoded_candidates > MAX_JSON_DER_CANDIDATES
                or decoded_private_bytes > MAX_JSON_DER_DECODED_BYTES):
            raise GuardError("Encoded private material exceeds the JSON decode budget")

    while pending:
        value, depth, stringified_layers = pending.pop()
        visited += 1
        if visited > MAX_JSON_SECRET_NODES or depth > MAX_JSON_SECRET_DEPTH:
            raise GuardError("Structured secret JSON exceeds its node or depth limit")
        if type(value) is dict:
            if visited + len(value) > MAX_JSON_SECRET_NODES:
                raise GuardError("Structured secret JSON exceeds its node or depth limit")
            if any(type(key) is not str for key in value):
                raise GuardError("Structured secret scan requires parsed JSON members")
            visited += len(value)
            if visited > MAX_JSON_SECRET_NODES:
                raise GuardError("Structured secret JSON exceeds its node or depth limit")
            if check_private_keys:
                kind = _private_jwk_kind(value)
                if kind is not None:
                    add("private_key_structure", kind, representation="jwk", kind=kind,
                        stringified_layers=stringified_layers)
            # Keys themselves can carry leaked material. They are scanned as
            # data without ever being copied into the finding record.
            pending.extend((key, depth + 1, stringified_layers) for key in value)
            pending.extend((item, depth + 1, stringified_layers) for item in value.values())
        elif type(value) is list:
            if visited + len(value) > MAX_JSON_SECRET_NODES:
                raise GuardError("Structured secret JSON exceeds its node or depth limit")
            if asset_keys:
                # JSON has one number type: 1, 1.0 and 1e0 describe the same
                # byte. Recognize contiguous integer-valued uint8 runs without
                # coercing strings/bools, wrapping negatives or truncating floats.
                run = bytearray()

                def inspect_run() -> None:
                    if len(run) >= 32:
                        for index, key in enumerate(asset_keys):
                            if key in run:
                                add("asset_key_exposure", index, representation="json-byte-array", rule_index=index,
                                    stringified_layers=stringified_layers)
                    run.clear()

                for item in value:
                    if (type(item) in (int, float) and 0 <= item <= 255
                            and (type(item) is int or item.is_integer())):
                        run.append(int(item))
                    else:
                        inspect_run()
                inspect_run()
            pending.extend((item, depth + 1, stringified_layers) for item in value)
        elif type(value) is str:
            if (check_private_keys or asset_keys) and _stringified_container(value):
                if stringified_layers >= MAX_JSON_STRINGIFIED_LAYERS:
                    raise GuardError("Stringified JSON exceeds its decode layer limit")
                # Bound characters before the allocating UTF-8 size check.
                if len(value) > MAX_JSON_STRINGIFIED_TEXT_BYTES:
                    raise GuardError("Stringified JSON exceeds its raw text limit")
                size = len(value.encode("utf-8", errors="surrogatepass"))
                if size > MAX_JSON_STRINGIFIED_TEXT_BYTES:
                    raise GuardError("Stringified JSON exceeds its raw text limit")
                charge_decode(size)
                nested = _stringified_json(value)
                if nested is not None:
                    pending.append((nested, depth + 1, stringified_layers + 1))
            if check_private_keys:
                for index, marker in enumerate(PEM_PRIVATE_KEY_MARKERS):
                    if marker in value:
                        add("private_key_marker", index, representation="json-decoded-string", rule_index=index,
                            stringified_layers=stringified_layers)
            compact = value.translate(_ASCII_FOLDING) if asset_keys else value
            folded_hex = compact.lower() if asset_keys else ""
            decoded_key = _asset_key_bytes(value) if asset_keys else None
            for index, forms in enumerate(patterns):
                if (any(form in value or form in compact for form in forms)
                        or asset_keys[index].hex() in folded_hex or decoded_key == asset_keys[index]):
                    add("asset_key_exposure", index, representation="json-decoded-string", rule_index=index,
                        stringified_layers=stringified_layers)
            if check_private_keys:
                encoded = _encoded_der(value)
                kind = "der"
                if encoded is None:
                    encoded = _encoded_pem(value)
                    kind = "pem"
                if encoded is not None:
                    encoding, data = encoded
                    charge_decode(len(data))
                    if kind == "pem":
                        for index, marker in enumerate(PEM_PRIVATE_KEY_MARKERS):
                            if marker.encode("ascii") in data:
                                representation = "json-" + encoding + "-pem"
                                add("private_key_marker", (representation, index),
                                    representation=representation, rule_index=index,
                                    stringified_layers=stringified_layers)
                        continue
                    for finding in scan_der_private_key(io.BytesIO(data), len(data)):
                        details = {key: item for key, item in finding.items() if key != "code"}
                        details["representation"] = "json-" + encoding + "-" + details["representation"]
                        add(finding["code"], (details["representation"], details.get("kind"), details.get("reason")),
                            stringified_layers=stringified_layers, **details)
        elif value is not None and type(value) not in (bool, int, float):
            raise GuardError("Structured secret scan requires parsed JSON data")
    return findings


def _der_header(data: bytes, offset: int) -> tuple[int, int, int]:
    """Read a canonical single-octet DER tag/length without reading its value."""
    if offset < 0 or len(data) - offset < 2 or data[offset] & 31 == 31:
        raise ValueError("Invalid DER header")
    tag, length = data[offset], data[offset + 1]
    position = offset + 2
    if length >= 128:
        count = length & 127
        if count == 0 or count > 4 or len(data) - position < count or data[position] == 0:
            raise ValueError("Invalid DER length")
        length = int.from_bytes(data[position:position + count], "big")
        position += count
        if length < 128:
            raise ValueError("Noncanonical DER length")
    return tag, position, position + length


def _der_prefix_kind(prefix: bytes) -> tuple[str, int] | None:
    try:
        tag, start, end = _der_header(prefix, 0)
        if tag != 0x30:
            return None
        tag, version_start, version_end = _der_header(prefix, start)
        if (tag != 0x02 or version_end - version_start != 1 or version_end > len(prefix)
                or prefix[version_start] not in (0, 1)):
            return None
        version = prefix[version_start]
        next_tag, next_start, _ = _der_header(prefix, version_end)
        if next_tag == 0x30 and next_start < len(prefix) and prefix[next_start] == 0x06:
            return "pkcs8", end
        if next_tag == 0x02 and version in (0, 1):
            return "traditional", end
        if next_tag == 0x04 and version == 1:
            return "sec1", end
    except ValueError:
        pass
    return None


def _der_fields(data: bytes) -> list[tuple[int, int, int]]:
    _, position, end = _der_header(data, 0)
    if end != len(data):
        raise ValueError("DER outer length does not match")
    fields = []
    while position < end:
        if len(fields) >= 16:
            raise ValueError("DER field limit")
        field = _der_header(data, position)
        if field[2] > end:
            raise ValueError("DER field exceeds container")
        fields.append(field)
        position = field[2]
    return fields


def _der_private_shape(data: bytes, kind: str) -> bool:
    fields = _der_fields(data)
    tags = [field[0] for field in fields]
    if kind == "pkcs8":
        return tags[:3] == [0x02, 0x30, 0x04] and 3 <= len(tags) <= 5 and all(
            tag in (0xA0, 0xA1, 0x81) for tag in tags[3:]
        )
    if kind == "sec1":
        return tags[:3] == [0x02, 0x04, 0xA0] and tags[3:] in ([], [0xA1])
    # Traditional RSA and DSA have nine and six INTEGER fields respectively.
    # Multi-prime RSA adds an OtherPrimeInfos SEQUENCE after the nine integers.
    return tags in ([0x02] * 6, [0x02] * 9, [0x02] * 9 + [0x30])


def scan_der_private_key(stream: BinaryIO, size: int) -> list[dict[str, Any]]:
    """Recognize a standalone unencrypted private DER key with bounded reads.

    ASN.1 containers unrelated to private-key shapes and public DER pass through.
    This does not search for DER embedded at arbitrary offsets or decode encrypted
    PKCS8.  ``structured_secret_unverifiable`` is a failing inspection result.
    """
    if type(size) is not int or size < 0:
        raise GuardError("Invalid structured secret payload size")
    stream.seek(0)
    prefix = stream.read(min(size, _DER_PREFIX_BYTES))
    if len(prefix) != min(size, _DER_PREFIX_BYTES):
        raise GuardError("Structured secret payload changed while reading")
    candidate = _der_prefix_kind(prefix)
    if candidate is None:
        return []
    kind, declared_end = candidate

    def unverifiable(reason: str) -> list[dict[str, Any]]:
        return [{"code": "structured_secret_unverifiable", "representation": "der-private-key",
                 "reason": reason}]

    if size > MAX_DER_PRIVATE_KEY_BYTES:
        return unverifiable("der_byte_limit")
    if declared_end != size:
        return unverifiable("der_length_mismatch")
    stream.seek(0)
    data = stream.read(size + 1)
    if len(data) != size:
        raise GuardError("Structured secret payload changed while reading")
    try:
        if not _der_private_shape(data, kind):
            return []
    except ValueError:
        return unverifiable("der_structure_invalid")
    try:
        private = serialization.load_der_private_key(data, password=None, unsafe_skip_rsa_key_validation=True)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return unverifiable("der_private_key_invalid")
    key_kinds = ((rsa.RSAPrivateKey, "RSA"), (dsa.DSAPrivateKey, "DSA"),
                 (ec.EllipticCurvePrivateKey, "EC"), (ed25519.Ed25519PrivateKey, "Ed25519"),
                 (ed448.Ed448PrivateKey, "Ed448"), (x25519.X25519PrivateKey, "X25519"),
                 (x448.X448PrivateKey, "X448"))
    for key_type, key_kind in key_kinds:
        if isinstance(private, key_type):
            return [{"code": "private_key_structure", "representation": "der-" + kind,
                     "kind": key_kind}]
    return unverifiable("der_private_key_unsupported")
