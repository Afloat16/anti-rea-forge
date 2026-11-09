"""Split loose external source maps before compression and publication.

Build-only, for trusted immutable build trees and trusted output parents. Deploy
only after success: two directories on different volumes cannot be published as
one atomic operation. No target code is run, rewritten, fetched or linked.
"""

from __future__ import annotations

import codecs
from contextlib import ExitStack
import hashlib
import itertools
import json
import os
from pathlib import Path
import stat
import tempfile
import unicodedata

from .core import (
    GuardError, MAX_DOCUMENT_BYTES, MAX_ENTRIES, _inventory, _is_link, _no_number, _pairs,
    _root, safe_relative_path, write_new,
)
from .distribution import scan_release
from .native import _assert_scanned_identity

_MAX_FILE = 64 << 20
_MAX_TOTAL = 256 << 20
_MAX_SOURCES = 100_000
_DIGITS = {c: i for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}
_POLICY = {"version": 1, "scan_zip_archives": False,
           "forbid_extensions": [".map", ".pdb", ".ilk", ".br", ".gzip", ".zstd"]}


def _destination(path: Path | str) -> Path:
    path = Path(path).absolute()
    safe_relative_path(path.name)
    dest = _root(path.parent) / path.name
    try:
        dest.lstat()
    except FileNotFoundError:
        return dest
    raise GuardError(f"Output must be a new directory: {dest}")


def _portable_identity(path: Path) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in path.parts)


def _read(path: Path, remaining: int):
    before = path.lstat()
    if _is_link(before) or not stat.S_ISREG(before.st_mode):
        raise GuardError("Split input must remain a regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if _is_link(opened) or not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev, opened.st_ino, opened.st_size
        ) != (before.st_dev, before.st_ino, before.st_size):
            raise GuardError("Split input changed before copying")
        if opened.st_size > min(remaining, _MAX_FILE):
            raise GuardError("Split input exceeds its file or total byte budget")
        data = stream.read(opened.st_size + 1)
    identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
    if len(data) != opened.st_size:
        raise GuardError("Split input size changed while copying")
    _assert_scanned_identity(path, identity, "Split input")
    return data, identity, stat.S_IMODE(opened.st_mode) & 0o777


def _json_candidate(data: bytes):
    # Check JSON objects regardless of file extension, including escaped keys,
    # BOMs and the commonly used UTF-8 XSSI header. Do not parse arbitrary JS.
    probe = data
    for bom in (codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE, codecs.BOM_UTF16_LE,
                codecs.BOM_UTF16_BE, codecs.BOM_UTF8):
        if probe.startswith(bom):
            probe = probe[len(bom):]
            break
    if probe.startswith(b")]}'"):
        _, separator, data = probe.partition(b"\n")
        if not separator:
            return None
        probe = data
    if not probe.lstrip(b" \t\r\n\x00").startswith(b"{"):
        return None
    if len(data) > MAX_DOCUMENT_BYTES:
        raise GuardError("JSON-like split input exceeds the 8 MiB inspection limit")
    try:
        value = json.loads(data, object_pairs_hook=_pairs, parse_constant=_no_number)
    except (json.JSONDecodeError, UnicodeError):
        return None  # e.g. JavaScript whose first token is a block
    except (RecursionError, ValueError) as exc:
        raise GuardError("Ambiguous, deeply nested or oversized JSON in split input") from exc
    return value if isinstance(value, dict) else None


def _validate_mappings(text: str, sources: int, names: int) -> None:
    """Check the flat-map segment shape, bounded VLQs and referenced indexes."""
    number = shift = generated = source = line = column = name = 0
    fields: list[int] = []
    after_comma = False
    for char in itertools.chain(text, ";"):
        if char not in ",;":
            digit = _DIGITS.get(char)
            if digit is None:
                raise GuardError("Invalid source-map VLQ character")
            number |= (digit & 31) << shift
            if number > 0xffffffff or shift > 30:
                raise GuardError("Source-map VLQ exceeds the 32-bit profile")
            if digit & 32:
                shift += 5
            else:
                # ECMA-426 VLQSignedValue: the negative zero code denotes INT32_MIN.
                value = -(number >> 1) if number & 1 else number >> 1
                fields.append(-(1 << 31) if number == 1 else value)
                number = shift = 0
                if len(fields) > 5:
                    raise GuardError("Too many source-map segment fields")
            after_comma = False
            continue
        if shift or (not fields and (char == "," or after_comma)) or len(fields) not in (0, 1, 4, 5):
            raise GuardError("Invalid or truncated source-map segment")
        if fields:
            generated += fields[0]
            if generated < 0:
                raise GuardError("Negative generated source-map column")
        if len(fields) >= 4:
            source += fields[1]
            line += fields[2]
            column += fields[3]
            if not 0 <= source < sources or line < 0 or column < 0:
                raise GuardError("Source-map original position is out of range")
        if len(fields) == 5:
            name += fields[4]
            if not 0 <= name < names:
                raise GuardError("Source-map name index is out of range")
        if char == ";":
            generated = 0
        after_comma = char == ","
        fields.clear()


def _source_digests(doc: dict | None, path: str) -> set[str]:
    if not doc or type(doc.get("version")) is not int or doc["version"] != 3 or "sections" in doc:
        raise GuardError(f"Expected a flat v3 external source map: {path}")
    sources, names, mappings = doc.get("sources"), doc.get("names", []), doc.get("mappings")
    if (not isinstance(sources, list) or not sources or len(sources) > _MAX_SOURCES
            or any(not isinstance(x, str) for x in sources)
            or not isinstance(names, list) or len(names) > _MAX_SOURCES
            or any(not isinstance(x, str) for x in names) or not isinstance(mappings, str)):
        raise GuardError(f"Invalid or oversized source-map structure: {path}")
    _validate_mappings(mappings, len(sources), len(names))
    contents = doc.get("sourcesContent")
    if contents is None:
        return set()
    if (not isinstance(contents, list) or len(contents) != len(sources)
            or any(x is not None and not isinstance(x, str) for x in contents)):
        raise GuardError(f"Invalid source-map sourcesContent: {path}")
    try:
        return {hashlib.sha256(x.encode("utf-8")).hexdigest() for x in contents if x}
    except UnicodeError as exc:
        raise GuardError(f"Source map contains invalid Unicode source text: {path}") from exc


def _unlink_created(path: Path) -> None:
    if os.name == "nt" and path.exists():
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
    path.unlink(missing_ok=True)


def split_source_maps(root: Path | str, public: Path | str, private: Path | str) -> dict:
    """Create fresh public assets and private maps; never mutate or run inputs.

    Policy findings return ok=False with no retained outputs; invalid input,
    size limits, collisions and I/O failures raise. Regular flat v3 external
    maps only. Compression, serving headers, old CDN objects, remote maps and
    deployed access control must be handled separately.
    """
    source, published, symbols = _root(root), _destination(public), _destination(private)
    keys = [_portable_identity(p) for p in (source, published, symbols)]
    if any(a == b[:len(a)] or b == a[:len(b)] for a, b in itertools.combinations(keys, 2)):
        raise GuardError("Input, public and private directories must be disjoint")
    inventory = _inventory(source)
    maps = {p for p in inventory if p.casefold().endswith(".map")}
    if not maps or len(maps) == len(inventory):
        raise GuardError("Need a public artifact and at least one external .map file")
    report = {"ok": False, "public_root": str(published), "private_root": str(symbols),
              "public_files": 0, "private_maps": 0, "findings": []}
    public_digests: dict[str, str] = {}
    source_digests: set[str] = set()
    identities = {}
    findings = report["findings"]
    remaining = _MAX_TOTAL

    with ExitStack() as rollback:
        made: set[Path] = set()

        def directory(path: Path, mode: int):
            if path in made:
                return
            path.mkdir(mode=mode)  # exclusive: never reuse an existing directory
            rollback.callback(path.rmdir)
            made.add(path)

        def parents(base: Path, relative: Path, mode: int):
            current = base
            for part in relative.parts:
                current /= part
                directory(current, mode)

        directory(published, 0o700)
        directory(symbols, 0o700)
        for relative, path in sorted(inventory.items()):
            data, identity, mode = _read(path, remaining)
            remaining -= len(data)
            identities[path] = identity
            doc = _json_candidate(data)
            secret = relative in maps
            if secret:
                source_digests.update(_source_digests(doc, relative))
                if len(source_digests) > _MAX_SOURCES:
                    raise GuardError("Too many distinct embedded source files")
            else:
                if doc and doc.get("version") == 3 and (
                    "sections" in doc or ("sources" in doc and "mappings" in doc)
                ):
                    findings.append({"code": "disguised_source_map", "path": relative})
                public_digests[relative] = hashlib.sha256(data).hexdigest()
            base = symbols if secret else published
            parents(base, Path(relative).parent, 0o700)
            destination = base / relative
            write_new(destination, data, secret=secret)
            rollback.callback(_unlink_created, destination)
            if not secret and os.name == "posix":
                os.chmod(destination, mode)

        # Preserve deliberately empty input directories (runtime/plugin mount points).
        # Directories that contain only private maps do not need public counterparts.
        entries_seen = 0
        for parent, children, filenames in os.walk(source):
            entries_seen += len(children) + len(filenames)
            if entries_seen > MAX_ENTRIES:
                raise GuardError("Too many split input entries")
            if not children and not filenames:
                parents(published, Path(parent).relative_to(source), 0o700)

        findings.extend({"code": "embedded_source_copy", "path": path}
                        for path, digest in public_digests.items() if digest in source_digests)
        # Scan the actual, complete public output, not merely the input manifest.
        # A temporary fixed policy is outside every output; callers can't disable it.
        with tempfile.TemporaryDirectory(dir=published.parent, prefix=".split-policy-") as temp:
            policy = Path(temp) / "policy.json"
            write_new(policy, json.dumps(_POLICY).encode("ascii"))
            scan = scan_release(published, policy)
        findings.extend(scan["findings"])
        if public_digests != {f["path"]: f["sha256"] for f in scan["files"]}:
            raise GuardError("Public files changed between copying and verification")
        if set(inventory) != set(_inventory(source)):
            raise GuardError("Split input inventory changed")
        for path, identity in identities.items():
            _assert_scanned_identity(path, identity, "Split input")
        if findings:
            return report
        if os.name == "posix":
            # Change child directories before their parents, and the public root
            # last. Reverse-order rollback restores owner access before any
            # unlink/rmdir, even when a source directory is read-only.
            directories = sorted((p for p in made if p.is_relative_to(published)),
                                 key=lambda p: len(p.parts), reverse=True)
            for destination in directories:
                info = (source / destination.relative_to(published)).lstat()
                if _is_link(info) or not stat.S_ISDIR(info.st_mode):
                    raise GuardError("Public source directory changed during splitting")
                rollback.callback(os.chmod, destination, 0o700)
                os.chmod(destination, stat.S_IMODE(info.st_mode) & 0o777)
        rollback.pop_all()
    return {**report, "ok": True, "public_files": len(public_digests),
            "private_maps": len(maps), "source_bytes_read": _MAX_TOTAL - remaining,
            "public_bytes_unchanged": True, "public_scan": scan["checks"]}
