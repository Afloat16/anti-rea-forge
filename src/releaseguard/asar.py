"""Bounded Electron ASAR index and integrity inspection, without extraction.

The canonical Pickle layout and member offsets follow electron/asar disk.ts.
Unpacked entries require an explicit caller opt-in and a separately verified
sibling namespace; this module never opens archive-controlled filesystem paths.
Links and ambiguous layouts are rejected. Integrity values are consistency
checks, not trusted signatures.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import re
import struct
from typing import Any, BinaryIO

from .core import MAX_DOCUMENT_BYTES, GuardError, parse_json, safe_relative_path

_MAX_DIRECTORY_DEPTH = 64
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class AsarEntry:
    name: str
    offset: int
    size: int
    directory: bool = False
    integrity: dict[str, Any] | None = None
    unpacked: bool = False


def looks_like_asar(prefix: bytes) -> bool:
    """Recognize the canonical two Pickle headers independently of a suffix."""
    if len(prefix) < 16:
        return False
    first_size, header_size, payload_size, _ = struct.unpack_from("<4I", prefix)
    return first_size == 4 and header_size >= 8 and payload_size == header_size - 4


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GuardError(message)


def _integrity(value: Any, size: int) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == {"algorithm", "hash", "blockSize", "blocks"},
             "Unsupported ASAR integrity metadata")
    _require(value["algorithm"] == "SHA256" and type(value["hash"]) is str
             and _SHA256.fullmatch(value["hash"]) is not None,
             "Unsupported ASAR integrity algorithm or digest")
    block_size = value["blockSize"]
    _require(type(block_size) is int and 1 <= block_size <= 512 * 1024 * 1024,
             "Invalid ASAR integrity block size")
    blocks = value["blocks"]
    _require(type(blocks) is list and len(blocks) == max(1, (size + block_size - 1) // block_size)
             and all(type(item) is str and _SHA256.fullmatch(item) for item in blocks),
             "Invalid ASAR integrity block digests")
    return value


def read_asar_entries(stream: BinaryIO, file_size: int, *, max_entries: int,
                      max_member_bytes: int, allow_unpacked: bool = False) -> list[AsarEntry]:
    """Validate a complete bounded index before reading any member payloads."""
    stream.seek(0)
    prefix = stream.read(16)
    _require(looks_like_asar(prefix), "Malformed or unsupported ASAR Pickle header")
    _, header_size, _, json_size = struct.unpack("<4I", prefix)
    _require(json_size <= MAX_DOCUMENT_BYTES and header_size == 8 + ((json_size + 3) & ~3),
             "ASAR header exceeds its limit or has inconsistent Pickle lengths")
    data_offset = 8 + header_size
    _require(data_offset <= file_size, "ASAR header exceeds the archive bounds")
    raw = stream.read(header_size - 8)
    _require(len(raw) == header_size - 8 and not any(raw[json_size:]),
             "Truncated ASAR header or nonzero Pickle padding")
    try:
        root = parse_json(raw[:json_size])
    except GuardError as exc:
        raise GuardError("Invalid or ambiguous ASAR JSON header") from exc
    _require(set(root) == {"files"} and type(root["files"]) is dict,
             "ASAR root must contain only a files directory")

    entries: list[AsarEntry] = []
    aliases: set[str] = set()
    # Iterate rather than recursively traversing archive-controlled paths.
    pending: list[tuple[str, dict[str, Any], int, bool]] = [("", root["files"], 0, False)]
    ranges: set[tuple[int, int]] = set()
    data_size = file_size - data_offset
    while pending:
        parent, children, depth, parent_unpacked = pending.pop()
        _require(depth < _MAX_DIRECTORY_DEPTH, "ASAR directory nesting exceeds its limit")
        _require(len(children) <= max_entries - len(entries), "ASAR entry count exceeds max_archive_entries")
        for leaf, node in children.items():
            _require(type(leaf) is str and "/" not in leaf and "\\" not in leaf,
                     "ASAR entries must use single path components")
            name = safe_relative_path(parent + leaf)
            alias = name.casefold()
            _require(alias not in aliases, "ASAR contains colliding paths")
            aliases.add(alias)
            _require(type(node) is dict, "ASAR entry must be an object")
            _require("link" not in node, "ASAR links cannot be inspected")
            if "unpacked" in node:
                _require(type(node["unpacked"]) is bool, "Invalid ASAR unpacked flag")
                _require(not parent_unpacked or node["unpacked"],
                         "ASAR unpacked directory contains conflicting packed metadata")
            unpacked = parent_unpacked or node.get("unpacked", False)
            _require(allow_unpacked or not unpacked,
                     "ASAR unpacked sidecars require a verified sibling namespace")
            if "files" in node:
                _require(not (set(node) - {"files", "unpacked"}) and type(node["files"]) is dict,
                         "Unsupported ASAR directory entry")
                entries.append(AsarEntry(name, 0, 0, directory=True, unpacked=unpacked))
                pending.append((name + "/", node["files"], depth + 1, unpacked))
            else:
                required = {"size", "unpacked"} if unpacked else {"offset", "size"}
                allowed = {"size", "unpacked", "executable", "integrity"}
                if not unpacked:
                    allowed.add("offset")
                _require(required <= set(node) and not (set(node) - allowed),
                         "Unsupported ASAR file entry")
                # The official writer marks every external file explicitly, even
                # when its containing directory is also marked as unpacked.
                _require(not unpacked or node.get("unpacked") is True,
                         "ASAR external file is missing its unpacked flag")
                size = node["size"]
                _require(type(size) is int and 0 <= size <= max_member_bytes,
                         "ASAR member exceeds max_file_bytes or has an invalid size")
                position = 0
                if not unpacked:
                    offset = node["offset"]
                    _require(type(offset) is str and re.fullmatch(r"0|[1-9][0-9]{0,15}", offset) is not None,
                             "Invalid ASAR member offset")
                    position = int(offset)
                    _require(position <= data_size and size <= data_size - position,
                             "ASAR member extends beyond the archive bounds")
                if "executable" in node:
                    _require(type(node["executable"]) is bool, "Invalid ASAR executable flag")
                integrity = _integrity(node["integrity"], size) if "integrity" in node else None
                entries.append(AsarEntry(name, 0 if unpacked else data_offset + position, size,
                                         integrity=integrity, unpacked=unpacked))
                if size and not unpacked:
                    ranges.add((position, position + size))
            _require(len(entries) <= max_entries, "ASAR entry count exceeds max_archive_entries")

    end = 0
    for start, stop in sorted(ranges):
        _require(start == end, "ASAR contains overlapping or unindexed member data")
        end = stop
    _require(end == data_size, "ASAR contains trailing or unindexed data")
    return entries


def validate_asar_integrity(stream: BinaryIO, size: int,
                            integrity: dict[str, Any] | None) -> None:
    """Check already validated integrity metadata against one bounded stream."""
    if integrity is None:
        return
    stream.seek(0)
    digest = hashlib.sha256()
    consumed = 0
    block_matches = True
    for expected in integrity["blocks"]:
        block = hashlib.sha256()
        remaining = min(integrity["blockSize"], size - consumed)
        while remaining:
            chunk = stream.read(min(1024 * 1024, remaining))
            _require(bool(chunk) and len(chunk) <= remaining,
                     "ASAR member changed or was truncated")
            digest.update(chunk)
            block.update(chunk)
            consumed += len(chunk)
            remaining -= len(chunk)
        block_matches = block_matches and block.hexdigest() == expected
    _require(consumed == size and digest.hexdigest() == integrity["hash"],
             "ASAR member digest mismatch")
    _require(block_matches, "ASAR member block digest mismatch")


def read_asar_member(stream: BinaryIO, entry: AsarEntry) -> bytes:
    """Read a packed range; external entries must use a verified sibling."""
    _require(not entry.unpacked and not entry.directory,
             "ASAR unpacked sidecars cannot be read as packed members")
    stream.seek(entry.offset)
    data = stream.read(entry.size)
    _require(len(data) == entry.size, "ASAR member changed or was truncated")
    validate_asar_integrity(io.BytesIO(data), entry.size, entry.integrity)
    return data
