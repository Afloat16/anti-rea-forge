"""Bounded inspection of packed Electron ASAR archives, without extraction.

The canonical Pickle layout and member offsets follow electron/asar's disk.ts.
Links, unpacked sidecars and unknown entry layouts are rejected. Exact shared
file ranges (ASAR deduplication) are supported; partial overlaps and unindexed
bytes are not. Header integrity values are consistency checks, not signatures.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
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
                      max_member_bytes: int) -> list[AsarEntry]:
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
    pending: list[tuple[str, dict[str, Any], int]] = [("", root["files"], 0)]
    ranges: set[tuple[int, int]] = set()
    data_size = file_size - data_offset
    while pending:
        parent, children, depth = pending.pop()
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
                _require(type(node["unpacked"]) is bool and not node["unpacked"],
                         "ASAR unpacked sidecars cannot be inspected as packed members")
            if "files" in node:
                _require(not (set(node) - {"files", "unpacked"}) and type(node["files"]) is dict,
                         "Unsupported ASAR directory entry")
                entries.append(AsarEntry(name, 0, 0, directory=True))
                pending.append((name + "/", node["files"], depth + 1))
            else:
                _require({"offset", "size"} <= set(node)
                         and not (set(node) - {"offset", "size", "unpacked", "executable", "integrity"}),
                         "Unsupported ASAR file entry")
                size, offset = node["size"], node["offset"]
                _require(type(size) is int and 0 <= size <= max_member_bytes,
                         "ASAR member exceeds max_file_bytes or has an invalid size")
                _require(type(offset) is str and re.fullmatch(r"0|[1-9][0-9]{0,15}", offset) is not None,
                         "Invalid ASAR member offset")
                position = int(offset)
                _require(position <= data_size and size <= data_size - position,
                         "ASAR member extends beyond the archive bounds")
                if "executable" in node:
                    _require(type(node["executable"]) is bool, "Invalid ASAR executable flag")
                integrity = _integrity(node["integrity"], size) if "integrity" in node else None
                entries.append(AsarEntry(name, data_offset + position, size, integrity=integrity))
                if size:
                    ranges.add((position, position + size))
            _require(len(entries) <= max_entries, "ASAR entry count exceeds max_archive_entries")

    end = 0
    for start, stop in sorted(ranges):
        _require(start == end, "ASAR contains overlapping or unindexed member data")
        end = stop
    _require(end == data_size, "ASAR contains trailing or unindexed data")
    return entries


def read_asar_member(stream: BinaryIO, entry: AsarEntry) -> bytes:
    """Read one already bounded range and check optional SHA-256 metadata."""
    stream.seek(entry.offset)
    data = stream.read(entry.size)
    _require(len(data) == entry.size, "ASAR member changed or was truncated")
    if entry.integrity is not None:
        expected = entry.integrity
        _require(hashlib.sha256(data).hexdigest() == expected["hash"], "ASAR member digest mismatch")
        block_size = expected["blockSize"]
        for number, digest in enumerate(expected["blocks"]):
            block = memoryview(data)[number * block_size:(number + 1) * block_size]
            _require(hashlib.sha256(block).hexdigest() == digest, "ASAR member block digest mismatch")
    return data
