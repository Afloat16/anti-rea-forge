"""Portable, bounded release inspection for source and binary distributions.

The scanner never executes inspected code or extracts archive members to disk.
Marker checks are heuristics, not a complete secret scanner or a resistance score.
A release and its ancestor directories must remain under trusted build control.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import re
import stat
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Any, BinaryIO

from .core import MAX_FILES, GuardError, _inventory, _is_link, _root, read_document, safe_relative_path
from .native import _assert_scanned_identity, _component_findings
from .native_token import NATIVE_TOKEN_HEX_DIGITS, NATIVE_TOKEN_PREFIX
from .sealed import load_asset_key

_CHUNK_BYTES = 1024 * 1024
_MAX_BYTES = 512 * 1024 * 1024
_MAX_FINDINGS = 10000
_ENCODINGS = ("utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")
_FIELDS = {
    "version", "forbid_literals", "forbid_extensions", "forbid_path_components",
    "forbid_file_sha256", "allowed_release_files", "check_private_keys",
    "check_source_maps", "check_native_tokens", "scan_zip_archives", "max_file_bytes", "max_total_bytes",
    "max_archive_depth", "max_archive_entries", "max_files",
}
_ZIP_EXTENSIONS = {".zip", ".jar", ".war", ".ear", ".whl", ".nupkg", ".vsix", ".apk", ".aab"}
_UNSUPPORTED_EXTENSIONS = {".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar", ".zst", ".asar"}
_UNSUPPORTED_MAGICS = (b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c",
                       b"Rar!\x1a\x07", b"\x28\xb5\x2f\xfd")
_KEY_MARKERS = ("-----BEGIN PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----",
                "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----",
                "-----BEGIN DSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----")
_MAP_MARKERS = ("sourceMappingURL", '"sourcesContent"')


def _native_token_rules():
    """Fixed-size byte expressions: no Unicode decoding or token material retained."""
    for encoding in _ENCODINGS:
        prefix = NATIVE_TOKEN_PREFIX.encode(encoding)
        unit = "X".encode(encoding)
        # Preserve the NUL bytes in the UTF-16/32 code unit; only its ASCII
        # digit position may vary. The token can be unaligned in a binary.
        hex_unit = unit.replace(b"X", b"[0-9a-f]")
        expression = re.compile(re.escape(prefix) + b"(?:%s){%d}" % (hex_unit, NATIVE_TOKEN_HEX_DIGITS))
        yield encoding, prefix, expression, len(prefix) + len(unit) * NATIVE_TOKEN_HEX_DIGITS


_TOKEN_RULES = tuple(_native_token_rules())


def _strings(value: Any, label: str, maximum: int) -> list[str]:
    if type(value) is not list or len(value) > maximum or any(type(x) is not str for x in value):
        raise GuardError(f"Invalid {label}")
    if len(set(value)) != len(value):
        raise GuardError(f"Duplicate {label}")
    return value


def load_distribution_policy(path: Path | str) -> dict[str, Any]:
    """Read a strict v1 portable policy; it is distinct from native gate policy."""
    supplied = read_document(path)
    if set(supplied) - _FIELDS or type(supplied.get("version")) is not int or supplied["version"] != 1:
        raise GuardError("Missing version, unsupported version or unknown portable policy fields")
    policy: dict[str, Any] = {
        "version": 1, "forbid_literals": [], "forbid_extensions": [".pdb", ".ilk", ".map"],
        "forbid_path_components": [".git", ".svn", ".hg", ".env"],
        "forbid_file_sha256": [], "allowed_release_files": None,
        "check_private_keys": True, "check_source_maps": True, "check_native_tokens": True,
        "scan_zip_archives": True,
        "max_file_bytes": 64 * 1024 * 1024, "max_total_bytes": 256 * 1024 * 1024,
        "max_archive_depth": 2, "max_archive_entries": 10000, "max_files": MAX_FILES,
    }
    policy.update(supplied)
    for literal in _strings(policy["forbid_literals"], "forbid_literals", 64):
        if not 1 <= len(literal) <= 1024:
            raise GuardError("Forbidden literals must contain 1..1024 characters")
        try:
            literal.encode("utf-8")
        except UnicodeError as exc:
            raise GuardError("Invalid Unicode in forbidden literal") from exc
    extensions = _strings(policy["forbid_extensions"], "forbid_extensions", 64)
    if any(not re.fullmatch(r"\.[a-z0-9]{1,16}", item) for item in extensions):
        raise GuardError("Forbidden extensions must use a lowercase .extension form")
    components = _strings(policy["forbid_path_components"], "forbid_path_components", 64)
    for item in components:
        if "/" in item:
            raise GuardError("Forbidden path components must be exact single names")
        safe_relative_path(item)
    if len({item.casefold() for item in components}) != len(components):
        raise GuardError("Duplicate case-insensitive forbidden path components")
    for digest in _strings(policy["forbid_file_sha256"], "forbid_file_sha256", 64):
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise GuardError("Forbidden file digests must use lowercase SHA-256 hex")
    if "allowed_release_files" in supplied:
        allowed = _strings(policy["allowed_release_files"], "allowed_release_files", MAX_FILES)
        if not allowed:
            raise GuardError("allowed_release_files must be nonempty when configured")
        for item in allowed:
            safe_relative_path(item)
        if len({item.casefold() for item in allowed}) != len(allowed):
            raise GuardError("Duplicate case-insensitive allowed release files")
    for field in ("check_private_keys", "check_source_maps", "check_native_tokens", "scan_zip_archives"):
        if type(policy[field]) is not bool:
            raise GuardError(f"{field} must be a boolean")
    for field, maximum in (("max_file_bytes", _MAX_BYTES), ("max_total_bytes", _MAX_BYTES),
                           ("max_files", MAX_FILES), ("max_archive_entries", MAX_FILES),
                           ("max_archive_depth", 8)):
        if type(policy[field]) is not int or not 1 <= policy[field] <= maximum:
            raise GuardError(f"{field} must be an integer in 1..{maximum}")
    return policy


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _validate_zip_extra(extra: bytes) -> None:
    # Python releases disagree on whether Unicode Path overrides are applied.
    # Reject that alternate naming channel uniformly rather than trusting the
    # runtime-specific ZipInfo.filename interpretation.
    position = 0
    while position < len(extra):
        if len(extra) - position < 4:
            raise GuardError("Truncated ZIP extra field")
        field, length = struct.unpack_from("<HH", extra, position)
        position += 4 + length
        if field in {1, 0x7075} or position > len(extra):
            raise GuardError("ZIP64, Unicode Path aliases or malformed ZIP extra fields are unsupported")


class _Scanner:
    def __init__(self, policy: dict[str, Any], asset_keys: tuple[bytes, ...] = ()):
        self.policy = policy
        self.total_bytes = 0
        self.archive_entries = 0
        self.archives = 0
        self.archive_scan_completed = True
        self.findings: list[dict[str, Any]] = []
        self.patterns: list[tuple[str, int, str, bytes]] = []
        groups = [("forbidden_literal", policy["forbid_literals"])]
        if policy["check_private_keys"]:
            groups.append(("private_key_marker", _KEY_MARKERS))
        if policy["check_source_maps"]:
            groups.append(("source_map_marker", _MAP_MARKERS))
        for code, strings in groups:
            for index, literal in enumerate(strings):
                self.patterns.extend((code, index, encoding, literal.encode(encoding)) for encoding in _ENCODINGS)
        for index, key in enumerate(asset_keys):
            self.patterns.append(("asset_key_exposure", index, "raw", key))
            encoded = {key.hex(), key.hex().upper(), base64.b64encode(key).decode("ascii"),
                       base64.urlsafe_b64encode(key).decode("ascii")}
            encoded |= {value.rstrip("=") for value in encoded}
            for text in sorted(encoded):
                for encoding in _ENCODINGS:
                    self.patterns.append(("asset_key_exposure", index, encoding, text.encode(encoding)))
        self.overlap = max((len(pattern[3]) for pattern in self.patterns), default=1) - 1
        self.token_rules = _TOKEN_RULES if policy["check_native_tokens"] else ()
        if self.token_rules:
            self.overlap = max(self.overlap, max(length for _, _, _, length in self.token_rules) - 1)
        self.digests = {value: index for index, value in enumerate(policy["forbid_file_sha256"])}
        self.components = {value.casefold(): index for index, value in enumerate(policy["forbid_path_components"])}

    def add(self, code: str, path: str, members: tuple[str, ...] = (), **details: Any) -> None:
        if len(self.findings) >= _MAX_FINDINGS:
            raise GuardError("Portable scan exceeded its finding limit")
        finding: dict[str, Any] = {"code": code, "path": path, **details}
        if members:
            finding["archive_members"] = list(members)
        self.findings.append(finding)

    def names(self, name: str, path: str, members: tuple[str, ...] = (), *, directory: bool = False) -> None:
        if not directory and Path(name).suffix.casefold() in self.policy["forbid_extensions"]:
            self.add("forbidden_extension", path, members)
        # Physical directory components are checked once by _component_findings.
        if members:
            for component in name.split("/"):
                index = self.components.get(component.casefold())
                if index is not None:
                    self.add("forbidden_path_component", path, members, rule_index=index)

    def remaining(self) -> int:
        return self.policy["max_total_bytes"] - self.total_bytes

    def payload(self, stream: BinaryIO, size: int, path: str, members: tuple[str, ...] = ()) -> dict[str, Any]:
        if size > self.policy["max_file_bytes"] or size > self.remaining():
            raise GuardError("Payload exceeds portable max_file_bytes or remaining max_total_bytes")
        digest = hashlib.sha256()
        total = 0
        tail = b""
        seen: set[tuple[str, int, str]] = set()
        while chunk := stream.read(min(_CHUNK_BYTES, size - total + 1)):
            total += len(chunk)
            self.total_bytes += len(chunk)
            if total > size or self.total_bytes > self.policy["max_total_bytes"]:
                raise GuardError("Payload grew or exceeded the portable scan byte budget")
            digest.update(chunk)
            window = tail + chunk
            for code, index, encoding, pattern in self.patterns:
                key = (code, index, encoding)
                if key not in seen and pattern in window:
                    self.add(code, path, members, rule_index=index, encoding=encoding)
                    seen.add(key)
            for encoding, prefix, expression, _ in self.token_rules:
                key = ("native_token_exposure", 0, encoding)
                if key in seen:
                    continue
                # Most payloads have no prefix. Only invoke the bounded regex
                # when needed, and report at most once per encoding/payload.
                first = window.find(prefix)
                if first >= 0 and expression.search(window, first) is not None:
                    self.add("native_token_exposure", path, members, encoding=encoding)
                    seen.add(key)
            tail = window[-self.overlap:] if self.overlap else b""
        if total != size:
            raise GuardError("Payload size changed during the portable scan")
        hexdigest = digest.hexdigest()
        index = self.digests.get(hexdigest)
        if index is not None:
            self.add("forbidden_file_digest", path, members, rule_index=index)
        return {"size": total, "sha256": hexdigest}

    def container(self, stream: BinaryIO, size: int, name: str, path: str,
                  members: tuple[str, ...] = ()) -> None:
        stream.seek(0)
        prefix = stream.read(min(size, 512))
        stream.seek(0)
        suffix = Path(name).suffix.casefold()
        is_zip = zipfile.is_zipfile(stream)
        expected_zip = suffix in _ZIP_EXTENSIONS or prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
        unsupported = suffix in _UNSUPPORTED_EXTENSIONS or prefix.startswith(_UNSUPPORTED_MAGICS) or prefix[257:262] == b"ustar"
        if not is_zip and not expected_zip:
            if unsupported:
                self.archive_scan_completed = False
                self.add("unsupported_archive", path, members)
            return
        if not self.policy["scan_zip_archives"]:
            self.archive_scan_completed = False
            self.add("archive_not_scanned", path, members)
            return
        if not is_zip:
            raise GuardError("Malformed ZIP archive encountered during portable scan")
        if len(members) >= self.policy["max_archive_depth"]:
            raise GuardError("ZIP nesting exceeds max_archive_depth")
        central_start = self._preflight_zip(stream, size)
        try:
            with zipfile.ZipFile(stream) as archive:
                self.archives += 1
                aliases: dict[str, tuple[str, bool]] = {}
                explicit: set[str] = set()
                infos = archive.infolist()
                offsets = sorted(info.header_offset for info in infos)
                if len(set(offsets)) != len(offsets) or any(offset < 0 or offset >= central_start for offset in offsets):
                    raise GuardError("ZIP entry offsets are duplicate or outside the archive")
                if (offsets and offsets[0] != 0) or (not offsets and central_start != 0):
                    raise GuardError("Prefixed or concatenated ZIP archives are unsupported")
                bounds = dict(zip(offsets, offsets[1:] + [central_start]))
                # Preflight bounds metadata before ZipFile allocates ZipInfo objects.
                self.archive_entries += len(infos)
                if self.archive_entries > self.policy["max_archive_entries"]:
                    raise GuardError("ZIP entry count exceeds max_archive_entries")
                for info in infos:
                    entry = self._entry_name(info, aliases, explicit)
                    entry_members = members + (entry,)
                    self.names(entry, path, entry_members, directory=info.is_dir())
                    if info.flag_bits & (1 | 0x40):
                        raise GuardError("Encrypted ZIP entries cannot be inspected")
                    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                        raise GuardError("Only stored and deflated ZIP entries are supported")
                    if info.is_dir() and info.file_size:
                        raise GuardError("ZIP directory unexpectedly contains data")
                    if info.file_size > self.policy["max_file_bytes"] or info.file_size > self.remaining():
                        raise GuardError("ZIP expansion exceeds max_file_bytes or remaining max_total_bytes")
                    # A bounded in-memory copy allows nested ZIP inspection and never
                    # writes an archive-controlled path to the host filesystem.
                    data = self._member_bytes(stream, info, bounds[info.header_offset])
                    if info.is_dir():
                        continue
                    content = io.BytesIO(data)
                    self.payload(content, len(data), path, entry_members)
                    self.container(content, len(data), entry, path, entry_members)
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, ValueError, zlib.error) as exc:
            if isinstance(exc, GuardError):
                raise
            raise GuardError("Invalid or unsupported ZIP archive") from exc

    @staticmethod
    def _member_bytes(stream: BinaryIO, info: zipfile.ZipInfo, boundary: int) -> bytes:
        """Check actual output instead of trusting ZipExtFile's declared-size cap."""
        stream.seek(info.header_offset)
        header = stream.read(30)
        if len(header) != 30 or header[:4] != b"PK\x03\x04":
            raise GuardError("ZIP local header is missing or truncated")
        needed, flags, method, _, _, crc, compressed, expanded, name_size, extra_size = struct.unpack_from("<5H3I2H", header, 4)
        if needed >= 45 or info.extract_version >= 45 or info.reserved:
            raise GuardError("ZIP64 or newer ZIP features are unsupported")
        if (needed, flags, method) != (info.extract_version, info.flag_bits, info.compress_type):
            raise GuardError("ZIP local and central metadata disagree")
        if flags & ~0x080e:
            raise GuardError("Unsupported ZIP entry flags")
        if name_size > 4096 or stream.tell() + name_size + extra_size + info.compress_size > boundary:
            raise GuardError("ZIP local member data overlaps another entry or directory")
        raw_name = stream.read(name_size)
        if raw_name.decode("utf-8" if flags & 0x800 else "cp437") != info.orig_filename:
            raise GuardError("ZIP local and central names disagree")
        _validate_zip_extra(stream.read(extra_size))
        if not flags & 8 and (crc, compressed, expanded) != (info.CRC, info.compress_size, info.file_size):
            raise GuardError("ZIP local and central sizes or CRC disagree")
        if flags & 8 and any(actual not in (0, expected) for actual, expected in
                              zip((crc, compressed, expanded), (info.CRC, info.compress_size, info.file_size))):
            raise GuardError("ZIP data-descriptor placeholders disagree with central metadata")
        if method == zipfile.ZIP_STORED and info.compress_size != info.file_size:
            raise GuardError("Stored ZIP entry has inconsistent lengths")
        decoder = zlib.decompressobj(-15) if method == zipfile.ZIP_DEFLATED else None
        result = bytearray()
        remaining = info.compress_size
        while remaining:
            chunk = stream.read(min(_CHUNK_BYTES, remaining))
            if not chunk:
                raise GuardError("ZIP compressed member is truncated")
            remaining -= len(chunk)
            output = decoder.decompress(chunk, info.file_size + 1 - len(result)) if decoder else chunk
            result.extend(output)
            if len(result) > info.file_size or (decoder and decoder.unconsumed_tail):
                raise GuardError("ZIP actual expansion exceeds its declared size")
            if decoder and (decoder.unused_data or (decoder.eof and remaining)):
                raise GuardError("ZIP compressed member has trailing data")
        if decoder and not decoder.eof:
            raise GuardError("ZIP deflate stream is incomplete")
        if len(result) != info.file_size or zlib.crc32(result) != info.CRC:
            raise GuardError("ZIP expanded size or CRC does not match metadata")
        if flags & 8:
            if stream.tell() + 12 > boundary:
                raise GuardError("ZIP data descriptor is missing")
            first = stream.read(4)
            descriptor_size = 12 if first == b"PK\x07\x08" else 8
            if stream.tell() + descriptor_size > boundary:
                raise GuardError("ZIP data descriptor is truncated")
            descriptor = stream.read(descriptor_size)
            values = descriptor if descriptor_size == 12 else first + descriptor
            if struct.unpack("<3I", values) != (info.CRC, info.compress_size, info.file_size):
                raise GuardError("ZIP data descriptor disagrees with central metadata")
        if stream.tell() != boundary:
            raise GuardError("ZIP contains unindexed bytes between entries or before its directory")
        return bytes(result)

    def _preflight_zip(self, stream: BinaryIO, size: int) -> int:
        """Bound central-directory allocation before invoking Python's ZIP reader.

        Multi-disk and ZIP64 archives are explicitly unsupported. Limiting only
        len(infolist()) would be too late: ZipFile has already allocated entries.
        """
        tail_size = min(size, 65557)
        stream.seek(size - tail_size)
        tail = stream.read(tail_size)
        marker = tail.rfind(b"PK\x05\x06")
        if marker < 0 or len(tail) - marker < 22:
            raise GuardError("ZIP end record is missing or truncated")
        disk, cd_disk, disk_entries, entries, cd_size, cd_offset, comment_size = struct.unpack_from("<4H2LH", tail, marker + 4)
        eocd = size - tail_size + marker
        if marker + 22 + comment_size != len(tail):
            raise GuardError("ZIP end record or trailing bytes are ambiguous")
        if disk or cd_disk or disk_entries != entries:
            raise GuardError("Multi-disk ZIP archives are unsupported")
        if entries == 0xffff or cd_size == 0xffffffff or cd_offset == 0xffffffff or (
            marker >= 20 and tail[marker - 20:marker - 16] == b"PK\x06\x07"
        ):
            raise GuardError("ZIP64 archives are unsupported by the portable scanner")
        if entries > self.policy["max_archive_entries"] - self.archive_entries:
            raise GuardError("ZIP entry count exceeds remaining max_archive_entries")
        start = eocd - cd_size
        if start < 0 or cd_offset != start:
            raise GuardError("Invalid, prefixed or concatenated ZIP central-directory range")
        stream.seek(start)
        count = 0
        consumed = 0
        while consumed < cd_size:
            header = stream.read(46)
            if len(header) != 46 or header[:4] != b"PK\x01\x02":
                raise GuardError("Invalid ZIP central-directory record")
            if struct.unpack_from("<H", header, 34)[0]:
                raise GuardError("ZIP member refers to another disk")
            if struct.unpack_from("<H", header, 6)[0] >= 45:
                raise GuardError("ZIP64 or newer ZIP features are unsupported")
            name_size, extra_size, comment_length = struct.unpack_from("<3H", header, 28)
            if name_size > 4096:
                raise GuardError("ZIP member name exceeds the metadata limit")
            consumed += 46 + name_size + extra_size + comment_length
            count += 1
            if consumed > cd_size or count > entries:
                raise GuardError("ZIP central-directory metadata exceeds declared bounds")
            stream.seek(name_size, io.SEEK_CUR)
            _validate_zip_extra(stream.read(extra_size))
            stream.seek(comment_length, io.SEEK_CUR)
        if count != entries:
            raise GuardError("ZIP central-directory entry count differs from its end record")
        return start

    @staticmethod
    def _entry_name(info: zipfile.ZipInfo, aliases: dict[str, tuple[str, bool]], explicit: set[str]) -> str:
        original = info.orig_filename
        name = original[:-1] if original.endswith("/") else original
        safe_relative_path(name)
        if original != info.filename or "\x00" in original:
            raise GuardError("ZIP member name is ambiguous")
        mode = info.external_attr >> 16
        kind = stat.S_IFMT(mode)
        if kind not in {0, stat.S_IFREG, stat.S_IFDIR} or (kind == stat.S_IFDIR and not info.is_dir()):
            raise GuardError("ZIP links and special files are not allowed")
        if kind == stat.S_IFREG and info.is_dir():
            raise GuardError("ZIP file and directory metadata disagree")
        if name in explicit:
            raise GuardError("Duplicate ZIP member path")
        explicit.add(name)
        parts = name.split("/")
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            directory = index < len(parts) or info.is_dir()
            prior = aliases.get(prefix.casefold())
            if prior is not None and prior != (prefix, directory):
                raise GuardError("Case-insensitive or file-directory ZIP path collision")
            aliases[prefix.casefold()] = (prefix, directory)
        return name


def scan_release(root: Path | str, policy_path: Path | str, *,
                 asset_key_files: tuple[Path | str, ...] | list[Path | str] = ()) -> dict[str, Any]:
    """Inspect an entire release with no requirement for a native entry point.

    Unsupported, disabled, malformed or over-budget containers never produce a
    passing report. Byte accounting includes physical files plus every expanded
    ZIP member, including nested archives. Checks use builder-controlled paths;
    ordinary identity checks are not an atomic snapshot or a race-proof sandbox.
    """
    if not isinstance(asset_key_files, (list, tuple)) or len(asset_key_files) > 16:
        raise GuardError("Expected up to 16 external asset-key files")
    asset_keys = tuple(load_asset_key(path) for path in asset_key_files)
    policy = load_distribution_policy(policy_path)
    release_root = _root(root)
    candidates = _inventory(release_root)
    if not candidates:
        raise GuardError("Cannot inspect an empty release")
    if len(candidates) > policy["max_files"]:
        raise GuardError("Release file count exceeds max_files")
    scanner = _Scanner(policy, asset_keys)
    files: list[dict[str, Any]] = []
    identities: list[tuple[Path, tuple[int, ...]]] = []
    for relative, path in sorted(candidates.items()):
        scanner.names(relative, relative)
        before = path.lstat()
        if _is_link(before) or not stat.S_ISREG(before.st_mode):
            raise GuardError("Release file became a link or special file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as handle:
            opened = os.fstat(handle.fileno())
            if _is_link(opened) or not stat.S_ISREG(opened.st_mode) or (
                opened.st_dev, opened.st_ino, opened.st_size
            ) != (before.st_dev, before.st_ino, before.st_size):
                raise GuardError("Release file changed before portable scanning")
            observed = scanner.payload(handle, opened.st_size, relative)
            scanner.container(handle, opened.st_size, relative, relative)
            after = os.fstat(handle.fileno())
            if _identity(opened) != _identity(after):
                raise GuardError("Release file changed during portable scanning")
        identities.append((path, _identity(after)))
        files.append({"path": relative, **observed})
    final = _inventory(release_root)
    if set(final) != set(candidates):
        raise GuardError("Release inventory changed during portable scanning")
    for path, identity in identities:
        _assert_scanned_identity(path, identity, "Release file")
    for finding in _component_findings(release_root, policy["forbid_path_components"]):
        code = finding.pop("code")
        path = finding.pop("path")
        scanner.add(code, path, **finding)
    if policy["allowed_release_files"] is not None:
        expected = set(policy["allowed_release_files"])
        for relative in sorted(set(final) - expected):
            scanner.add("unexpected_release_file", relative)
        for relative in sorted(expected - set(final)):
            scanner.add("missing_release_file", relative)
    return {
        "ok": not scanner.findings, "root": str(release_root), "files": files,
        "findings": scanner.findings,
        "checks": {
            "scan_completed": True, "files_scanned": len(files),
            "bytes_scanned": scanner.total_bytes, "max_total_bytes": policy["max_total_bytes"],
            "archives_scanned": scanner.archives, "archive_entries": scanner.archive_entries,
            "archive_scan_completed": scanner.archive_scan_completed,
            "archive_formats": ["zip-stored", "zip-deflate"] if policy["scan_zip_archives"] else [],
            "literal_rules": len(policy["forbid_literals"]), "encodings": list(_ENCODINGS),
            "private_key_markers_checked": policy["check_private_keys"],
            "source_map_markers_checked": policy["check_source_maps"],
            "native_token_format_checked": policy["check_native_tokens"],
            "asset_keys_checked": len(asset_keys),
            "release_allowlist_applied": policy["allowed_release_files"] is not None,
        },
        "notes": [
            "Static exposure checks only; passing does not measure REA or cracking resistance.",
            "PEM and source-map markers are heuristics. Undeclared secrets and encoded data can remain undetected.",
            "Native-token findings identify the public token format, not proof of validity. Reports retain file paths and archive member names.",
            "Only stored/deflated ZIP containers are expanded; detected other archives fail policy. ZIP64, Unicode Path aliases, prefixed/concatenated archives and unindexed gaps are unsupported.",
            "scan_completed means the scan plan finished; archive_scan_completed is false for detected unexpanded archives.",
            "The byte budget counts disk bytes and all expanded ZIP members. No members are extracted or executed.",
            "Release roots and ancestors must stay under trusted build control. Verify later-used bytes with a signed manifest.",
        ],
    }
