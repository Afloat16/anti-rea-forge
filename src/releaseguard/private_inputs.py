"""Bounded, external private-file references for release-copy checks.

These snapshots identify exact whole-file copies and complete unchanged byte
sequences inside larger payloads, including inspected archive members. They do
not recognize edited, encoded, compiled or split implementations. Keep the
source files and their ancestor directories under trusted build control
throughout scanning and publication.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import secrets
import stat
from typing import BinaryIO

from .core import GuardError

MAX_PRIVATE_INPUT_FILES = 64
MAX_PRIVATE_INPUT_BYTES = 8 * 1024 * 1024
MAX_PRIVATE_INPUT_TOTAL_BYTES = 64 * 1024 * 1024
PRIVATE_CONTENT_ANCHOR_BYTES = 64
MAX_PRIVATE_CONTENT_CANDIDATES = 4096
MAX_PRIVATE_CONTENT_VERIFY_BYTES = 512 * 1024 * 1024
_MAX_PAYLOAD_BYTES = 512 * 1024 * 1024
_CHUNK_BYTES = 128 * 1024


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        (getattr(info, "st_file_attributes", 0) or 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _identity(info: os.stat_result) -> tuple[int, ...]:
    # Compare timestamps only within the same stat API: Windows path stat and
    # fstat can have different creation/change-time semantics.
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_size


def _stamp(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns,
            getattr(info, "st_file_attributes", 0) or 0)


def _path(value: Path | str) -> Path:
    if not isinstance(value, Path) and type(value) is not str:
        raise GuardError("Invalid private-input path")
    if not 1 <= len(str(value)) <= 32768 or "\x00" in str(value):
        raise GuardError("Invalid private-input path")
    return Path(value).absolute()


def _check_file(info: os.stat_result, remaining: int) -> None:
    if _is_link(info) or not stat.S_ISREG(info.st_mode):
        raise GuardError("Private inputs must be regular files without links or reparse points")
    if not 1 <= info.st_size <= MAX_PRIVATE_INPUT_BYTES:
        raise GuardError("Each private input must contain 1 byte to 8 MiB")
    if info.st_size > remaining:
        raise GuardError("Private inputs exceed the 64 MiB total byte limit")


@dataclass(frozen=True)
class PrivateInputSnapshot:
    """Private in-process evidence; never serialize the snapshot or its fields."""

    path: Path = field(repr=False)
    root: Path = field(repr=False)
    sha256: str = field(repr=False)
    identity: tuple[int, ...] = field(repr=False)
    size: int = field(repr=False)
    anchor: bytes = field(repr=False)


def _snapshot_private_input(path: Path | str, root: Path,
                            remaining: int) -> PrivateInputSnapshot:
    directory_fd: int | None = None
    descriptor: int | None = None
    try:
        destination = _path(path)
        if destination.resolve().is_relative_to(root):
            raise GuardError("Private inputs must stay outside the release directory")
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
                if _is_link(info) or not stat.S_ISDIR(info.st_mode):
                    raise GuardError("Private-input directories must not be links or reparse points")
            before = destination.lstat()
        _check_file(before, remaining)
        if directory_fd is None:
            descriptor = os.open(destination, flags)
        else:
            descriptor = os.open(destination.name, flags, dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        _check_file(opened, remaining)
        if _identity(before) != _identity(opened):
            raise GuardError("Private input changed while opening")
        digest = hashlib.sha256()
        length = 0
        anchor = b""
        while block := os.read(descriptor, min(_CHUNK_BYTES, opened.st_size - length + 1)):
            length += len(block)
            if length > opened.st_size:
                raise GuardError("Private input changed while reading")
            digest.update(block)
            if len(anchor) < PRIVATE_CONTENT_ANCHOR_BYTES:
                anchor += block[:PRIVATE_CONTENT_ANCHOR_BYTES - len(anchor)]
        after = os.fstat(descriptor)
        final = (destination.lstat() if directory_fd is None else os.stat(
            destination.name, dir_fd=directory_fd, follow_symlinks=False,
        ))
        if (length != opened.st_size or _stamp(opened) != _stamp(after)
                or _stamp(before) != _stamp(final)):
            raise GuardError("Private input changed while reading")
        return PrivateInputSnapshot(destination, root, digest.hexdigest(), _stamp(final), length, anchor)
    except GuardError:
        raise
    except (OSError, ValueError, RuntimeError):
        raise GuardError("Cannot load private input from a regular unchanged external file") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_fd is not None:
            os.close(directory_fd)


def snapshot_private_inputs(paths: tuple[Path | str, ...] | list[Path | str], *,
                            root: Path | str) -> tuple[PrivateInputSnapshot, ...]:
    """Snapshot at most 64 external regular files, 8 MiB each and 64 MiB total.

    No directories, globs, imports or execution are supported. On platforms
    with directory-descriptor support, every ancestor is opened with O_NOFOLLOW.
    Elsewhere, link/reparse and before/after identity checks detect ordinary
    replacement; these checks do not provide an atomic filesystem snapshot.
    """
    if not isinstance(paths, (list, tuple)) or len(paths) > MAX_PRIVATE_INPUT_FILES:
        raise GuardError("Expected up to 64 external private-input files")
    try:
        release_root = _path(root).resolve()
    except (OSError, ValueError, RuntimeError):
        raise GuardError("Invalid release root for private-input inspection") from None
    snapshots: list[PrivateInputSnapshot] = []
    remaining = MAX_PRIVATE_INPUT_TOTAL_BYTES
    for path in paths:
        current = _snapshot_private_input(path, release_root, remaining)
        snapshots.append(current)
        remaining -= current.size
    return tuple(snapshots)


class PrivateContentBudgetError(GuardError):
    """Public fixed reason for an incomplete exact-content inspection."""

    def __init__(self, reason: str):
        if reason not in {"private_content_candidate_limit", "private_content_verification_limit"}:
            raise ValueError("Invalid private-content budget reason")
        self.reason = reason
        super().__init__(reason)


class PrivateContentScanner:
    """Locate complete reference bytes without retaining full private files.

    A maximum 64-byte prefix locates candidates. A bounded streaming SHA-256
    verifies each entire candidate. References at most 64 bytes long are already
    exact when their complete anchor matches. Candidate and verification limits
    apply to the whole scanner, including every decoded archive member. The
    caller must also bound the total payload bytes and number of payloads.

    No reference or payload is imported, evaluated, normalized or executed.
    A budget failure is incomplete inspection, never evidence of absence.
    """

    def __init__(self, snapshots: tuple[PrivateInputSnapshot, ...] | list[PrivateInputSnapshot]):
        if (not isinstance(snapshots, (list, tuple)) or len(snapshots) > MAX_PRIVATE_INPUT_FILES
                or any(not isinstance(item, PrivateInputSnapshot) for item in snapshots)):
            raise GuardError("Invalid private-input snapshots")
        self._targets: dict[bytes, dict[tuple[int, str], list[int]]] = {}
        total = 0
        for index, item in enumerate(snapshots):
            if (type(item.size) is not int or not 1 <= item.size <= MAX_PRIVATE_INPUT_BYTES
                    or type(item.anchor) is not bytes
                    or len(item.anchor) != min(item.size, PRIVATE_CONTENT_ANCHOR_BYTES)
                    or type(item.sha256) is not str or len(item.sha256) != 64
                    or any(character not in "0123456789abcdef" for character in item.sha256)):
                raise GuardError("Invalid private-input snapshots")
            total += item.size
            self._targets.setdefault(item.anchor, {}).setdefault((item.size, item.sha256), []).append(index)
        if total > MAX_PRIVATE_INPUT_TOTAL_BYTES:
            raise GuardError("Invalid private-input snapshots")
        self._count = len(snapshots)
        self.candidates_checked = 0
        self.verification_bytes = 0
        self._exhausted_reason: str | None = None

    def _exhausted(self, reason: str) -> None:
        self._exhausted_reason = reason
        raise PrivateContentBudgetError(reason)

    def _candidate(self, stream: BinaryIO, start: int, length: int, digest: str,
                   anchor_length: int) -> bool:
        if self.candidates_checked >= MAX_PRIVATE_CONTENT_CANDIDATES:
            self._exhausted("private_content_candidate_limit")
        self.candidates_checked += 1
        if length == anchor_length:
            return True
        # Charge the entire proposed span before any seek/read, even if a read
        # later fails. No individual candidate can exceed the remaining budget.
        if length > MAX_PRIVATE_CONTENT_VERIFY_BYTES - self.verification_bytes:
            self._exhausted("private_content_verification_limit")
        self.verification_bytes += length
        resume = stream.tell()
        try:
            stream.seek(start)
            remaining = length
            current = hashlib.sha256()
            while remaining:
                requested = min(_CHUNK_BYTES, remaining)
                chunk = stream.read(requested)
                if not chunk or len(chunk) > requested:
                    raise GuardError("Payload changed during private-input inspection")
                remaining -= len(chunk)
                current.update(chunk)
            return secrets.compare_digest(current.hexdigest(), digest)
        finally:
            stream.seek(resume)

    def scan(self, stream: BinaryIO, size: int, *,
             matched_indices: tuple[int, ...] | list[int] | set[int] = ()) -> tuple[int, ...]:
        """Return new matching reference indexes and restore the input position.

        Pass whole-payload digest matches in ``matched_indices`` to avoid
        duplicate findings. Exact duplicate references share verification work
        and still return every original index. The seekable input must represent
        precisely ``size`` bytes; malformed or truncated streams fail closed.
        """
        if (type(size) is not int or not 0 <= size <= _MAX_PAYLOAD_BYTES
                or not isinstance(matched_indices, (list, tuple, set))
                or len(matched_indices) > self._count
                or any(type(index) is not int or not 0 <= index < self._count
                       for index in matched_indices)):
            raise GuardError("Invalid private-input inspection arguments")
        if self._exhausted_reason is not None:
            raise PrivateContentBudgetError(self._exhausted_reason)
        found = set(matched_indices)
        existing = set(found)
        targets = {
            anchor: {(length, digest): indices for (length, digest), indices in candidates.items()
                     if length <= size and not all(index in found for index in indices)}
            for anchor, candidates in self._targets.items()
        }
        targets = {anchor: candidates for anchor, candidates in targets.items() if candidates}
        resume: int | None = None
        try:
            resume = stream.tell()
            stream.seek(0, os.SEEK_END)
            if stream.tell() != size:
                raise GuardError("Payload changed during private-input inspection")
            if not targets:
                return ()
            stream.seek(0)
            overlap = max(map(len, targets)) - 1
            tail = b""
            total = 0
            while total < size:
                requested = min(_CHUNK_BYTES, size - total)
                chunk = stream.read(requested)
                if not chunk or len(chunk) > requested:
                    raise GuardError("Payload changed during private-input inspection")
                window_start = total - len(tail)
                window = tail + chunk
                for anchor, candidates in targets.items():
                    pending = [((length, digest), indices) for (length, digest), indices in candidates.items()
                               if not all(index in found for index in indices)]
                    if not pending:
                        continue
                    # Search only starts that could hold the shortest pending
                    # reference. This avoids scanning millions of impossible
                    # suffix positions when a long reference has a common anchor.
                    last_start = size - min(key[0] for key, _ in pending)
                    end = min(len(window), last_start - window_start + len(anchor))
                    position = max(0, len(tail) - len(anchor) + 1)
                    while position < end:
                        position = window.find(anchor, position, end)
                        if position < 0:
                            break
                        absolute = window_start + position
                        for (length, digest), indices in pending:
                            if (absolute + length <= size and not all(index in found for index in indices)
                                    and self._candidate(stream, absolute, length, digest, len(anchor))):
                                found.update(indices)
                        if all(all(index in found for index in indices) for _, indices in pending):
                            break
                        position += 1
                total += len(chunk)
                tail = window[-overlap:] if overlap else b""
            if stream.read(1):
                raise GuardError("Payload changed during private-input inspection")
        except GuardError:
            raise
        except (OSError, ValueError, TypeError, OverflowError):
            raise GuardError("Cannot inspect an unchanged seekable private-input payload") from None
        finally:
            if resume is not None:
                try:
                    stream.seek(resume)
                except (OSError, ValueError, TypeError, OverflowError):
                    raise GuardError("Cannot restore private-input inspection stream") from None
        return tuple(sorted(found - existing))


def assert_private_inputs_unchanged(snapshots: tuple[PrivateInputSnapshot, ...] |
                                   list[PrivateInputSnapshot]) -> None:
    """Reopen and hash every private input before completing publication.

    Missing, replaced, modified or newly linked inputs fail with a fixed error
    that discloses no private path, content or digest.
    """
    if (not isinstance(snapshots, (list, tuple)) or len(snapshots) > MAX_PRIVATE_INPUT_FILES
            or any(not isinstance(item, PrivateInputSnapshot) for item in snapshots)):
        raise GuardError("Invalid private-input snapshots")
    remaining = MAX_PRIVATE_INPUT_TOTAL_BYTES
    for expected in snapshots:
        try:
            current = _snapshot_private_input(expected.path, expected.root, remaining)
        except (GuardError, OSError):
            raise GuardError("Private inputs changed during the operation") from None
        if (current.identity != expected.identity or current.size != expected.size
                or not secrets.compare_digest(current.sha256, expected.sha256)):
            raise GuardError("Private inputs changed during the operation")
        remaining -= current.size
