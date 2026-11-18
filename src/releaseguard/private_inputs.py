"""Bounded, external private-file references for release-copy checks.

These snapshots identify exact whole-file copies, including renamed archive
members. They do not recognize translated, compiled, concatenated or otherwise
changed implementations. Keep the source files and their ancestor directories
under trusted build control throughout scanning and publication.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import secrets
import stat

from .core import GuardError

MAX_PRIVATE_INPUT_FILES = 64
MAX_PRIVATE_INPUT_BYTES = 8 * 1024 * 1024
MAX_PRIVATE_INPUT_TOTAL_BYTES = 64 * 1024 * 1024
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
        while block := os.read(descriptor, min(_CHUNK_BYTES, opened.st_size - length + 1)):
            length += len(block)
            if length > opened.st_size:
                raise GuardError("Private input changed while reading")
            digest.update(block)
        after = os.fstat(descriptor)
        final = (destination.lstat() if directory_fd is None else os.stat(
            destination.name, dir_fd=directory_fd, follow_symlinks=False,
        ))
        if (length != opened.st_size or _stamp(opened) != _stamp(after)
                or _stamp(before) != _stamp(final)):
            raise GuardError("Private input changed while reading")
        return PrivateInputSnapshot(destination, root, digest.hexdigest(), _stamp(final), length)
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
