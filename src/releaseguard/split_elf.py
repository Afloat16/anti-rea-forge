"""Split symbols from a trusted, immutable linked ELF before packaging on Linux."""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile

from .core import GuardError, safe_relative_path, write_new
from .elf import _COMPILER_METADATA_NAMES, _TYPE_METADATA_NAMES, audit_elf
from .native import _ENCODINGS, _assert_scanned_identity
from .split_maps import _destination, _portable_identity, _read


def _check_load_image(original: bytes, released: bytes) -> None:
    """Require identical ELF/program headers and PT_LOAD bytes, except section-table metadata."""
    if original[:16] != released[:16]:
        raise GuardError("objcopy changed ELF identification")
    is64 = original[4] == 2
    endian = "<" if original[5] == 1 else ">"
    word = "Q" if is64 else "I"
    header_size, phoff_at, shoff_at = (64, 32, 40) if is64 else (52, 28, 32)
    # audit_elf already validated both section tables, counts and entry sizes.
    for image in (original, released):
        shoff = struct.unpack_from(endian + word, image, shoff_at)[0]
        shentsize, shnum = struct.unpack_from(endian + "HH", image, header_size - 6)
        if shoff + shentsize * shnum != len(image):
            raise GuardError("Expected an ELF ending in its section table; appended payloads are unsupported")
    before, after = memoryview(original), memoryview(released)
    for start, end in ((0, shoff_at), (shoff_at + (8 if is64 else 4), header_size - 4)):
        if before[start:end] != after[start:end]:
            raise GuardError("objcopy changed ELF execution header fields")
    phoff = struct.unpack_from(endian + word, original, phoff_at)[0]
    phsize, phnum = struct.unpack_from(endian + "HH", original, header_size - 10)
    end = phoff + phsize * phnum
    if before[phoff:end] != after[phoff:end]:
        raise GuardError("objcopy changed program headers")
    loads = 0
    for pos in range(phoff, end, phsize or 1):
        if struct.unpack_from(endian + "I", original, pos)[0] != 1:  # PT_LOAD
            continue
        loads += 1
        offset = struct.unpack_from(endian + word, original, pos + (8 if is64 else 4))[0]
        size = struct.unpack_from(endian + word, original, pos + (32 if is64 else 16))[0]
        start, stop = max(offset, header_size), offset + size
        if stop > min(len(before), len(after)) or before[start:stop] != after[start:stop]:
            raise GuardError("objcopy changed bytes in a loadable segment")
    if not loads:
        raise GuardError("Expected an ELF with a loadable segment")


def _objcopy(tool: str, *args: str | Path) -> bytes:
    try:
        result = subprocess.run([tool, *args], capture_output=True, timeout=120, check=True,
                                env={**os.environ, "LC_ALL": "C"})
    except subprocess.TimeoutExpired as exc:
        raise GuardError("GNU objcopy timed out") from exc
    except subprocess.CalledProcessError as exc:
        reason = exc.stderr.decode("utf-8", errors="replace").strip()[:512]
        raise GuardError(f"GNU objcopy failed: {reason}") from exc
    return result.stdout


def _metadata_sections(image: bytes, selected: frozenset[bytes], kind: str) -> dict[str, tuple[int, str]]:
    """Fingerprint exact private sections from an already audited ELF.

    Only nonallocated PROGBITS data can be moved out of the public program.
    ELF validation bounds the section table, name table and data before this
    helper runs. Hash views avoid copying potentially large metadata payloads.
    """
    is64 = image[4] == 2
    endian = "<" if image[5] == 1 else ">"
    header_size, shoff_at = (64, 40) if is64 else (52, 32)
    shoff = struct.unpack_from(endian + ("Q" if is64 else "I"), image, shoff_at)[0]
    entry_size, count, names_index = struct.unpack_from(endian + "HHH", image, header_size - 6)
    if not count or not names_index:
        return {}
    layout = endian + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
    names_section = struct.unpack_from(layout, image, shoff + names_index * entry_size)
    names = image[names_section[4]:names_section[4] + names_section[5]]
    program_ranges = []
    if kind == "compiler":
        # SHF_ALLOC is not enough: a malformed section can clear that flag
        # while its bytes remain in a load/program segment. Do not remove only
        # the section header and then certify an IR payload still in the file.
        word = "Q" if is64 else "I"
        phoff = struct.unpack_from(endian + word, image, 32 if is64 else 28)[0]
        phsize, phnum = struct.unpack_from(endian + "HH", image, header_size - 10)
        for pos in range(phoff, phoff + phsize * phnum, phsize or 1):
            if not struct.unpack_from(endian + "I", image, pos)[0]:  # PT_NULL
                continue
            offset = struct.unpack_from(endian + word, image, pos + (8 if is64 else 4))[0]
            size = struct.unpack_from(endian + word, image, pos + (32 if is64 else 16))[0]
            if size:
                if offset > len(image) or size > len(image) - offset:
                    raise GuardError("ELF program segment exceeds file while splitting compiler metadata")
                program_ranges.append((offset, offset + size))
    result = {}
    view = memoryview(image)
    for index in range(1, count):
        section = struct.unpack_from(layout, image, shoff + index * entry_size)
        if section[1] == 0:
            continue
        name = names[section[0]:names.find(b"\0", section[0])]
        if name not in selected:
            continue
        label = name.decode("ascii")
        if label in result or section[1] != 1 or section[2] & 2:  # SHT_PROGBITS / SHF_ALLOC
            raise GuardError(f"Duplicate, allocated or unsupported ELF {kind} metadata cannot be split")
        # Compiler metadata is accepted only as ordinary data (possibly marked
        # SHF_EXCLUDE by FatLTO), without links/entry semantics. Unknown flags
        # are not a license to discard a section used by a specialized loader.
        if kind == "compiler" and (section[2] & ~0x80000000 or section[6]
                                   or section[7] or section[9]):
            raise GuardError("Unsupported ELF compiler metadata flags or links cannot be split")
        offset, size = section[4:6]
        if size and any(offset < end and start < offset + size for start, end in program_ranges):
            raise GuardError("ELF compiler metadata overlaps a program segment and cannot be split")
        result[label] = (size, hashlib.sha256(view[offset:offset + size]).hexdigest())
    return result


def _type_metadata(image: bytes) -> dict[str, tuple[int, str]]:
    return _metadata_sections(image, _TYPE_METADATA_NAMES, "type")


def _compiler_metadata(image: bytes) -> dict[str, tuple[int, str]]:
    return _metadata_sections(image, _COMPILER_METADATA_NAMES, "compiler")


def split_elf_debug(artifact: Path | str, public: Path | str, private: Path | str,
                    private_names: tuple[str, ...] | list[str] = ()) -> dict:
    """Publish one stripped ELF and its separate private symbols, or leave no outputs.

    Both new output directories must have trusted, existing parents. The input
    is an ordinary linked GNU/Linux ELF, up to 64 MiB, before signing/packaging.
    Optional markers describe exact ASCII spellings that must survive privately
    and be absent in UTF-8, UTF-16LE/BE and UTF-32LE/BE in the released file.
    """
    tool = shutil.which("objcopy")
    if not sys.platform.startswith("linux") or not tool or b"GNU objcopy" not in _objcopy(tool, "--version"):
        raise GuardError("split-elf-debug requires GNU objcopy on Linux")
    source = Path(artifact).absolute()
    name = safe_relative_path(source.name)
    debug_name = safe_relative_path(name + ".debug")
    published, symbols = _destination(public), _destination(private)
    if any(Path(p).absolute().parent != d.parent for p, d in ((public, published), (private, symbols))):
        raise GuardError("Output paths must use real directories without symlink aliases or ..")
    if _portable_identity(published) == _portable_identity(symbols):
        raise GuardError("Public and private output directories must be distinct")
    if not isinstance(private_names, (list, tuple)) or len(private_names) > 64 or any(
        not isinstance(n, str) or not n.isascii() or not n.isprintable() or not 1 <= len(n) <= 512
        for n in private_names
    ):
        raise GuardError("Expected up to 64 nonempty printable ASCII private names of at most 512 characters")
    if (source.lstat().st_mode & (stat.S_ISUID | stat.S_ISGID)
            or {"security.capability", "security.ima", "security.evm"}.intersection(
                os.listxattr(source, follow_symlinks=False))):
        raise GuardError("Split ordinary build artifacts before applying privileges or integrity signatures")
    original, identity, mode = _read(source, 64 << 20)
    release_file, debug_file = published / name, symbols / debug_name
    result = {"ok": False, "public_elf": str(release_file), "private_debug": str(debug_file), "findings": []}

    with tempfile.TemporaryDirectory(dir=symbols.parent, prefix=".split-elf-") as tmp:
        # Fixed scratch paths avoid collisions with input names and prevent operating on the user's file.
        work = Path(tmp)
        snapshot, stripped = work / "input", work / "output"
        (work / "symbols").mkdir()
        sidecar = work / "symbols" / debug_name
        write_new(snapshot, original, secret=True)
        source_meta = audit_elf(snapshot)
        if not source_meta["evidence"]["symbol_table_present"] or not source_meta["section_names_available"]:
            raise GuardError("Expected a linked ELF with a named section table and static symbols")
        if set(source_meta["sections"]) & {".gnu_debuglink", ".gnu_debugaltlink", ".gnu_debugdata", ".debug_sup"}:
            raise GuardError("Already split or supplementary debug metadata is unsupported")
        type_metadata = _type_metadata(original)
        compiler_metadata = _compiler_metadata(original)
        _objcopy(tool, "--only-keep-debug", snapshot, sidecar)
        remove_metadata = ["--remove-section=" + name
                           for name in sorted(type_metadata.keys() | compiler_metadata.keys())]
        _objcopy(tool, "--strip-all", *remove_metadata, f"--add-gnu-debuglink={sidecar}", snapshot, stripped)
        public_meta = audit_elf(stripped)
        private_meta = audit_elf(sidecar)
        if (any(public_meta["evidence"].values()) or public_meta["compiler_metadata_present"]
                or ".gnu_debuglink" not in public_meta["sections"]
                or not private_meta["evidence"]["symbol_table_present"]):
            raise GuardError("Could not verify separated ELF symbol and debug metadata")
        released, debug = stripped.read_bytes(), sidecar.read_bytes()
        if _type_metadata(debug) != type_metadata:
            raise GuardError("Could not preserve exact private ELF type metadata")
        if _compiler_metadata(debug) != compiler_metadata:
            raise GuardError("Could not preserve exact private ELF compiler metadata")
        _check_load_image(original, released)
        for marker in dict.fromkeys(private_names):
            needle = marker.encode("ascii")
            if needle not in debug:
                raise GuardError(f"Private name absent from separate debug file: {marker}")
            if any(marker.encode(encoding) in released for encoding in _ENCODINGS):
                result["findings"].append({"code": "private_name_in_public", "name": marker})
        _assert_scanned_identity(source, identity, "Split ELF input")
        if result["findings"]:
            return result
        with ExitStack() as rollback:
            for directory in (symbols, published):
                directory.mkdir(mode=0o700)
                rollback.callback(directory.rmdir)
            write_new(debug_file, debug, secret=True)
            rollback.callback(debug_file.unlink)
            write_new(release_file, released)
            rollback.callback(release_file.unlink)
            release_file.chmod(mode)
            rollback.pop_all()
    return {**result, "ok": True}
