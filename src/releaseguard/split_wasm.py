"""Move recognized Wasm debug sections out of a trusted immutable build.

The private output is the complete original module, not a debug-only encoding.
Only known debug custom sections are removed; every other byte stays in order.
No input code is executed and no external tools or URLs are invoked.
"""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
import io
from pathlib import Path
import stat

from .core import GuardError, _root, safe_relative_path, write_new
from .native import _assert_scanned_identity
from .split_maps import _portable_identity, _read, _unlink_created
from .wasm import _inspect_wasm_stream


def _destination_file(path: Path | str) -> Path:
    destination = Path(path).absolute()
    safe_relative_path(destination.name)
    parent = _root(destination.parent)
    if parent != destination.parent:
        raise GuardError("Wasm output parents must be real directories without symlink aliases or ..")
    try:
        destination.lstat()
    except FileNotFoundError:
        return destination
    raise GuardError("Wasm output must be a new file")


def _under(path: Path, directory: Path) -> bool:
    value, root = _portable_identity(path), _portable_identity(directory)
    return value[:len(root)] == root


def split_wasm(artifact: Path | str, public: Path | str, private: Path | str) -> dict:
    """Create two new files, rolling back both if publication fails.

    Existing parent directories and their ancestors must be trusted and remain
    unchanged. Public and private output trees must be separate; the original
    input must not sit in the public output tree. Publish only after success.
    A module is limited to 64 MiB. This operation validates framing and exact
    retained bytes, not Wasm instruction/type semantics or application behavior.
    """
    source = Path(artifact).absolute()
    safe_relative_path(source.name)
    if _root(source.parent) != source.parent:
        raise GuardError("Wasm input parent must be a real directory without symlink aliases or ..")
    published, original_file = _destination_file(public), _destination_file(private)
    if (_portable_identity(published) == _portable_identity(original_file)
            or _under(published.parent, original_file.parent)
            or _under(original_file.parent, published.parent)):
        raise GuardError("Public and private Wasm output trees must be distinct and nonoverlapping")
    if _under(source, published.parent):
        raise GuardError("Original Wasm input must not be inside the public output tree")
    if source.lstat().st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise GuardError("Split ordinary Wasm build artifacts before applying privileges")
    original, identity, mode = _read(source, 64 << 20)
    try:
        before, sections = _inspect_wasm_stream(io.BytesIO(original), len(original))
    except ValueError as exc:
        raise GuardError(str(exc)) from exc
    if before["evidence"]["linker_metadata_present"]:
        raise GuardError("Wasm linker metadata requires a final linked module before debug separation")
    private_sections = [section for section in sections if section.private_kind is not None]
    if not private_sections:
        raise GuardError("Wasm input has no recognized private debug sections to separate")
    retained = [section for section in sections if section.private_kind is None]
    view = memoryview(original)
    released = b"".join([original[:8], *(view[section.start:section.end] for section in retained)])
    try:
        after, public_sections = _inspect_wasm_stream(io.BytesIO(released), len(released))
    except ValueError as exc:
        raise GuardError("Separated Wasm section envelope could not be verified") from exc
    if any(after["evidence"].values()) or len(public_sections) != len(retained):
        raise GuardError("Separated Wasm still contains recognized private debug sections")
    for expected, actual in zip(retained, public_sections):
        if (expected.section_id != actual.section_id
                or view[expected.start:expected.end] != released[actual.start:actual.end]):
            raise GuardError("Separated Wasm changed a retained section")
    original_hash = hashlib.sha256(original).hexdigest()
    public_hash = hashlib.sha256(released).hexdigest()
    core_hash = hashlib.sha256(original[:8])
    for section in retained:
        if section.section_id:
            core_hash.update(view[section.start:section.end])
    removed = [{"index": section.index, "kind": section.private_kind,
                "bytes": section.end - section.start,
                "sha256": hashlib.sha256(view[section.start:section.end]).hexdigest()}
               for section in private_sections]
    _assert_scanned_identity(source, identity, "Split Wasm input")
    with ExitStack() as rollback:
        write_new(original_file, original, secret=True)
        rollback.callback(_unlink_created, original_file)
        write_new(published, released)
        rollback.callback(_unlink_created, published)
        published.chmod(mode)
        private_bytes, private_identity, _ = _read(original_file, 64 << 20)
        public_bytes, public_identity, _ = _read(published, 64 << 20)
        if private_bytes != original or public_bytes != released:
            raise GuardError("Separated Wasm outputs differ from their verified bytes")
        _assert_scanned_identity(source, identity, "Split Wasm input")
        # Close changes between the sequential readbacks. The trusted build
        # directory requirement still applies: this is not a multi-file atomic
        # snapshot in the presence of an adversarial concurrent writer.
        _assert_scanned_identity(original_file, private_identity, "Private Wasm original output")
        _assert_scanned_identity(published, public_identity, "Public Wasm output")
        rollback.pop_all()
    return {
        "ok": True,
        "public_wasm": str(published),
        "private_original": str(original_file),
        "original": {"bytes": len(original), "sha256": original_hash},
        "public": {"bytes": len(released), "sha256": public_hash},
        "removed_sections": removed,
        "retained_sections": len(retained),
        "retained_bytes_sha256": public_hash,
        "core_sections_sha256": core_hash.hexdigest(),
        "checks": {"section_envelope_validated": True, "retained_bytes_identical": True,
                   "private_original_identical": True, "full_module_validation_performed": False},
        "notes": [
            "The private file is an exact complete copy of the original module. Keep it outside every public package and deployment.",
            "Only recognized debug custom sections are removed; all other sections, including exports, code, data and unknown customs, are unchanged.",
            "This does not validate Wasm instruction/type semantics. Applications that inspect removed custom sections may change behavior; test the actual application before release.",
            "Private original possession restores all removed metadata. This is a distribution boundary, not protection against an authorized runtime or equivalent algorithm reconstruction.",
        ],
    }
