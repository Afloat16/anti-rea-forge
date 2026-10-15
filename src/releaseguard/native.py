"""Build assets and fail-closed, read-only artifact release gates.

Build seeds diversify reversible literal masks. They are public, not secrets.
No target code is executed and no third-party analyzer is probed or modified.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
from importlib.resources import files
from pathlib import Path
from typing import Any

from . import __version__
from .core import GuardError, _inventory, _is_link, _root, read_document, read_limited, write_new
from .elf import audit_elf
from .pe import audit_pe

_FLAG_NAMES = {"dynamic_base", "nx_compat", "guard_cf", "high_entropy_va"}
_POLICY_FIELDS = {
    "version", "formats", "forbid_literals", "forbid_extensions", "require_native",
    "require_no_debug_metadata", "require_no_symbol_table", "required_pe_flags", "max_binary_bytes",
}
_ENCODINGS = ("utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")
_ASSET_PATHS = ("cmake/ReleaseGuard.cmake", "include/releaseguard/literal.hpp")
_CHUNK_BYTES = 1024 * 1024


def _list_of_strings(value: Any, label: str, maximum: int) -> list[str]:
    if type(value) is not list or len(value) > maximum or any(type(x) is not str for x in value):
        raise GuardError(f"Invalid {label}")
    if len(set(value)) != len(value):
        raise GuardError(f"Duplicate {label}")
    return value


def load_policy(path: Path | str) -> dict[str, Any]:
    supplied = read_document(path)
    if set(supplied) - _POLICY_FIELDS or "version" not in supplied:
        raise GuardError("Missing version or unknown gate policy fields")
    if type(supplied["version"]) is not int or supplied["version"] != 1:
        raise GuardError("Unsupported gate policy version")
    policy = {
        "version": 1, "formats": ["pe"], "forbid_literals": [],
        "forbid_extensions": [".pdb", ".ilk", ".map"], "require_native": True,
        "require_no_debug_metadata": True, "require_no_symbol_table": True,
        "required_pe_flags": [], "max_binary_bytes": 512 * 1024 * 1024,
    }
    policy.update(supplied)
    formats = _list_of_strings(policy["formats"], "formats", 2)
    if not formats or set(formats) - {"pe", "elf"}:
        raise GuardError("Gate supports explicitly selected pe/elf formats only")
    literals = _list_of_strings(policy["forbid_literals"], "forbid_literals", 64)
    for literal in literals:
        if not 1 <= len(literal) <= 1024:
            raise GuardError("Forbidden literals must contain 1..1024 characters")
        try:
            literal.encode("utf-8")
        except UnicodeError as exc:
            raise GuardError("Invalid Unicode in forbidden literal") from exc
    extensions = _list_of_strings(policy["forbid_extensions"], "forbid_extensions", 32)
    if any(not re.fullmatch(r"\.[a-z0-9]{1,16}", x) for x in extensions):
        raise GuardError("Forbidden extensions must use a lowercase .extension form")
    flags = _list_of_strings(policy["required_pe_flags"], "required_pe_flags", 4)
    if set(flags) - _FLAG_NAMES:
        raise GuardError("Unknown required PE flag")
    for name in ("require_native", "require_no_debug_metadata", "require_no_symbol_table"):
        if type(policy[name]) is not bool:
            raise GuardError(f"{name} must be a boolean")
    limit = policy["max_binary_bytes"]
    if type(limit) is not int or not 1 <= limit <= 4 * 1024**3:
        raise GuardError("max_binary_bytes must be an integer in 1..4294967296")
    return policy


def _resources() -> dict[str, bytes]:
    root = files("releaseguard").joinpath("data")
    return {name: root.joinpath(*name.split("/")).read_bytes() for name in _ASSET_PATHS}


def _seed_header(seed: str) -> bytes:
    return ("#pragma once\n"
            "// Public build diversification seed. This is not an encryption key.\n"
            f"#define RELEASEGUARD_BUILD_SEED 0x{seed}ULL\n").encode("ascii")


def init_native(output_dir: Path | str, seed: str | None = None) -> dict[str, Any]:
    """Create versioned build assets, or validate and reuse an existing output."""
    if seed is not None and (type(seed) is not str or not re.fullmatch(r"[0-9a-fA-F]{16}", seed)):
        raise GuardError("Build seed must be exactly 16 hexadecimal digits")
    requested_seed = seed.lower() if seed is not None else None
    output = Path(output_dir).absolute()
    resources = _resources()
    if output.exists() and not _is_link(output.lstat()) and output.is_dir():
        with os.scandir(output) as entries:
            empty = next(entries, None) is None
        if empty:
            # rmdir refuses if another process populated it after the check.
            output.rmdir()
    if output.exists() or output.is_symlink():
        if _is_link(output.lstat()) or not output.is_dir():
            raise GuardError("Native output must be a real directory, not a link")
        marker = output / "releaseguard-native.json"
        if not marker.is_file() or marker.is_symlink():
            raise GuardError("Output already exists without a generated-asset manifest; use a fresh directory")
        document = read_document(marker)
        if set(document) != {"format", "version", "seed", "assets"}:
            raise GuardError("Invalid native asset manifest")
        if document["format"] != "open-release-guard-native/v1" or document["version"] != __version__:
            raise GuardError("Native asset version differs; regenerate into a fresh directory")
        current_seed = document["seed"]
        if type(current_seed) is not str or not re.fullmatch(r"[0-9a-f]{16}", current_seed):
            raise GuardError("Invalid recorded build seed")
        if requested_seed is not None and current_seed != requested_seed:
            raise GuardError("Existing output uses another build seed; use a fresh directory")
        resources["releaseguard_build.hpp"] = _seed_header(current_seed)
        expected = {name: hashlib.sha256(raw).hexdigest() for name, raw in resources.items()}
        if document["assets"] != expected:
            raise GuardError("Generated native assets do not match this installation")
        actual = _inventory(_root(output))
        if set(actual) != set(resources) | {"releaseguard-native.json"}:
            raise GuardError("Generated native directory contains missing or unexpected files")
        for name, raw in resources.items():
            if read_limited(output / name, 1024 * 1024) != raw:
                raise GuardError(f"Generated native asset was changed: {name}")
        return {"ok": True, "output": str(output), "seed": current_seed, "reused": True}

    current_seed = requested_seed if requested_seed is not None else secrets.token_hex(8)
    resources["releaseguard_build.hpp"] = _seed_header(current_seed)
    document = {
        "format": "open-release-guard-native/v1", "version": __version__, "seed": current_seed,
        "assets": {name: hashlib.sha256(raw).hexdigest() for name, raw in resources.items()},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="releaseguard-native-", dir=output.parent) as temporary:
        staging = Path(temporary) / "assets"
        staging.mkdir()
        for name, raw in resources.items():
            destination = staging / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            write_new(destination, raw)
        write_new(staging / "releaseguard-native.json", json.dumps(document, indent=2).encode("ascii") + b"\n")
        if output.exists() or output.is_symlink():
            raise GuardError("Native output was created concurrently; retry with a fresh directory")
        staging.rename(output)
    return {"ok": True, "output": str(output), "seed": current_seed, "reused": False}


def _scan(path: Path, policy: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    patterns = [(index, encoding, literal.encode(encoding))
                for index, literal in enumerate(policy["forbid_literals"]) for encoding in _ENCODINGS]
    overlap = max((len(raw) for _, _, raw in patterns), default=1) - 1
    matched: set[tuple[int, str]] = set()
    findings: list[dict[str, Any]] = []
    before = path.lstat()
    if _is_link(before) or not stat.S_ISREG(before.st_mode):
        raise GuardError("Artifact must be a regular file, not a link or special file")
    if before.st_size > policy["max_binary_bytes"]:
        raise GuardError("Artifact exceeds max_binary_bytes")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise GuardError("Artifact changed before scanning")
        digest = hashlib.sha256()
        tail = b""
        total = 0
        while chunk := handle.read(_CHUNK_BYTES):
            digest.update(chunk)
            window = tail + chunk
            base_offset = total - len(tail)
            total += len(chunk)
            if total > policy["max_binary_bytes"]:
                raise GuardError("Artifact grew beyond max_binary_bytes while scanning")
            for index, encoding, raw in patterns:
                if (index, encoding) not in matched:
                    found = window.find(raw)
                    if found >= 0:
                        findings.append({"code": "forbidden_literal", "rule_index": index,
                                         "encoding": encoding, "offset": base_offset + found})
                        matched.add((index, encoding))
            tail = window[-overlap:] if overlap else b""
        after = os.fstat(handle.fileno())
    if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
        after.st_size, after.st_mtime_ns, after.st_ctime_ns
    ) or total != opened.st_size:
        raise GuardError("Artifact changed while scanning")
    return {"path": str(path), "size": total, "sha256": digest.hexdigest(),
            "_identity": (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)}, findings


def gate(binary: Path | str, policy_path: Path | str,
         root: Path | str | None = None) -> dict[str, Any]:
    policy = load_policy(policy_path)
    path = Path(binary).absolute()
    initial = path.lstat()
    if _is_link(initial) or not stat.S_ISREG(initial.st_mode):
        raise GuardError("Artifact must be a regular file, not a link or special file")
    if initial.st_size > policy["max_binary_bytes"]:
        return {"ok": False,
                "artifact": {"path": str(path), "size": initial.st_size,
                             "sha256": None, "format": "uninspected"},
                "findings": [{"code": "artifact_too_large", "limit": policy["max_binary_bytes"]}],
                "checks": {"scan_completed": False},
                "notes": ["Artifact rejected before reading payload due to the configured size limit."]}
    # Scan the same regular file before interpreting format-specific metadata.
    artifact, findings = _scan(path, policy)
    identity = artifact.pop("_identity")
    magic = read_limited_prefix(path, 4)
    if magic[:2] == b"MZ":
        format_name, report = "pe", audit_pe(path)
    elif magic == b"\x7fELF":
        format_name, report = "elf", audit_elf(path)
    else:
        raise GuardError("Unsupported artifact format; expected PE or ELF")
    artifact["format"] = format_name
    if format_name not in policy["formats"]:
        findings.append({"code": "format_not_allowed", "format": format_name})
    evidence = report["evidence"]
    managed = report.get("managed", False)
    if policy["require_native"] and managed:
        findings.append({"code": "managed_artifact"})
    debug = evidence["debug_directory_present"] if format_name == "pe" else evidence["debug_sections_present"]
    symbols = evidence["coff_symbols_present"] if format_name == "pe" else evidence["symbol_table_present"]
    if policy["require_no_debug_metadata"] and debug:
        findings.append({"code": "debug_metadata_present"})
    if policy["require_no_symbol_table"] and symbols:
        findings.append({"code": "symbol_table_present"})
    if format_name == "elf":
        if policy["require_no_debug_metadata"] and not report.get("section_names_available", False):
            findings.append({"code": "debug_metadata_unverifiable"})
        if policy["require_no_symbol_table"] and not report.get("section_table_present", False):
            findings.append({"code": "symbol_table_unverifiable"})
    if format_name == "pe":
        for name in policy["required_pe_flags"]:
            if not report["flags"][name]:
                findings.append({"code": "missing_pe_flag", "flag": name})
        if "dynamic_base" in policy["required_pe_flags"] and not evidence["relocations_present"]:
            findings.append({"code": "missing_relocation_evidence"})
        if "guard_cf" in policy["required_pe_flags"] and not evidence["load_config_present"]:
            findings.append({"code": "missing_cfg_load_config_evidence"})
        if "guard_cf" in policy["required_pe_flags"] and not report["flags"]["dynamic_base"]:
            findings.append({"code": "missing_cfg_dynamic_base_evidence"})
        if "high_entropy_va" in policy["required_pe_flags"] and (
            report["format"] != "PE32+" or not report["flags"]["dynamic_base"]
            or not evidence["relocations_present"]
        ):
            findings.append({"code": "invalid_high_entropy_evidence"})
    candidates: dict[str, Path] = {}
    if root is not None:
        release_root = _root(root)
        if not path.resolve().is_relative_to(release_root):
            raise GuardError("Artifact must be inside the explicitly selected release root")
        candidates = _inventory(release_root)
    else:
        with os.scandir(path.parent) as entries:
            for count, entry in enumerate(entries):
                if count >= 40_000:
                    raise GuardError("Too many sibling entries; select a dedicated release directory")
                candidate = Path(entry.path)
                if candidate.stem.casefold() == path.stem.casefold():
                    if _is_link(entry.stat(follow_symlinks=False)):
                        raise GuardError("Artifact sidecar must not be a link/reparse point")
                    candidates[candidate.name] = candidate
    for relative, candidate in sorted(candidates.items()):
        if candidate.suffix.lower() in policy["forbid_extensions"]:
            findings.append({"code": "forbidden_sidecar", "path": relative})
    # Metadata parsing is a separate read; catch ordinary concurrent changes.
    # Windows stat/lstat and fstat can expose different st_ctime semantics.
    # Keep the timestamp comparison handle-to-handle, preserving ChangeTime.
    final = path.lstat()
    if _is_link(final) or not stat.S_ISREG(final.st_mode):
        raise GuardError("Artifact changed after scanning")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        checked = os.fstat(handle.fileno())
    if (checked.st_dev, checked.st_ino, checked.st_size) != (
        final.st_dev, final.st_ino, final.st_size
    ) or (checked.st_dev, checked.st_ino, checked.st_size,
          checked.st_mtime_ns, checked.st_ctime_ns) != identity:
        raise GuardError("Artifact changed after scanning")
    return {
        "ok": not bool(findings), "artifact": artifact, "findings": findings,
        "checks": {"scan_completed": True, "literal_rules": len(policy["forbid_literals"]), "encodings": list(_ENCODINGS),
                   "native": not managed, "debug_metadata_present": debug,
                   "symbol_table_present": symbols,
                   "required_pe_flags_applied": format_name == "pe",
                   "sidecar_scope": "release_root" if root is not None else "same_stem_siblings"},
        "notes": ["Static release checks only; passing is not a decompilation/crack resistance score.",
                  "Runtime plaintext, public exports and the implementation remain observable."]
    }


def read_limited_prefix(path: Path, length: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(length)
