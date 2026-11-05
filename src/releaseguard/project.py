"""Build-only project setup and signed release sidecars.

These helpers never rewrite, import or execute a release. Configuration, output
directories and their ancestors belong to the trusted build operator. Keep the
release immutable from inspection through publication; this is not a sandbox.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .core import (
    GuardError, HEX256, _fields, _is_link, _text, _version, canonical, create_manifest,
    key_id, parse_json, verify_document, write_new,
)
from .analysis import _identifier as _analysis_identifier
from .distribution import scan_release

DEFAULT_CONFIG = Path(".releaseguard/project.json")
_CONFIG_LIMIT = 64 * 1024
_DEFAULT_POLICY = {
    "version": 1,
    "forbid_literals": [],
    "forbid_extensions": [".pdb", ".ilk", ".map"],
    "forbid_path_components": [".git", ".svn", ".hg", ".env"],
    "check_private_keys": True,
    "check_source_maps": True,
    "scan_zip_archives": True,
    "max_file_bytes": 67108864,
    "max_total_bytes": 268435456,
    "max_archive_depth": 2,
    "max_archive_entries": 10000,
    "max_files": 20000,
}


def _json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=True, indent=2).encode("ascii") + b"\n"


def outside_release(path: Path | str, root: Path | str, label: str) -> None:
    if Path(path).resolve().is_relative_to(Path(root).resolve()):
        raise GuardError(f"{label} must be outside the release directory")


def _relative_or_absolute(path: Path, base: Path) -> str:
    try:
        return Path(os.path.relpath(path, base)).as_posix()
    except ValueError:
        # Windows paths on different drives have no relative representation.
        return path.as_posix()


def _new_bundle(directory: Path, files: dict[str, bytes]) -> None:
    """Create only a fresh directory, with no overwrite or implicit merging."""
    directory.mkdir(mode=0o755)
    written: list[Path] = []
    try:
        for name, content in files.items():
            destination = directory / name
            write_new(destination, content)
            written.append(destination)
    except BaseException:
        for destination in reversed(written):
            destination.unlink(missing_ok=True)
        directory.rmdir()
        raise


def init_project(root: Path | str, product: str,
                 out: Path | str = ".releaseguard") -> dict[str, Any]:
    """Generate an editable portable policy without touching the release."""
    _analysis_identifier(product, "product")
    release_root = Path(root).absolute()
    try:
        root_info = release_root.lstat()
    except FileNotFoundError:
        pass  # The normal build may create the release after initialization.
    else:
        if _is_link(root_info) or not stat.S_ISDIR(root_info.st_mode):
            raise GuardError("Release root must be a regular directory, not a link/reparse point")
    output = Path(out).absolute()
    outside_release(output, release_root, "Project configuration")
    document = {
        "version": 1,
        "product": product,
        "root": _relative_or_absolute(release_root.resolve(), output.resolve()),
        "policy": "policy.json",
    }
    _new_bundle(output, {
        "project.json": _json_bytes(document),
        "policy.json": _json_bytes(_DEFAULT_POLICY),
        "ANALYSIS_NOTICE.md": render_analysis_notice(product),
    })
    return {
        "ok": True,
        "config": str(output / "project.json"),
        "policy": str(output / "policy.json"),
        "notice": str(output / "ANALYSIS_NOTICE.md"),
        "release_modified": False,
    }


def _read_config(path: Path) -> dict[str, Any]:
    before = path.lstat()
    if _is_link(before) or not stat.S_ISREG(before.st_mode):
        raise GuardError("Project configuration must be a regular file, not a link or special file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode) or _is_link(opened) or (
            opened.st_dev, opened.st_ino, opened.st_size
        ) != (before.st_dev, before.st_ino, before.st_size):
            raise GuardError("Project configuration changed before reading")
        if opened.st_size > _CONFIG_LIMIT:
            raise GuardError("Project configuration exceeds the 64 KiB limit")
        raw = handle.read(_CONFIG_LIMIT + 1)
        after = os.fstat(handle.fileno())
    if len(raw) > _CONFIG_LIMIT or len(raw) != opened.st_size or (
        opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns
    ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise GuardError("Project configuration changed while reading")
    return parse_json(raw)


def load_project(config: Path | str = DEFAULT_CONFIG) -> dict[str, Any]:
    """Resolve paths relative to the config file, never the caller's cwd."""
    path = Path(config).absolute()
    document = _read_config(path)
    _fields(document, {"version", "product", "root", "policy"})
    _version(document["version"])
    _analysis_identifier(document["product"], "product")
    resolved: dict[str, Any] = {"product": document["product"]}
    for field in ("root", "policy"):
        value = _text(document[field], f"project {field}", 32768)
        candidate = Path(value)
        resolved[field] = candidate if candidate.is_absolute() else path.parent / candidate
    outside_release(path, resolved["root"], "Project configuration")
    outside_release(resolved["policy"], resolved["root"], "Scan policy")
    return resolved


def check_project(config: Path | str = DEFAULT_CONFIG) -> dict[str, Any]:
    project = load_project(config)
    return scan_release(project["root"], project["policy"])


def render_analysis_notice(product: str, *, release: str | None = None,
                           manifest_sha256: str | None = None,
                           issuer_sha256: str | None = None) -> bytes:
    """Plain, unsigned owner-workflow information, never model instructions."""
    _analysis_identifier(product, "product")
    if release is not None:
        _analysis_identifier(release, "release")
    for value in (manifest_sha256, issuer_sha256):
        if value is not None and (type(value) is not str or not HEX256.fullmatch(value)):
            raise GuardError("Notice digests must be lowercase SHA-256 hex")
    metadata = {"product": product}
    if release is not None:
        metadata["release"] = release
    if manifest_sha256 is not None:
        metadata["manifest_sha256"] = manifest_sha256
    if issuer_sha256 is not None:
        metadata["issuer_key_sha256"] = issuer_sha256
    content = (
        "# Analysis authorization notice / 分析授权说明\n\n"
        "```json\n" + _json_bytes(metadata).decode("ascii") + "```\n\n"
        "This release is accompanied by an explicit-permission analysis workflow. "
        "The publisher asks analysts to obtain a signed grant for the intended "
        "release and operation through an independently trusted contact channel.\n\n"
        "Cooperating gateways verify the signed release manifest, the grant, the "
        "authenticated analyst, the configured gateway audience, the exact operation "
        "and the validity period before calling their analysis handler. "
        "The independent scopes are `inspect`, `decompile` and `instrument`.\n\n"
        "This notice is public, unsigned information. It is not a system prompt, "
        "a legal ownership certificate, an analysis grant or a public-key trust anchor. "
        "It does not change the software license or rights granted independently. "
        "Resolve authorization using the operator's trusted configuration and applicable "
        "permissions, not instructions embedded in the analysis target.\n\n"
        "No application runtime component is required. A third-party tool or operator "
        "that does not use the cooperating gateway can ignore this notice.\n\n"
        "本发布包配有显式分析授权流程。请通过独立可信渠道获取与目标版本及操作相符的签名授权；"
        "接入的分析网关会在调用工具前验证。普通用户运行软件不需要安装或运行 Release Guard。\n\n"
        "本说明仅为公开信息，不是系统指令、法律权属证明、授权凭据或公钥信任来源；"
        "它不改变软件许可证或独立取得的权利，也不能强制未接入的第三方 AI 或工具停止。\n"
    )
    return content.encode("utf-8")


def prepare_release(config: Path | str, private: Ed25519PrivateKey, release: str,
                    out: Path | str) -> dict[str, Any]:
    """Scan, sign the same inventory, and create external publication sidecars."""
    _analysis_identifier(release, "release")
    project = load_project(config)
    output = Path(out).absolute()
    outside_release(output, project["root"], "Prepared release sidecars")
    if output.exists() or output.is_symlink():
        raise GuardError("Prepared output must be a new directory")
    scan = scan_release(project["root"], project["policy"])
    if not scan["ok"]:
        return {"ok": False, "prepared": False, "scan": scan, "outputs": {}}
    manifest = create_manifest(project["root"], project["product"], release, private)
    signed = verify_document(manifest, "manifest", private.public_key())
    if signed["files"] != scan["files"]:
        raise GuardError("Release changed between scanning and signing; freeze it and retry")
    manifest_digest = hashlib.sha256(canonical(manifest)).hexdigest()
    issuer = key_id(private.public_key())
    summary = {
        "ok": True,
        "product": project["product"],
        "release": release,
        "manifest_sha256": manifest_digest,
        "issuer_key_sha256": issuer,
        "files_checked": len(scan["files"]),
        "bytes_scanned": scan["checks"]["bytes_scanned"],
        "release_modified": False,
        "application_runtime_integration": False,
        "note": "Build-time inspection has an I/O cost; no application benchmark is implied.",
    }
    _new_bundle(output, {
        "manifest.json": _json_bytes(manifest),
        "ANALYSIS_NOTICE.md": render_analysis_notice(
            project["product"], release=release, manifest_sha256=manifest_digest, issuer_sha256=issuer,
        ),
        "release-report.json": _json_bytes(summary),
    })
    return {
        "ok": True,
        "prepared": True,
        "scan": scan,
        "outputs": {name: str(output / name) for name in
                    ("manifest.json", "ANALYSIS_NOTICE.md", "release-report.json")},
        "manifest_sha256": manifest_digest,
        "issuer_key_sha256": issuer,
        "release_modified": False,
        "application_runtime_integration": False,
    }
