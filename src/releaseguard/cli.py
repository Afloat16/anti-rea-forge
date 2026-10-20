"""CLI for release inspection and authenticity checks."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
import sys
from pathlib import Path

from . import __version__
from .core import (
    GuardError, create_manifest, generate_keys, issue_license, key_id,
    load_private_key, load_public_key, read_document, save_document,
    verify_license, verify_manifest, canonical, parse_json, write_new, _is_link,
)
from .pe import audit_pe
from .native import gate, init_native
from .passwords import create_password_verifier, verify_password
from .sealed import generate_asset_key, load_asset_key, seal_asset, open_asset, MAX_ASSET_BYTES
from .capabilities import issue_capability, consume_capability, ReplayStore, MAX_REQUEST_BYTES


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        description="Open Release Guard: release authenticity, native hardening and server authorization. "
                    "Local checks do not prevent decompilation or patched-client bypass."
    )
    cli.add_argument("--version", action="version", version=__version__)
    commands = cli.add_subparsers(dest="command", required=True)

    audit = commands.add_parser("audit", help="Read-only audit of a Windows PE EXE/DLL")
    audit.add_argument("path", type=Path)
    audit.add_argument("--strict", action="store_true", help="Exit 3 if the report has warnings")

    keys = commands.add_parser("keygen", help="Create a passphrase-encrypted Ed25519 issuer key")
    keys.add_argument("--private", type=Path, required=True, help="Private PEM; keep outside releases and Git")
    keys.add_argument("--public", type=Path, required=True, help="Public PEM; distribute through a trusted channel")

    sign = commands.add_parser("manifest-sign", help="Sign the complete contents of a release directory")
    sign.add_argument("--root", type=Path, required=True)
    sign.add_argument("--private", type=Path, required=True)
    sign.add_argument("--product", required=True)
    sign.add_argument("--release", required=True)
    sign.add_argument("--out", type=Path, required=True, help="New file OUTSIDE the release directory")

    check = commands.add_parser("manifest-verify", help="Verify signature and exact release file set")
    check.add_argument("manifest", type=Path)
    check.add_argument("--root", type=Path, required=True)
    check.add_argument("--public", type=Path, required=True, help="Previously trusted issuer public key")
    check.add_argument("--product", required=True)
    check.add_argument("--release", help="Pin an expected release; recommended to prevent accepting older releases")

    issue = commands.add_parser("license-issue", help="Issue a signed, portable, offline license")
    issue.add_argument("--private", type=Path, required=True)
    issue.add_argument("--product", required=True)
    issue.add_argument("--subject", required=True)
    issue.add_argument("--days", type=int, default=365)
    issue.add_argument("--feature", action="append", default=[])
    issue.add_argument("--out", type=Path, required=True)

    license_check = commands.add_parser("license-verify", help="Verify license signature, time, product and features")
    license_check.add_argument("license", type=Path)
    license_check.add_argument("--public", type=Path, required=True)
    license_check.add_argument("--product", required=True)
    license_check.add_argument("--subject", help="Optional expected license holder")
    license_check.add_argument("--require-feature", action="append", default=[])

    native = commands.add_parser("native-init", help="Generate C++17/CMake build assets with a public diversification seed")
    native.add_argument("--out", type=Path, required=True, help="Fresh generated directory, or unchanged output to reuse")
    native.add_argument("--seed", help="Optional 16 hexadecimal digits for reproducible builds; not a secret key")

    release_gate = commands.add_parser("gate", help="Fail a build if a PE/ELF artifact violates an explicit static policy")
    release_gate.add_argument("artifact", type=Path)
    release_gate.add_argument("--policy", type=Path, required=True)
    release_gate.add_argument("--root", type=Path, help="Check forbidden sidecar extensions throughout this release directory")

    password_create = commands.add_parser("password-create", help="Create a salted, one-way Argon2id password verifier")
    password_create.add_argument("--out", type=Path, required=True)
    password_check = commands.add_parser("password-check", help="Check a password against a bounded Argon2id verifier")
    password_check.add_argument("verifier", type=Path)
    asset_keygen = commands.add_parser("asset-keygen", help="Create a random 256-bit asset key; keep it outside releases")
    asset_keygen.add_argument("--out", type=Path, required=True)
    for command, description in (("asset-seal", "Encrypt a data asset with an external key and trusted context"),
                                 ("asset-open", "Authenticate a sealed data asset before writing plaintext")):
        asset = commands.add_parser(command, help=description)
        asset.add_argument("input", type=Path)
        asset.add_argument("--key-file", type=Path, required=True, help="External 32-byte binary key, never a build seed")
        for name in ("product", "release", "purpose", "asset-id"):
            asset.add_argument("--" + name, required=True, help="Expected context from trusted application configuration")
        asset.add_argument("--out", type=Path, required=True, help="New output file; existing files are never replaced")
    replay_init = commands.add_parser("replay-store-init", help="Initialize a NEW persistent replay database in the trusted server environment")
    replay_init.add_argument("--out", type=Path, required=True)
    for command, description in (("capability-issue", "Issuer only: sign a short-lived capability for exact request bytes"),
                                 ("capability-consume", "Server only: verify and irrevocably consume one request authorization")):
        capability = commands.add_parser(command, help=description)
        if command == "capability-issue":
            capability.add_argument("--private", type=Path, required=True)
            capability.add_argument("--ttl", type=int, default=60, help="Validity in seconds, 1..300 (default: 60)")
            capability.add_argument("--out", type=Path, required=True)
        else:
            capability.add_argument("capability", type=Path)
            capability.add_argument("--public", type=Path, required=True, help="Previously trusted issuer public key")
            capability.add_argument("--store", type=Path, required=True, help="Existing trusted server replay database; never a client cache")
        for name in ("subject", "audience", "product", "operation"):
            capability.add_argument("--" + name, required=True, help="Expected value from authenticated server context or trusted issuer policy")
        capability.add_argument("--request", type=Path, required=True, help="Exact immutable request bytes the server will execute (maximum 1 MiB)")
    return cli


def _passphrase(confirm: bool = False) -> bytes:
    configured = os.environ.get("RELEASEGUARD_PASSPHRASE")
    if configured is not None:
        value = configured
    else:
        if not sys.stdin.isatty():
            raise GuardError("No interactive terminal. Set RELEASEGUARD_PASSPHRASE via a secret manager.")
        value = getpass.getpass("Issuer key passphrase: ")
        if confirm and getpass.getpass("Confirm passphrase: ") != value:
            raise GuardError("Passphrases do not match")
    if not value:
        raise GuardError("An empty passphrase is not allowed")
    return value.encode("utf-8")


def _outside_root(path: Path, root: Path, label: str) -> None:
    if path.resolve().is_relative_to(root.resolve()):
        raise GuardError(f"{label} must be outside the release directory")


def _user_password(confirm: bool = False) -> bytes:
    value = os.environ.get("RELEASEGUARD_USER_PASSWORD")
    if value is None:
        if not sys.stdin.isatty():
            raise GuardError("No interactive terminal. Set RELEASEGUARD_USER_PASSWORD via a secret manager.")
        value = getpass.getpass("User password: ")
        if confirm and getpass.getpass("Confirm user password: ") != value:
            raise GuardError("Passwords do not match")
    try:
        return value.encode("utf-8")
    except UnicodeError as exc:
        raise GuardError("Password must be valid UTF-8") from exc


def _crypto_input(path: Path, limit: int) -> bytes:
    """Bound file input and reject links/FIFOs before consuming a crypto record."""
    before = path.lstat()
    if _is_link(before) or not stat.S_ISREG(before.st_mode):
        raise GuardError("Crypto input must be a regular file, not a link or special file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode) or _is_link(opened) or (
            opened.st_dev, opened.st_ino, opened.st_size
        ) != (before.st_dev, before.st_ino, before.st_size):
            raise GuardError("Crypto input changed before reading")
        if opened.st_size > limit:
            raise GuardError("Crypto input exceeds its size limit")
        content = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
    if len(content) > limit or len(content) != opened.st_size or (
        opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns
    ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise GuardError("Crypto input changed or exceeded its size limit")
    return content


def _run(args: argparse.Namespace) -> tuple[dict, int]:
    if args.command == "replay-store-init":
        ReplayStore.create(args.out)
        return {"ok": True, "replay_store": str(args.out)}, 0
    if args.command in {"capability-issue", "capability-consume"}:
        request = _crypto_input(args.request, MAX_REQUEST_BYTES)
        expected = {name: getattr(args, name) for name in ("subject", "audience", "product", "operation")}
        if args.command == "capability-issue":
            private = load_private_key(args.private, _passphrase())
            document = issue_capability(private, **expected, request=request, ttl_seconds=args.ttl)
            # Bearer capabilities are credentials, even though their claims are readable.
            write_new(args.out, canonical(document) + b"\n", secret=True)
            return {"ok": True, "capability": str(args.out), "ttl_seconds": args.ttl}, 0
        document = parse_json(_crypto_input(args.capability, 16384))
        consume_capability(document, load_public_key(args.public), ReplayStore(args.store),
                           **expected, request=request)
        return {"ok": True, "capability_consumed": True}, 0
    if args.command == "password-create":
        document = create_password_verifier(_user_password(confirm=True))
        write_new(args.out, canonical(document) + b"\n", secret=True)
        return {"ok": True, "verifier": str(args.out), "algorithm": "argon2id"}, 0
    if args.command == "password-check":
        # Parse a bounded record before prompting; verify_password validates its profile.
        document = parse_json(_crypto_input(args.verifier, 4096))
        passed = verify_password(_user_password(), document)
        return {"ok": passed, "password_verified": passed}, 0 if passed else 3
    if args.command == "asset-keygen":
        generate_asset_key(args.out)
        return {"ok": True, "key_file": str(args.out), "key_bits": 256}, 0
    if args.command in {"asset-seal", "asset-open"}:
        key = load_asset_key(args.key_file)
        context = (args.product, args.release, args.purpose, args.asset_id)
        if args.command == "asset-seal":
            plaintext = _crypto_input(args.input, MAX_ASSET_BYTES)
            document = seal_asset(plaintext, key, *context)
            save_document(args.out, document)
            return {"ok": True, "sealed_asset": str(args.out), "plaintext_bytes": len(plaintext)}, 0
        document = parse_json(_crypto_input(args.input, 2 * MAX_ASSET_BYTES))
        plaintext = open_asset(document, key, *context)
        # No output is created until authentication succeeds. This never executes data.
        write_new(args.out, plaintext, secret=True)
        return {"ok": True, "plaintext_file": str(args.out), "plaintext_bytes": len(plaintext)}, 0
    if args.command == "native-init":
        return init_native(args.out, args.seed), 0
    if args.command == "gate":
        result = gate(args.artifact, args.policy, args.root)
        return result, 0 if result["ok"] else 3
    if args.command == "audit":
        report = audit_pe(args.path)
        passed = not bool(report["warnings"])
        code = 3 if args.strict and not passed else 0
        return {"ok": code == 0, "policy_passed": passed, "audit": report}, code
    if args.command == "keygen":
        fingerprint = generate_keys(args.private, args.public, _passphrase(confirm=True))
        return {"ok": True, "public_key_sha256": fingerprint,
                "public_key": str(args.public), "private_key": str(args.private)}, 0
    if args.command == "manifest-sign":
        _outside_root(args.out, args.root, "Manifest output")
        _outside_root(args.private, args.root, "Private key")
        private = load_private_key(args.private, _passphrase())
        document = create_manifest(args.root, args.product, args.release, private)
        save_document(args.out, document)
        return {"ok": True, "manifest": str(args.out),
                "issuer_sha256": key_id(private.public_key())}, 0
    if args.command == "manifest-verify":
        body = verify_manifest(read_document(args.manifest), args.root,
                               load_public_key(args.public), args.product, args.release)
        return {"ok": True, "product": body["product"], "release": body["release"],
                "files_verified": len(body["files"])}, 0
    if args.command == "license-issue":
        private = load_private_key(args.private, _passphrase())
        document = issue_license(args.product, args.subject, args.days, args.feature, private)
        save_document(args.out, document)
        return {"ok": True, "license": str(args.out),
                "issuer_sha256": key_id(private.public_key())}, 0
    if args.command == "license-verify":
        body = verify_license(read_document(args.license), load_public_key(args.public), args.product,
                              subject=args.subject, required_features=args.require_feature)
        return {"ok": True, "claims": body}, 0
    raise GuardError("Unknown command")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result, code = _run(args)
    except (ValueError, OSError, OverflowError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=True), file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print('{"ok": false, "error": "Operation cancelled"}', file=sys.stderr)
        return 130
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
