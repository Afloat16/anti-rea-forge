"""CLI for release inspection and authenticity checks."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from . import __version__
from .core import (
    GuardError, create_manifest, generate_keys, issue_license, key_id,
    load_private_key, load_public_key, read_document, save_document,
    verify_license, verify_manifest,
)
from .pe import audit_pe
from .native import gate, init_native


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        description="Open Release Guard: release authenticity and PE audits. "
                    "Does not prevent decompilation or patched-client bypass."
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


def _run(args: argparse.Namespace) -> tuple[dict, int]:
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
