"""Trusted fixture/recovery helper for python_key_recovery.mjs.

Only the generate operation compiles and executes Python, and only source
authored below. The recovery operation reads integer values emitted by actual
REA, tries ordinary int.to_bytes reconstructions, and authenticates an owned
AES-GCM ciphertext. No examined code object is unmarshalled or executed during
recovery. All fixture keys are public synthetic data; never use them in a product.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import importlib.metadata
import importlib.util
import json
import marshal
from pathlib import Path
import platform
import struct
import sys
import zipfile

import cryptography
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import releaseguard


KEY = bytes(range(224, 256))
OTHER_KEY = bytes(range(128, 160))
FILENAME = "/build/owned-private/client-blue/pricing.py"
BEHAVIOR = [11, 11, 18, 74]
PUBLIC_SOURCE = "def public_price(quantity):\n    return max(0, quantity) * 7 + 11\n"
MAIN_SOURCE = ('\nif __name__ == "__main__":\n'
               '    print([public_price(-3), public_price(0), public_price(1), public_price(9)])\n')


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def identity(wheel: Path | None) -> dict:
    root = Path(releaseguard.__file__).resolve().parent
    files = sorted(path for path in root.rglob("*")
                   if path.is_file() and "__pycache__" not in path.parts)
    inventory = hashlib.sha256()
    for path in files:
        inventory.update((path.relative_to(root).as_posix() + " " + digest(path.read_bytes()) + "\n").encode())
    if wheel:
        require(releaseguard.__version__ == importlib.metadata.version("open-release-guard") == "1.2.0",
                "Expected the installed official 1.2.0 baseline")
        with zipfile.ZipFile(wheel) as archive:
            names = sorted(name for name in archive.namelist()
                           if name.startswith("releaseguard/") and not name.endswith("/"))
            require({name[len("releaseguard/"):] for name in names}
                    == {path.relative_to(root).as_posix() for path in files},
                    "Installed baseline files differ from the official wheel")
            for name in names:
                require((root / name[len("releaseguard/"):]).read_bytes() == archive.read(name),
                        "Installed baseline bytes differ from the official wheel")
    return {"version": releaseguard.__version__,
            "installed_distribution_version": importlib.metadata.version("open-release-guard"),
            "package_files": len(files), "package_inventory_sha256": inventory.hexdigest(),
            "python_version": platform.python_version(), "implementation": platform.python_implementation(),
            "cryptography_version": cryptography.__version__}


def fixture_specs():
    for version in (2, 4):
        for order in ("big", "little"):
            for signed in (False, True):
                yield (f"marshal{version}_{order}_{'signed' if signed else 'unsigned'}",
                       KEY, KEY, order, signed, version, "disclosure")
    for where, key in (("prefix", b"\0" * 4 + bytes(range(224, 252))),
                       ("suffix", bytes(range(224, 252)) + b"\0" * 4)):
        for order in ("big", "little"):
            signed = (where, order) in {("prefix", "little"), ("suffix", "big")}
            yield (f"leading_zero_{where}_{order}", key, key, order, signed, 4, "disclosure")
    yield ("ordinary_public_pyc", None, KEY, "big", False, 4, "public-control")
    yield ("unconfigured_key_boundary", KEY, OTHER_KEY, "big", False, 4, "unconfigured-key-boundary")
    yield ("short_signed_integer_boundary", b"\xff" * 32, b"\xff" * 32,
           "big", True, 4, "short-integer-boundary")


def generate(work: Path) -> dict:
    work.mkdir()
    policy = work / "policy.json"
    policy.write_text('{"version":1}\n', encoding="ascii")
    rows = []
    for name, embedded, configured, order, signed, version, kind in fixture_specs():
        root = work / name
        disk, archive_dir = root / "disk", root / "zipapp"
        disk.mkdir(parents=True)
        archive_dir.mkdir()
        source = PUBLIC_SOURCE
        if embedded is not None:
            integer = int.from_bytes(embedded, order, signed=signed)
            for function in ("asset_key", "reused_asset_key"):
                source += (f"\ndef {function}():\n"
                           f"    return ({integer}).to_bytes(32, {order!r}, signed={signed!r})\n")
        source += MAIN_SOURCE
        code = compile(source, FILENAME, "exec", dont_inherit=True, optimize=0)
        body = marshal.dumps(code, version)
        pyc = importlib.util.MAGIC_NUMBER + struct.pack("<I", 3) + importlib.util.source_hash(source.encode()) + body
        path = disk / "pricing.pyc"
        path.write_bytes(pyc)
        # This is a locally authored fixture, not attacker-supplied bytecode.
        loader = importlib.machinery.SourcelessFileLoader("owned_pricing_fixture", str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        observed = [module.public_price(q) for q in (-3, 0, 1, 9)]
        require(observed == BEHAVIOR, "Owned fixture behavior differs")
        if embedded is not None:
            require(module.asset_key() == module.reused_asset_key() == embedded,
                    "Owned integer fixture cannot reconstruct its exact 32-byte key")
            require(embedded not in pyc and embedded.hex().encode() not in pyc,
                    "This regression requires the raw and hex key to be absent")
        archive_path = archive_dir / "application.pyz"
        info = zipfile.ZipInfo("__main__.pyc", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(info, pyc)
        with zipfile.ZipFile(archive_path) as archive:
            require(archive.read("__main__.pyc") == pyc, "Archive changed fixture bytes")
        known = embedded if embedded is not None else KEY
        (root / "owned.key").write_bytes(known)
        (root / "configured.key").write_bytes(configured)
        nonce, aad, plaintext = bytes(range(12)), ("owned-pyc:" + name).encode(), b"owned unpublished pricing table"
        crypto = {"nonce": nonce.hex(), "aad": aad.hex(),
                  "ciphertext": AESGCM(known).encrypt(nonce, plaintext, aad).hex(),
                  "expected_plaintext_sha256": digest(plaintext)}
        (root / "crypto.json").write_text(json.dumps(crypto), encoding="ascii")
        row = {"id": name, "kind": kind, "marshal_version": version, "byteorder": order,
               "signed": signed, "root": str(root), "artifact_sha256": digest(pyc), "artifact_bytes": len(pyc),
               "zipapp_sha256": digest(archive_path.read_bytes()), "zipapp_bytes": archive_path.stat().st_size,
               "source_sha256": digest(source.encode()), "magic": int.from_bytes(pyc[:2], "little"),
               "behavior": observed, "key_reconstruction_verified": embedded is not None,
               "raw_and_hex_embedded_key_absent": embedded is not None,
               "expected_recovery": embedded is not None,
               "expected_candidate_gate": ("incomplete" if kind == "short-integer-boundary"
                                            else "reject" if kind == "disclosure" else "allow")}
        rows.append(row)
    return {"policy": str(policy), "fixtures": rows, "python": platform.python_version(),
            "implementation": platform.python_implementation(), "magic": int.from_bytes(importlib.util.MAGIC_NUMBER, "little")}


def recover(root: Path) -> dict:
    raw = sys.stdin.buffer.read(16 * 1024 * 1024 + 1)
    require(len(raw) <= 16 * 1024 * 1024, "REA evidence exceeds its budget")
    evidence = json.loads(raw)
    require(evidence["operation"] == "inspect_python_pyc" and evidence["provider"]["id"] == "rea-python-pyc",
            "Expected actual REA PYC evidence")
    result = evidence["normalized_result"]
    require(result["coverage"]["status"] == "complete", "Incomplete REA analysis is not protection evidence")
    require(result["artifact"]["sha256"] == digest((root / "disk" / "pricing.pyc").read_bytes()),
            "REA analyzed a different artifact")
    # No source, key, or artifact bytes are used to generate recovery candidates.
    # They come only from the ordinary integer values reported by real REA.
    integers = {int(item["value"]) for code in result["code_objects"] for item in code["consts"]
                if item["kind"] == "int" and isinstance(item.get("value"), str)}
    candidates = set()
    for integer in integers:
        for order in ("big", "little"):
            for signed in (False, True):
                try:
                    candidates.add(integer.to_bytes(32, order, signed=signed))
                except OverflowError:
                    pass
    crypto = json.loads((root / "crypto.json").read_text())
    recovered = set()
    for candidate in candidates:
        try:
            plaintext = AESGCM(candidate).decrypt(bytes.fromhex(crypto["nonce"]),
                                                bytes.fromhex(crypto["ciphertext"]), bytes.fromhex(crypto["aad"]))
        except InvalidTag:
            continue
        require(digest(plaintext) == crypto["expected_plaintext_sha256"], "Unexpected authenticated plaintext")
        recovered.add(candidate)
    expected_key = (root / "owned.key").read_bytes()  # Oracle comparison only, after recovery.
    require(not recovered or recovered == {expected_key}, "Recovery selected an unexpected key")
    return {"rea_integer_candidates": len(integers), "reconstruction_candidates": len(candidates),
            "authenticated_key_candidates": len(recovered), "exact_key_recovered": bool(recovered),
            "aes_plaintext_verified": bool(recovered),
            "public_function_name_visible": any(c["name"] == "public_price" for c in result["code_objects"]),
            "original_filename_occurrences": sum(c["filename"] == FILENAME for c in result["code_objects"]),
            "coverage": result["coverage"], "header_magic": result["header"]["magic"],
            "python_version": result["header"]["python_version"],
            "rea_claims_source_recovery": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("identity", "generate", "recover"))
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--case", type=Path)
    args = parser.parse_args()
    if args.action == "identity":
        result = identity(args.wheel)
    elif args.action == "generate":
        require(args.work is not None, "--work is required")
        result = generate(args.work)
    else:
        require(args.case is not None, "--case is required")
        result = recover(args.case)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
