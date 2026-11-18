"""Owned exact-content fixtures, official v1.3 identity, and bounded-work probes."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import platform
import random
import struct
import time
import tracemalloc
import zipfile

import cryptography
import releaseguard


BASELINE_WHEEL_SHA256 = "1bb79222ca7aa1224f3815b2cacf235985e9c9f08bf7330ce0a80099df7bc3a6"
PRIVATE_SOURCE = (b"// Owned server-only example: rg_private_quote_37_19.\n"
                  b"export function quote(quantity) { return quantity * 37 + 19; }\n")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identity(wheel: Path | None) -> dict:
    root = Path(releaseguard.__file__).resolve().parent
    files = sorted(path for path in root.rglob("*")
                   if path.is_file() and "__pycache__" not in path.parts)
    inventory = hashlib.sha256()
    for path in files:
        inventory.update((path.relative_to(root).as_posix() + " " + digest(path.read_bytes()) + "\n").encode())
    if wheel is not None:
        if digest(wheel.read_bytes()) != BASELINE_WHEEL_SHA256:
            raise RuntimeError("Expected the pinned official v1.3.0 wheel")
        if releaseguard.__version__ != "1.3.0" or importlib.metadata.version("open-release-guard") != "1.3.0":
            raise RuntimeError("Expected the installed official v1.3.0 baseline")
        with zipfile.ZipFile(wheel) as archive:
            names = sorted(name for name in archive.namelist()
                           if name.startswith("releaseguard/") and not name.endswith("/"))
            if {name[len("releaseguard/"):] for name in names} != {path.relative_to(root).as_posix() for path in files}:
                raise RuntimeError("Baseline package files differ from the official wheel")
            for name in names:
                if (root / name[len("releaseguard/"):]).read_bytes() != archive.read(name):
                    raise RuntimeError("Baseline package bytes differ from the official wheel")
    return {"version": releaseguard.__version__,
            "installed_distribution_version": importlib.metadata.version("open-release-guard"),
            "package_files": len(files), "package_inventory_sha256": inventory.hexdigest(),
            "python_version": platform.python_version(), "implementation": platform.python_implementation(),
            "cryptography_version": cryptography.__version__}


def zipped(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(entries.items()):
            item = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            item.create_system = 3
            item.external_attr = 0o100644 << 16
            archive.writestr(item, data)
    return output.getvalue()


def asar(data: bytes, *, unpacked: bool = False) -> bytes:
    entry = {"size": len(data), **({"unpacked": True} if unpacked else {"offset": "0"})}
    header = json.dumps({"files": {"app.mjs": entry}}, separators=(",", ":")).encode()
    padding = b"\0" * (-len(header) % 4)
    size = len(header) + len(padding) + 8
    return struct.pack("<4I", 4, size, size - 4, len(header)) + header + padding + (b"" if unpacked else data)


def fixtures(work: Path) -> dict:
    private = work / "private.mjs"
    private.write_bytes(PRIVATE_SOURCE)
    policy = work / "policy.json"
    policy.write_text('{"version":1}\n', encoding="ascii")
    combined = b"export const clientVersion = 2;\n" + PRIVATE_SOURCE + b"export function publicStatus() { return 'ready'; }\n"
    # A long inert comment puts the 64-byte private prefix across the actual
    # 128 KiB matcher read boundary. It remains ordinary valid JavaScript.
    prefix_length = 128 * 1024 - 31
    boundary = b"//" + b"p" * (prefix_length - 3) + b"\n" + PRIVATE_SOURCE
    variants = {
        "exact_whole_file": PRIVATE_SOURCE,
        "prefixed": b"// wrapper\n" + PRIVATE_SOURCE,
        "suffixed": PRIVATE_SOURCE + b"\n// wrapper\n",
        "concatenated_bundle": combined,
        "anchor_crosses_chunk": boundary,
        "changed_comment_boundary": PRIVATE_SOURCE.replace(b"quote_37_19", b"quote_37_20"),
        "public_only": b"export const clientVersion = 2;\n",
    }
    cases = []
    for name, content in variants.items():
        root = work / name
        root.mkdir()
        (root / "app.mjs").write_bytes(content)
        (root / "package.json").write_text(json.dumps({"name": "owned-private-content-control",
            "version": "1.0.0", "type": "module", "main": "app.mjs"}) + "\n", encoding="ascii")
        config = work / (name + "-project.json")
        config.write_text(json.dumps({"version": 1, "product": "owned-private-content-control",
            "root": str(root), "policy": str(policy), "private_input_files": [str(private)]}) + "\n", encoding="ascii")
        cases.append({"name": name, "root": str(root), "config": str(config), "script": "app.mjs",
            "source_bytes": len(content), "source_sha256": digest(content),
            "contains_complete_reference": PRIVATE_SOURCE in content,
            "expected_private_function_count": 0 if name == "public_only" else 1,
            "baseline_ok": name != "exact_whole_file",
            "candidate_ok": PRIVATE_SOURCE not in content})
    container_layouts = {
        "deflated_zip": {"app.zip": zipped({"app.mjs": combined})},
        "nested_zip": {"app.zip": zipped({"inner.zip": zipped({"app.mjs": combined})})},
        "packed_asar": {"app.asar": asar(combined)},
        "zip_packed_asar": {"app.zip": zipped({"app.asar": asar(combined)})},
        "unpacked_asar": {"app.asar": asar(combined, unpacked=True), "app.asar.unpacked/app.mjs": combined},
        "zip_unpacked_asar": {"app.zip": zipped({"app.asar": asar(combined, unpacked=True),
                                                  "app.asar.unpacked/app.mjs": combined})},
    }
    containers = []
    for name, entries in container_layouts.items():
        root = work / name
        root.mkdir()
        for name_in_root, content in entries.items():
            target = root / name_in_root
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        containers.append({"name": name, "root": str(root), "baseline_ok": True, "candidate_ok": False,
                           "shared_contained_payload_sha256": digest(combined)})
    return {"private_file": str(private), "private_reference_bytes": len(PRIVATE_SOURCE),
            "private_reference_sha256": digest(PRIVATE_SOURCE), "policy": str(policy),
            "javascript_cases": cases, "container_variants": containers}


def resources(work: Path) -> dict:
    from releaseguard.private_inputs import (
        PrivateContentBudgetError, PrivateContentScanner, snapshot_private_inputs,
    )
    directory = work / "resource-probe"
    directory.mkdir()
    public = directory / "public"
    public.mkdir()
    count = 0

    def reference(data: bytes):
        nonlocal count
        count += 1
        path = directory / ("private-" + str(count))
        path.write_bytes(data)
        return snapshot_private_inputs([path], root=public)[0]

    def measure(name, references, payload, expected, *, repetitions=1):
        scanner = PrivateContentScanner(references)
        stream = io.BytesIO(payload)
        tracemalloc.start()
        start = time.perf_counter()
        reason = None
        matches = ()
        try:
            for _ in range(repetitions):
                matches = scanner.scan(stream, len(payload))
        except PrivateContentBudgetError as error:
            reason = error.reason
        elapsed = time.perf_counter() - start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        if (reason if reason else matches) != expected:
            raise RuntimeError("Unexpected bounded-resource probe result: " + name)
        return {"name": name, "public_bytes": len(payload) * repetitions,
            "reference_count": len(references), "retained_anchor_bytes": sum(len(item.anchor) for item in references),
            "seconds": round(elapsed, 6), "traced_matcher_peak_bytes": peak,
            "candidates_checked": scanner.candidates_checked, "verification_bytes": scanner.verification_bytes,
            "matches": list(matches), "incomplete_reason": reason}

    generator = random.Random(14000)
    references = [reference(generator.randbytes(64) + b"private implementation") for _ in range(64)]
    public_data = (b"public data\n" * ((64 * 1024 * 1024 + 11) // 12))[:64 * 1024 * 1024]
    results = [
        measure("64_references_256MiB_public_control", references, public_data, (), repetitions=4),
        measure("single_reference_64MiB_public_control", [reference(PRIVATE_SOURCE)], public_data, ()),
        measure("anchor_crosses_128KiB_chunk", [reference(PRIVATE_SOURCE)],
                b"p" * (128 * 1024 - 31) + PRIVATE_SOURCE + b"suffix", (0,)),
        measure("short_reference_1B", [reference(b"\0")], b"public\0bytes", (0,)),
        measure("4096_candidates_fail_closed", [reference(b"a" * 64 + b"b")], b"a" * 5000,
                "private_content_candidate_limit"),
        measure("512MiB_verification_fail_closed", [reference(b"a" * (8 * 1024 * 1024 - 1) + b"b")],
                b"a" * (8 * 1024 * 1024 + 128), "private_content_verification_limit"),
    ]
    return {"python_version": platform.python_version(), "platform": platform.platform(),
        "method": "Inputs allocated before tracemalloc; one run per case including tracing overhead; not a general throughput claim.",
        "memory_scope": "Python matcher allocations only; excludes preallocated fixtures, interpreter, scanner metadata and container buffers.",
        "results": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("identity", "fixtures", "resources"))
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--work", type=Path)
    args = parser.parse_args()
    if args.mode == "identity":
        result = identity(args.wheel)
    else:
        if args.work is None or not args.work.is_dir():
            parser.error("--work must be an existing owned scratch directory")
        result = fixtures(args.work.resolve()) if args.mode == "fixtures" else resources(args.work.resolve())
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
