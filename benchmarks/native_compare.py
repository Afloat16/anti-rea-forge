#!/usr/bin/env python3
"""Compare the project's own Linux/GCC example before and after release checks.

Run after installing this checkout (``python -m pip install -e .``), or with
``PYTHONPATH=src`` from the repository root. This is a reproducible static
artifact/functional comparison, not a REA or crack-resistance benchmark. The
script compiles and executes only ``examples/main.cpp`` from this checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
from typing import Any

try:
    from releaseguard import __version__
    from releaseguard.core import GuardError, write_new
    from releaseguard.native import gate, init_native
except ImportError as exc:
    raise SystemExit(
        "releaseguard is unavailable; install this checkout with "
        "'python -m pip install -e .' or run with PYTHONPATH=src."
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples" / "main.cpp"
POLICY = ROOT / "examples" / "policy.json"
DEFAULT_SEED = "1af38c4e60b975d2"
MARKER = b"releaseguard-demo-private-literal"
BASELINE_FLAGS = ["-std=c++17", "-O2"]
PROTECTED_FLAGS = [
    "-std=c++17", "-O2", "-flto", "-fvisibility=hidden",
    "-fvisibility-inlines-hidden", "-fstack-protector-strong", "-fPIE",
    "-pie", "-s", "-Wl,-z,relro,-z,now,-z,noexecstack",
    "-DRELEASEGUARD_EXAMPLE_PROTECTED=1",
]


def run(command: list[str], *, cwd: Path, timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=timeout)
    if result.returncode:
        # Diagnostics are stderr only; successful JSON contains no build paths.
        diagnostic = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        raise RuntimeError(f"{Path(command[0]).name} failed ({result.returncode}):\n{diagnostic}")
    return result


def without_temporary_paths(report: dict[str, Any]) -> dict[str, Any]:
    result = dict(report)
    result["artifact"] = dict(report["artifact"])
    result["artifact"].pop("path", None)
    return result


def describe(report: dict[str, Any], flags: list[str]) -> dict[str, Any]:
    sanitized = without_temporary_paths(report)
    return {"flags": flags, "binary": sanitized.pop("artifact"), "gate": sanitized}


def compare(seed: str) -> dict[str, Any]:
    if platform.system() != "Linux":
        raise RuntimeError("This comparison requires Linux and GCC g++; no result was produced.")
    compiler = shutil.which("g++")
    if compiler is None:
        raise RuntimeError("GCC g++ is required; no compiler was found and no result was produced.")
    if not SOURCE.is_file() or not POLICY.is_file():
        raise RuntimeError("Run this script from a complete open-release-guard checkout with examples/.")

    version = run([compiler, "--version"], cwd=ROOT, timeout=10).stdout.decode("utf-8").strip()
    # A program named g++ may be an alias to another toolchain. Reject that
    # rather than presenting its result as a GCC comparison.
    if "Free Software Foundation" not in version:
        raise RuntimeError("The discovered g++ does not identify as GCC; no result was produced.")

    with tempfile.TemporaryDirectory(prefix="rg-native-compare-") as temporary:
        build = Path(temporary)
        assets = build / "assets"
        generated = init_native(assets, seed=seed)
        baseline = build / "baseline"
        protected = build / "protected"
        run([compiler, *BASELINE_FLAGS, str(SOURCE), "-o", str(baseline)], cwd=build)
        run([
            compiler, *PROTECTED_FLAGS, "-I", str(assets), "-I", str(assets / "include"),
            str(SOURCE), "-o", str(protected),
        ], cwd=build)

        # These two binaries are generated solely from our own checked-in
        # sample. No input artifact, downloaded code or third-party EXE runs.
        baseline_run = run([str(baseline)], cwd=build, timeout=10)
        protected_run = run([str(protected)], cwd=build, timeout=10)
        if baseline_run.stdout != protected_run.stdout:
            raise RuntimeError("Baseline/protected stdout differs; functional equivalence failed.")

        baseline_report = gate(baseline, POLICY)
        protected_report = gate(protected, POLICY)
        baseline_codes = {item["code"] for item in baseline_report["findings"]}
        if baseline_report["ok"] or not {
            "forbidden_literal", "symbol_table_present"
        }.issubset(baseline_codes):
            raise RuntimeError("Baseline did not fail both the literal and symbol-table checks.")
        if not protected_report["ok"]:
            raise RuntimeError("Protected sample failed the release gate: " + json.dumps(
                protected_report["findings"], ensure_ascii=True
            ))

        # A controlled regression must be rejected. It is scanned only; the
        # modified copy is never executed.
        negative = build / "protected-with-marker"
        write_new(negative, protected.read_bytes() + MARKER)
        negative_report = gate(negative, POLICY)
        negative_codes = {item["code"] for item in negative_report["findings"]}
        if negative_report["ok"] or "forbidden_literal" not in negative_codes:
            raise RuntimeError("Negative control was not rejected for the appended marker.")

        return {
            "format": "open-release-guard-native-compare/v1",
            "ok": True,
            "releaseguard_version": __version__,
            "environment": {
                "python": platform.python_version(), "python_implementation": platform.python_implementation(),
                "system": platform.system(), "machine": platform.machine(),
                "compiler": "g++", "compiler_version": version,
            },
            "inputs": {
                "source": "examples/main.cpp", "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                "policy": "examples/policy.json", "policy_sha256": hashlib.sha256(POLICY.read_bytes()).hexdigest(),
                "seed": generated["seed"], "seed_is_secret": False,
            },
            "baseline": describe(baseline_report, BASELINE_FLAGS),
            "protected": describe(protected_report, PROTECTED_FLAGS),
            "functional_equivalence": {
                "stdout_equal": True,
                "stdout_sha256": hashlib.sha256(baseline_run.stdout).hexdigest(),
                "stdout_utf8": baseline_run.stdout.decode("utf-8"),
                "stderr_equal": baseline_run.stderr == protected_run.stderr,
                "baseline_returncode": baseline_run.returncode,
                "protected_returncode": protected_run.returncode,
            },
            "negative_control": {
                "operation": "append the policy's UTF-8 forbidden marker to a copy of the protected binary",
                "executed": False, "rejected_as_expected": True,
                **describe(negative_report, PROTECTED_FLAGS),
            },
            "rea_evaluated": False,
            "limitations": [
                "This checks only the project's own small sample with the recorded GCC toolchain.",
                "Static marker/symbol checks and matching stdout do not measure decompilation or crack resistance.",
                "The reversible literal mask leaves runtime plaintext and its decoding implementation observable.",
                "No analyst study, REA test or probability-of-protection estimate was performed.",
                "Hashes are comparable for repeated builds with the same inputs and toolchain; other environments may differ.",
            ],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", default=DEFAULT_SEED, help="public 16-digit hexadecimal build seed")
    parser.add_argument("--out", type=Path, help="exclusively create JSON here; existing files are never overwritten")
    args = parser.parse_args()
    try:
        if args.out is not None and (args.out.exists() or args.out.is_symlink()):
            raise FileExistsError(f"Output already exists: {args.out}")
        report = compare(args.seed)
        content = (json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")
        if args.out is None:
            sys.stdout.buffer.write(content)
        else:
            write_new(args.out, content)
    except (GuardError, OSError, RuntimeError, subprocess.TimeoutExpired, UnicodeError) as exc:
        print(f"native comparison failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
