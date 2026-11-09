"""Reproduce project-owned native function controls with trusted LLVM 18 tools.

Run with PYTHONPATH=src. Each prepare creates a fresh corpus. Private seeds allow
source/input replay with --seed, while only executable files enter public/.
score executes caller-supplied C in a separate process and is for trusted local
experiments. cost measures repeated calls inside each process.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import secrets
import statistics
import struct
import subprocess
import sys
import tempfile

from releaseguard.core import GuardError, write_new
from releaseguard.native_obfuscation import obfuscate_native_ir


PROFILES = ("baseline", "flatten", "split-flatten-substitution")
RANDOM_INPUTS = 16384
SCORE_INPUTS = 1_000_000
CALLS = 1_000_000
WARMUPS = 3
FLAGS = ["-std=c11", "-O2", "-fPIC", "-fno-unroll-loops", "-fno-vectorize",
         "-fno-slp-vectorize", "-g0", "-Wall", "-Wextra", "-Werror"]
LINK_FLAGS = ["-std=c11", "-O2", "-g0", "-Wall", "-Wextra", "-Werror",
              "-fno-pie", "-no-pie", "-Wl,--export-dynamic-symbol=rg_compute"]
DRIVER = r"""#include <stdint.h>
#include <stdio.h>
uint32_t rg_compute(uint32_t);
int main(void) {
    unsigned char in[4], out[4];
    size_t n;
    while ((n = fread(in, 1, 4, stdin)) == 4) {
        uint32_t x = (uint32_t)in[0] | (uint32_t)in[1] << 8
                   | (uint32_t)in[2] << 16 | (uint32_t)in[3] << 24;
        uint32_t y = rg_compute(x);
        for (unsigned i = 0; i < 4; ++i) out[i] = (unsigned char)(y >> (i * 8));
        if (fwrite(out, 1, 4, stdout) != 4) return 2;
    }
    return n == 0 && !ferror(stdin) && fflush(stdout) == 0 ? 0 : 2;
}
"""
TIMING_DRIVER = r"""#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
uint32_t rg_compute(uint32_t);
int main(void) {
    const unsigned calls = @CALLS@;
    uint32_t *inputs = malloc(calls * sizeof(*inputs));
    if (!inputs) return 2;
    uint32_t state = UINT32_C(0x9e3779b9);
    for (unsigned i = 0; i < calls; ++i) {
        state = state * UINT32_C(1664525) + UINT32_C(1013904223);
        inputs[i] = state;
    }
    uint64_t expected = 0;
    for (unsigned sample = 0; sample < 3 + @SAMPLES@; ++sample) {
        struct timespec start, stop;
        uint64_t checksum = UINT64_C(0xcbf29ce484222325);
        if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 2;
        for (unsigned i = 0; i < calls; ++i)
            checksum = (checksum ^ rg_compute(inputs[i])) * UINT64_C(0x100000001b3);
        if (clock_gettime(CLOCK_MONOTONIC, &stop) != 0) return 2;
        int64_t elapsed = (int64_t)(stop.tv_sec - start.tv_sec) * INT64_C(1000000000)
                        + stop.tv_nsec - start.tv_nsec;
        if (elapsed <= 0) return 3;
        if (sample == 0) expected = checksum;
        if (checksum != expected) return 4;
        if (sample >= 3 && printf("%llu %llu\n", (unsigned long long)elapsed,
                                 (unsigned long long)checksum) < 0) return 2;
    }
    free(inputs);
    return fflush(stdout) == 0 ? 0 : 2;
}
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    write_new(path, (json.dumps(value, indent=2) + "\n").encode("ascii"), secret=True)


def new_path(path):
    path = Path(path).absolute()
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"Output already exists: {path}")
    return path


def environment():
    env = {key: value for key, value in os.environ.items() if not key.startswith("LLVM_OBF_")}
    for key in ("LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES"):
        env.pop(key, None)
    env["LC_ALL"] = "C"
    return env


def execute(command, *, payload=None, cwd=None, timeout=120):
    try:
        proc = subprocess.run(list(map(str, command)), input=payload, cwd=cwd,
                              capture_output=True, timeout=timeout, env=environment())
        output, stderr, code, timed_out = proc.stdout, proc.stderr, proc.returncode, False
    except subprocess.TimeoutExpired as exc:
        output, stderr, code, timed_out = exc.stdout or b"", exc.stderr or b"", None, True
    return output, {
        "ok": code == 0 and not timed_out and not stderr,
        "returncode": code, "timed_out": timed_out,
        "stdout_bytes": len(output), "stdout_sha256": digest(output),
        "stderr_bytes": len(stderr), "stderr_sha256": digest(stderr),
        "stderr": stderr[:4096].decode("utf-8", errors="replace"),
    }


def tool(command, *, cwd=None):
    output, record = execute(command, cwd=cwd)
    require(record["ok"], f"{Path(command[0]).name} failed: {record}")
    return output


def toolchain(directory):
    directory = directory.resolve(strict=True)
    versions = {}
    for name in ("clang", "opt", "llc"):
        output = tool([directory / name, "--version"]).decode("utf-8")
        match = re.search(r"(?:clang|LLVM) version (18\.[0-9]+\.[0-9]+)\b", output)
        require(match, f"{name} must identify as LLVM 18")
        versions[name] = match[1]
    require(len(set(versions.values())) == 1, "LLVM tool versions must match exactly")
    return directory, versions


def seed_value(value):
    value = value if value is not None else secrets.token_hex(16)
    require(bool(re.fullmatch(r"[0-9a-fA-F]{32}", value)), "Seed must contain 32 hexadecimal digits")
    return value.lower()


def generator(seed, domain):
    return random.Random(int(digest(bytes.fromhex(seed) + domain.encode("ascii")), 16))


def kernel_source(seed):
    rng = generator(seed, "kernel-v1")
    constants = [rng.getrandbits(32) | 1 for _ in range(8)]
    initial, mixing, rotation, final = (rng.randrange(1, 32) for _ in range(4))
    return f"""#include <stdint.h>
__attribute__((noinline)) uint32_t rg_compute(uint32_t x) {{
    uint32_t v = x ^ {constants[0]}u;
    if ((x & 0x1041u) != 0) v += {constants[1]}u;
    else v = (v << {initial}) | (v >> {32 - initial});
    switch ((x >> 4) & 3u) {{
        case 0: v ^= {constants[2]}u; break;
        case 1: v += x * {constants[3]}u; break;
        case 2: v = (v ^ (v >> {mixing})) * {constants[4]}u; break;
        default: v -= {constants[5]}u; break;
    }}
    for (uint32_t i = 0; i < 3; ++i) {{
        if (((v >> i) & 1u) != 0) {{
            v ^= {constants[6]}u;
            v = (v << {rotation}) | (v >> {32 - rotation});
        }} else v = v * {constants[7]}u + x + i;
    }}
    return v ^ (v >> {final});
}}
""".encode("ascii")


def fresh_inputs(seed, count, excluded=()):
    rng = generator(seed, "inputs-v1")
    seen = set(excluded)
    values = []
    while len(values) < count:
        value = rng.getrandbits(32)
        if value not in seen:
            seen.add(value)
            values.append(value)
    return values


def pack(values):
    return struct.pack(f"<{len(values)}I", *values)


def compare_output(reference, output, process):
    require(bool(reference) and len(reference) % 4 == 0, "Reference output must contain complete uint32 values")
    expected_count, actual_count = len(reference) // 4, len(output) // 4
    compared = min(expected_count, actual_count)
    differences = sum(a != b for a, b in zip(struct.iter_unpack("<I", reference[:compared * 4]),
                                            struct.iter_unpack("<I", output[:compared * 4])))
    missing = max(0, expected_count - actual_count)
    return {**process, "ok": process["ok"] and output == reference,
            "expected_output_bytes": len(reference), "length_matches": len(output) == len(reference),
            "input_count": expected_count, "compared_inputs": compared,
            "different_values": differences, "missing_values": missing,
            "difference_count": differences + missing,
            "extra_output_bytes": max(0, len(output) - len(reference))}


def artifact(path):
    data = path.read_bytes()
    return {"sha256": digest(data), "bytes": len(data)}


def validate_coverage(report, profile):
    rows = [row for row in report.get("functions", []) if row.get("name") == "rg_compute"]
    require(report.get("ok") is True and report.get("transformation_applied") is True
            and report.get("profile") == profile and report.get("requested") == ["rg_compute"]
            and len(rows) == 1 and rows[0].get("requested") is True
            and rows[0].get("changed") is True,
            f"Required rg_compute transformation coverage is missing for {profile}")
    # The native API validates VM-specific coverage before returning its report.
    if profile != "virtualize":
        require(rows[0].get("dispatcher") is True and rows[0].get("new_dispatchers", 0) > 0,
                f"Required dispatcher coverage is missing for {profile}")


def prepare(args):
    root = new_path(args.corpus)
    vm_plugin = getattr(args, "vm_plugin", None)
    vm_sha = getattr(args, "vm_plugin_sha256", None)
    require(bool(vm_plugin) == bool(vm_sha), "--vm-plugin and --vm-plugin-sha256 must be supplied together")
    tools, versions = toolchain(args.llvm_bin)
    seed = seed_value(args.seed)
    root.mkdir()
    private, public = root / "private", root / "public"
    private.mkdir(mode=0o700)
    public.mkdir()
    (private / "build").mkdir()
    write_new(private / "kernel.c", kernel_source(seed), secret=True)
    write_new(private / "driver.c", DRIVER.encode("ascii"), secret=True)
    tool([tools / "clang", *FLAGS, "-emit-llvm", "-c", "kernel.c", "-o", "kernel.bc"], cwd=private)
    tool([tools / "opt", "-S", "-passes=verify", "-verify-each", "kernel.bc", "-o", "kernel.ll"], cwd=private)
    boundaries = sorted({((1 << bit) + offset) & 0xffffffff
                         for bit in range(32) for offset in (-1, 0, 1)} | {0xffffffff})
    low = list(range(1 << 16))
    values = low + boundaries + fresh_inputs(seed, RANDOM_INPUTS, low + boundaries)
    payload = pack(values)
    write_new(private / "inputs.bin", payload, secret=True)
    groups = {"low16_exhaustive": len(low), "uint32_boundaries": len(boundaries),
              "fresh_random": RANDOM_INPUTS}
    profiles = {}
    variants = (*PROFILES, "vm") if vm_plugin else PROFILES
    expected = None
    for profile in variants:
        folder = private / "build" / profile
        if profile == "baseline":
            folder.mkdir()
            tool([tools / "llc", "-O=2", "-relocation-model=pic", "-filetype=obj",
                  "kernel.bc", "-o", folder / "protected.o"], cwd=private)
            coverage = None
        else:
            build_seed = digest(bytes.fromhex(seed) + profile.encode("ascii"))[:32]
            transform = "virtualize" if profile == "vm" else profile
            plugin = vm_plugin if profile == "vm" else args.plugin
            plugin_sha = vm_sha if profile == "vm" else args.plugin_sha256
            build = obfuscate_native_ir(private / "kernel.bc", folder, tools, plugin, plugin_sha,
                                        ["rg_compute"], seed=None if profile == "vm" else build_seed,
                                        profile=transform)
            validate_coverage(build, transform)
            coverage = build["functions"]
        binary = folder / "app"
        tool([tools / "clang", *LINK_FLAGS, "driver.c", folder / "protected.o", "-o", binary], cwd=private)
        output, process = execute([binary], payload=payload, cwd=private)
        require(process["ok"] and len(output) == len(payload), f"Incomplete native output for {profile}: {process}")
        if expected is None:
            expected = output
            write_new(private / "expected.bin", expected, secret=True)
        comparison = compare_output(expected, output, process)
        require(comparison["ok"], f"Native functional mismatch for {profile}: {comparison}")
        profiles[profile] = {"binary": artifact(binary), "object": artifact(folder / "protected.o"),
                             "coverage": coverage, "functional": comparison}
    for profile in variants:
        (private / "build" / profile / "app").rename(public / profile)
    manifest = {
        "schema": "releaseguard-native-code-corpus/v1", "ok": True,
        "created_utc": datetime.now(timezone.utc).isoformat(), "seed": seed,
        "public_abi": "uint32_t rg_compute(uint32_t x)",
        "llvm_versions": versions, "plugin_sha256": args.plugin_sha256.lower(),
        "vm_plugin_sha256": vm_sha.lower() if vm_sha else None,
        "compiler_flags": FLAGS, "link_flags": LINK_FLAGS, "input_groups": groups,
        "input_count": len(values), "profiles": profiles,
        "files": {name: artifact(private / name) for name in
                  ("kernel.c", "driver.c", "kernel.bc", "kernel.ll", "inputs.bin", "expected.bin")},
    }
    save(private / "manifest.json", manifest)
    return {key: value for key, value in manifest.items() if key != "seed"}


def load_corpus(corpus):
    root = corpus.resolve(strict=True)
    manifest = json.loads((root / "private/manifest.json").read_bytes())
    variants = manifest.get("profiles", {})
    require(manifest.get("schema") == "releaseguard-native-code-corpus/v1"
            and manifest.get("ok") is True and set(variants) in (set(PROFILES), {*PROFILES, "vm"}),
            "Corpus is incomplete or has an unexpected schema")
    for name, record in manifest["files"].items():
        require(Path(name).name == name, "Invalid private artifact name")
        require(artifact(root / "private" / name) == record, f"Private corpus artifact changed: {name}")
    for profile in variants:
        row = manifest["profiles"][profile]
        require(row["functional"]["ok"] is True, f"Incomplete functional control: {profile}")
        require(artifact(root / "public" / profile) == row["binary"], f"Public binary changed: {profile}")
        require(artifact(root / "private/build" / profile / "protected.o") == row["object"],
                f"Private object changed: {profile}")
    payload = (root / "private/inputs.bin").read_bytes()
    expected = (root / "private/expected.bin").read_bytes()
    require(len(payload) == len(expected) == manifest["input_count"] * 4 and payload,
            "Incomplete corpus input or expected output")
    return root, manifest, payload, expected


def score(args):
    root, manifest, original, original_expected = load_corpus(args.corpus)
    tools, versions = toolchain(args.llvm_bin)
    work = Path(tempfile.mkdtemp(prefix="score-", dir=root / "private"))
    source = args.candidate.read_bytes()
    write_new(work / "candidate.c", source, secret=True)
    seed = seed_value(args.seed)
    excluded = (item[0] for item in struct.iter_unpack("<I", original))
    extra = pack(fresh_inputs(seed, SCORE_INPUTS, excluded))
    payload = original + extra
    write_new(work / "inputs.bin", payload, secret=True)
    save(work / "seed.json", {"seed": seed, "extra_inputs": SCORE_INPUTS})
    reference, baseline = execute([root / "public/baseline"], payload=payload, cwd=work)
    require(baseline["ok"] and len(reference) == len(payload)
            and reference[:len(original_expected)] == original_expected,
            f"Baseline reference failed: {baseline}")
    write_new(work / "expected.bin", reference, secret=True)
    _, compiled = execute([tools / "clang", *LINK_FLAGS, work / "candidate.c",
                            root / "private/driver.c", "-o", work / "candidate"], cwd=work)
    report = {"schema": "releaseguard-native-code-score/v1", "ok": False,
              "completed_utc": datetime.now(timezone.utc).isoformat(), "llvm_versions": versions,
              "candidate_source_sha256": digest(source), "corpus_source": manifest["files"]["kernel.c"],
              "baseline_binary": manifest["profiles"]["baseline"]["binary"],
              "input_count": len(payload) // 4, "corpus_input_count": len(original) // 4,
              "new_distinct_inputs": SCORE_INPUTS, "input_sha256": digest(payload),
              "expected_sha256": digest(reference), "compilation": compiled, "baseline": baseline,
              "candidate": None, "private_evidence": str(work)}
    if compiled["ok"]:
        output, process = execute([work / "candidate"], payload=payload, cwd=work)
        report["candidate"] = compare_output(reference, output, process)
        report["candidate_binary"] = artifact(work / "candidate")
        report["ok"] = report["candidate"]["ok"]
    report["completed_utc"] = datetime.now(timezone.utc).isoformat()
    save(work / "report.json", report)
    return report


def function_size(tools, binary):
    if not (tools / "llvm-nm").is_file():
        return None
    output = tool([tools / "llvm-nm", "--print-size", "--format=posix", "--defined-only", binary])
    rows = [line.split() for line in output.decode("ascii").splitlines()]
    sizes = [int(row[3], 16) for row in rows if len(row) == 4 and row[0] == "rg_compute"]
    require(len(sizes) == 1 and sizes[0] > 0, "Expected one sized public rg_compute symbol")
    return sizes[0]


def cost(args):
    require(args.samples >= 7, "At least seven measured samples are required")
    require(0 < args.iterations <= 0xffffffff, "Iterations must be a positive uint32 count")
    root, manifest, _, _ = load_corpus(args.corpus)
    tools, versions = toolchain(args.llvm_bin)
    work = Path(tempfile.mkdtemp(prefix="cost-", dir=root / "private"))
    source = TIMING_DRIVER.replace("@SAMPLES@", str(args.samples)).replace(
        "@CALLS@", str(args.iterations)).encode("ascii")
    write_new(work / "timing.c", source, secret=True)
    rows = {}
    checksums = set()
    for profile in manifest["profiles"]:
        binary = work / profile
        obj = root / "private/build" / profile / "protected.o"
        tool([tools / "clang", *LINK_FLAGS, work / "timing.c", obj, "-o", binary], cwd=work)
        output, process = execute([binary], cwd=work, timeout=300)
        require(process["ok"], f"Timing driver failed for {profile}: {process}")
        lines = output.decode("ascii").splitlines()
        require(len(lines) == args.samples and all(re.fullmatch(r"[0-9]+ [0-9]+", line) for line in lines),
                f"Incomplete timing samples for {profile}")
        samples, sums = zip(*(map(int, line.split()) for line in lines))
        require(min(samples) > 0 and len(set(sums)) == 1, f"Invalid timing/checksum for {profile}")
        checksums.update(sums)
        median = statistics.median(samples)
        rows[profile] = {"samples_ns": samples, "median_ns": median,
                         "median_ns_per_call": median / args.iterations,
                         "checksum": sums[0], "object": manifest["profiles"][profile]["object"],
                         "public_binary": manifest["profiles"][profile]["binary"],
                         "function_symbol": "rg_compute",
                         "function_bytes": function_size(tools, root / "public" / profile),
                         "timing_binary": artifact(binary), "execution": process}
    require(len(checksums) == 1, "Profile timing checksums differ")
    baseline_median = rows["baseline"]["median_ns"]
    for row in rows.values():
        row["median_ratio_to_baseline"] = row["median_ns"] / baseline_median
    report = {"schema": "releaseguard-native-code-cost/v1", "ok": True,
              "completed_utc": datetime.now(timezone.utc).isoformat(), "llvm_versions": versions,
              "clock": "CLOCK_MONOTONIC", "warmups": WARMUPS, "samples": args.samples,
              "calls_per_sample": args.iterations, "checksums_equal": True, "profiles": rows,
              "timing_source_sha256": digest(source), "link_flags": LINK_FLAGS,
              "host": {"system": platform.system(), "machine": platform.machine(),
                       "release": platform.release(), "logical_cpus": os.cpu_count()},
              "measurement_scope": "In-process function calls, loop and checksum arithmetic. Input generation, allocation, process startup, compilation and output occur outside the measured interval.",
              "private_evidence": str(work)}
    save(work / "report.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("--plugin", type=Path, required=True)
    prep.add_argument("--plugin-sha256", required=True)
    prep.add_argument("--vm-plugin", type=Path, help="Optional trusted Amice LLVM 18 VM plugin")
    prep.add_argument("--vm-plugin-sha256", help="Expected SHA-256 of the optional VM plugin")
    prep.add_argument("--seed", help="Private 32-hex generation seed for source/input replay")
    prep.set_defaults(func=prepare)
    scoring = commands.add_parser("score")
    scoring.add_argument("--seed", help="Private replay seed, otherwise newly generated after copying the candidate")
    scoring.set_defaults(func=score)
    timing = commands.add_parser("cost")
    timing.add_argument("--samples", type=int, default=7)
    timing.add_argument("--iterations", type=int, default=CALLS,
                        help="Function calls per measured sample, shared by every variant")
    timing.set_defaults(func=cost)
    for command in (prep, scoring, timing):
        command.add_argument("corpus", type=Path)
        command.add_argument("--llvm-bin", type=Path, required=True)
        command.add_argument("--out", type=Path, required=command is not prep,
                             help="Exclusively create a JSON report")
    scoring.add_argument("candidate", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.out is not None:
            args.out = new_path(args.out)
            require(not args.out.is_relative_to(args.corpus.absolute() / "public"),
                    "Reports must stay outside public/")
        report = args.func(args)
        if args.out is None:
            print(json.dumps(report, indent=2))
        else:
            save(args.out, report)
    except (GuardError, OSError, RuntimeError, UnicodeError, ValueError) as exc:
        print(f"Native code control failed: {exc}", file=sys.stderr)
        return 2
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
