"""Owned Clang embedded IR: official v1.2 gate, repaired split and recovery controls.

Requires real Linux Clang/llvm-dis and GNU binutils. It invokes no REA model,
modifies no third-party executable and makes no machine-code secrecy claim.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import zipfile


BASELINE_SHA256 = "b16280c1f81cb6cec5a028102edeefdaf8b62e9300da3e87acb1878b3f0ab75b"
SOURCE = Path(__file__).resolve().parent / "embedded_llvm/owned_strategy.c"
NAMES = ("owned_private_margin_calculation", "owned_private_quantity",
         "owned_private_scaled", "owned_private_total")
FLAGS = ["-O0", "-g0", "-fno-discard-value-names", "-fembed-bitcode=all"]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def installed_identity(python, wheel=None):
    script = r'''
import hashlib, importlib.metadata, json, pathlib, releaseguard, sys, zipfile
root = pathlib.Path(releaseguard.__file__).resolve().parent
actual = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*")
          if p.is_file() and "__pycache__" not in p.parts}
if len(sys.argv) > 1:
    with zipfile.ZipFile(sys.argv[1]) as wheel:
        expected = {n[len("releaseguard/"):]: wheel.read(n) for n in wheel.namelist()
                    if n.startswith("releaseguard/") and not n.endswith("/")}
        if actual != expected:
            raise RuntimeError("Baseline package bytes differ from the official wheel")
inventory = hashlib.sha256()
for name, data in sorted(actual.items()):
    inventory.update((name + " " + hashlib.sha256(data).hexdigest() + "\n").encode())
version = importlib.metadata.version("open-release-guard")
if releaseguard.__version__ != version:
    raise RuntimeError("Package version metadata differs")
print(json.dumps({"version": version, "package_files": len(actual),
                  "package_inventory_sha256": inventory.hexdigest()}))
'''
    result = subprocess.run([str(python), "-I", "-c", script, *([str(wheel)] if wheel else [])],
                            capture_output=True, timeout=30)
    require(result.returncode == 0 and result.stderr == b"", "Installed package verification failed")
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llvm-bin", type=Path, required=True)
    parser.add_argument("--baseline-python", type=Path, required=True)
    parser.add_argument("--baseline-wheel", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--work", type=Path, required=True, help="New directory for the owned artifacts")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform.startswith("linux"), "This actual compiler/runtime control requires Linux")
    require(all(shutil.which(tool) for tool in ("gcc", "objcopy", "readelf", "nm")), "Missing GNU tools are not protection")
    wheel = args.baseline_wheel.resolve(strict=True)
    require(digest(wheel.read_bytes()) == BASELINE_SHA256, "Expected the verified official v1.2.0 wheel")
    baseline = installed_identity(args.baseline_python, wheel)
    candidate = installed_identity(args.python)
    require(baseline["version"] == "1.2.0", "Expected the official v1.2.0 installed baseline")
    work = args.work.resolve()
    work.mkdir()
    env = {**os.environ, "TMPDIR": str(work), "LC_ALL": "C"}
    llvm = args.llvm_bin.resolve(strict=True)
    clang, dis = llvm / "clang", llvm / "llvm-dis"

    def command(*values, expected=0):
        completed = subprocess.run([str(value) for value in values], cwd=work, env=env,
                                   capture_output=True, timeout=90)
        require(completed.returncode == expected,
                f"Command failed: {values[0]} (exit {completed.returncode}): {completed.stderr[:500]!r}")
        return completed.stdout

    def cli(python, *values, expected=0):
        return json.loads(command(python, "-I", "-m", "releaseguard", *values, expected=expected))

    def runtime(binary):
        codes = [subprocess.run([str(binary), *["owned"] * n], cwd=work, env=env,
                                capture_output=True, timeout=10).returncode for n in range(3)]
        require(codes == [48, 85, 122], "Owned program changed its three input/output controls")
        return codes

    versions = {label: command(tool, "--version").decode().splitlines()[0]
                for label, tool in (("clang", clang), ("llvm_dis", dis), ("gcc", "gcc"),
                                    ("objcopy", "objcopy"), ("readelf", "readelf"), ("nm", "nm"))}
    require("clang" in versions["clang"] and "LLVM" in versions["llvm_dis"]
            and "GNU objcopy" in versions["objcopy"], "Unexpected compiler, reader or object-file tool")
    source = work / SOURCE.name
    source.write_bytes(SOURCE.read_bytes())
    obj, original = work / "owned.o", work / "owned"
    command(clang, *FLAGS, "-c", source, "-o", obj)
    command("gcc", obj, "-o", original)
    original_bytes = original.read_bytes()
    original_runtime = runtime(original)
    policy = work / "policy.json"
    policy.write_text('{"version":1}', encoding="utf-8")
    sections = (".llvmbc", ".llvmcmd")

    def extract(binary, name, label):
        output = work / (label + ".section")
        command("objcopy", "--dump-section", name + "=" + str(output), binary, work / (label + ".inspection"))
        require(output.is_file(), "Expected embedded compiler section was not extracted")
        return output

    def recover(bitcode, label):
        output = work / (label + ".ll")
        command(dis, bitcode, "-o", output)
        ir = output.read_text(encoding="utf-8")
        recovered = [name for name in NAMES if name in ir]
        require(len(recovered) == len(NAMES) and str(source) in ir
                and "mul nsw i32" in ir and ", 37" in ir and "add nsw i32" in ir and ", 11" in ir,
                "Actual llvm-dis did not recover the owned private names, path and arithmetic")
        return {"reader_completed": True, "private_names_recovered": len(recovered),
                "source_path_recovered": True, "arithmetic_recovered": True,
                "bitcode_sha256": digest(bitcode.read_bytes()), "bitcode_bytes": bitcode.stat().st_size}

    payloads = {name: extract(original, name, "original" + name) for name in sections}
    original_recovery = recover(payloads[".llvmbc"], "original-ir")
    original_text = extract(original, ".text", "original-text").read_bytes()
    original_dynamic = command("nm", "-D", original)
    old_public, old_private = work / "v1.2-public", work / "v1.2-private"
    old_split = cli(args.baseline_python, "split-elf-debug", original,
                    "--public", old_public, "--private", old_private)
    require(old_split["ok"], "Official v1.2 splitter did not produce the control")
    old_binary = Path(old_split["public_elf"])
    old_gate = cli(args.baseline_python, "scan-release", "--root", old_public, "--policy", policy)
    require(old_gate["ok"] and old_gate["checks"]["native_metadata_scan_completed"], "v1.2 gap did not reproduce")
    old_recovery = recover(extract(old_binary, ".llvmbc", "v1.2-bitcode"), "v1.2-ir")
    old_rejected = cli(args.python, "scan-release", "--root", old_public, "--policy", policy, expected=3)
    require(not old_rejected["ok"] and {item["code"] for item in old_rejected["findings"]}
            == {"native_compiler_metadata"}, "Candidate did not specifically reject the old disclosure")

    public, private = work / "public", work / "private"
    split = cli(args.python, "split-elf-debug", original, "--public", public, "--private", private)
    require(split["ok"], "Candidate splitter did not complete")
    released, sidecar = Path(split["public_elf"]), Path(split["private_debug"])
    gate = cli(args.python, "scan-release", "--root", public, "--policy", policy)
    require(gate["ok"] and gate["checks"]["native_metadata_scan_completed"], "Separated public program did not pass")
    public_sections = command("readelf", "--sections", "--wide", released)
    require(all(name.encode() not in public_sections for name in sections), "Public compiler section remains")
    private_payloads = {name: extract(sidecar, name, "private" + name) for name in sections}
    require(all(private_payloads[name].read_bytes() == payloads[name].read_bytes() for name in sections),
            "Exact compiler IR/command bytes were not preserved privately")
    private_recovery = recover(private_payloads[".llvmbc"], "private-ir")

    standalone_rows = []
    for label, target_flags, magic in (("raw", [], b"BC\xc0\xde"),
                                      ("wrapper", ["--target=x86_64-apple-macosx10.13"], b"\xde\xc0\x17\x0b")):
        bitcode = work / (label + ".bc")
        command(clang, *target_flags, *FLAGS[:-1], "-emit-llvm", "-c", source, "-o", bitcode)
        payload = bitcode.read_bytes()
        require(payload.startswith(magic), "Clang did not emit the expected raw/wrapper format")
        recovery = recover(bitcode, label + "-standalone-ir")
        outer = io.BytesIO()
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("module.data", payload)
        with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("nested.data", inner.getvalue())
        observations = []
        for wrapped, suffix, members in ((payload, "renamed", []),
                                         (outer.getvalue(), "nested", ["nested.data", "module.data"])):
            root = work / (label + "-" + suffix)
            root.mkdir()
            (root / "renamed.data").write_bytes(wrapped)
            before = cli(args.baseline_python, "scan-release", "--root", root, "--policy", policy)
            after = cli(args.python, "scan-release", "--root", root, "--policy", policy, expected=3)
            require(before["ok"] and not after["ok"]
                    and not after["checks"]["native_metadata_scan_completed"]
                    and len(after["findings"]) == 1
                    and after["findings"][0]["code"] == "native_metadata_unverifiable"
                    and after["findings"][0]["reason"] == "unsupported_standalone_metadata"
                    and after["findings"][0].get("archive_members", []) == members,
                    "Raw compiler IR gate did not preserve accurate unsupported-format status")
            observations.append({"container": suffix, "baseline_allowed": True,
                                 "candidate_rejected_as_unsupported": True, "finding": after["findings"][0]})
        standalone_rows.append({"format": label, "compiler_target_flags": target_flags,
                                "recovery": recovery, "gate_controls": observations,
                                "native_execution_claimed": False})
    restored_rows = []
    for name in sections:
        root = work / ("restored-" + name[1:])
        root.mkdir()
        binary = root / "owned"
        command("objcopy", "--add-section", name + "=" + str(private_payloads[name]), released, binary)
        report = cli(args.python, "scan-release", "--root", root, "--policy", policy, expected=3)
        require(not report["ok"] and {item["code"] for item in report["findings"]}
                == {"native_compiler_metadata"}, "Restored compiler material did not trip the gate")
        row = {"section": name, "gate_rejected": True, "findings": report["findings"],
               "runtime_exit_codes": runtime(binary), "sha256": digest(binary.read_bytes())}
        if name == ".llvmbc":
            row["recovery"] = recover(extract(binary, name, "restored-bitcode"), "restored-ir")
        restored_rows.append(row)

    runtimes = {"original": original_runtime, "v1.2_public": runtime(old_binary), "public": runtime(released)}
    for binary, label in ((old_binary, "v1.2-public"), (released, "public")):
        require(extract(binary, ".text", label + "-text").read_bytes() == original_text,
                "Native .text changed during separation")
        require(command("nm", "-D", binary) == original_dynamic, "Dynamic symbol interface changed")
    require(original.read_bytes() == original_bytes, "The build input was modified")
    require(installed_identity(args.baseline_python, wheel) == baseline
            and installed_identity(args.python) == candidate, "Compared package changed during the run")
    report = {
        "schema": "releaseguard-llvm-metadata-recovery/v1", "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(), "tools": versions, "compiler_flags": FLAGS,
        "producer": "Clang -fembed-bitcode=all object; GNU GCC link; no manual metadata injection before baseline",
        "baseline_wheel_sha256": BASELINE_SHA256, "baseline_package": baseline, "candidate_package": candidate,
        "source_sha256": digest(source.read_bytes()), "benchmark_sha256": digest(Path(__file__).read_bytes()),
        "original_sha256": digest(original_bytes), "original_recovery": original_recovery,
        "baseline": {"gate_allowed": True, "public_sha256": digest(old_binary.read_bytes()),
                     "recovery": old_recovery, "candidate_findings": old_rejected["findings"]},
        "separated_public": {"gate_allowed": True, "compiler_sections_absent": True,
                             "sha256": digest(released.read_bytes()), "private_names_recovered_from_embedded_ir": 0,
                             "recovery_status": "section absent; no embedded IR payload available to llvm-dis"},
        "private": {"exact_bitcode_and_command_bytes_preserved": True, "recovery": private_recovery,
                    "sidecar_sha256": digest(sidecar.read_bytes())},
        "restored_controls": restored_rows, "runtime_exit_codes": runtimes,
        "standalone_bitcode": standalone_rows,
        "native_text_sha256_unchanged": digest(original_text), "dynamic_symbols_unchanged": True,
        "native_code_still_distributed": True, "rea_or_model_called": False,
        "scope": "Closes canonical embedded LLVM IR/command sections; does not prevent machine-code analysis, custom serialization or runtime capture.",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"out": str(args.out), "baseline_private_names": len(NAMES),
                      "public_embedded_ir_private_names": 0, "runtime_controls": runtimes}))


if __name__ == "__main__":
    main()
