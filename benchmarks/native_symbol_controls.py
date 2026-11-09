"""Build and analyze three matched, project-owned i386 Linux executables."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

from ghidra_token.probe import ARCHIVE_SHA, VERSION, get_ghidra, launch_command

HERE = Path(__file__).resolve().parent / "elf_symbols"
CASES = ("baseline", "public", "restored")
PUBLIC = "rg_public_entry"


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def output(cmd, **kwargs):
    return subprocess.check_output(list(map(str, cmd)), text=True, timeout=120, **kwargs)


def save(path, data):
    with path.open("x", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def load(path):
    return json.loads(path.read_bytes())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def code_section(binary):
    rows = [r.split() for r in output(["objdump", "-h", binary]).splitlines()]
    [section] = [r for r in rows if len(r) >= 7 and r[1] == ".text"]
    size, address, _, offset = [int(n, 16) for n in section[2:6]]
    code = binary.read_bytes()[offset:offset + size]
    check(len(code) == size > 0, "Incomplete .text")
    return address, code


def symbol_rows(binary):
    return [r.split() for r in output(["nm", "--defined-only", binary]).splitlines() if r.strip()]


def statuses(path, emulator):
    prefix = [emulator] if emulator else []
    return [subprocess.run([*prefix, path, *["x"] * n], timeout=10, check=False).returncode for n in (0, 1, 2)]


def prepare(args):
    root = args.corpus.resolve()
    root.mkdir()
    for name in ("baseline", "restored"):
        (root / name).mkdir()
    original = root / "baseline/app"
    private_name = "rg_private_" + secrets.token_hex(8)
    # Supplying an address later does not supply this randomly chosen source identifier.
    flags = ["-m32", "-O0", "-g", "-fno-pic", "-fno-pie", "-fno-omit-frame-pointer",
             "-fno-stack-protector", "-nostdlib", "-no-pie",
             "-Wl,--no-dynamic-linker,-e,_start,--export-dynamic-symbol=" + PUBLIC + ",-Ttext-segment=0x08048000"]
    output(["gcc", *flags, "-DPRIVATE_RULE=" + private_name, HERE / "fixture.c", "-o", original])
    output([sys.executable, "-m", "releaseguard", "split-elf-debug", original,
            "--public", root / "public", "--private", root / "symbols", "--private-name", private_name])
    public = root / "public/app"
    sidecar = root / "symbols/app.debug"
    names = {name: int(address, 16) for address, _, name in symbol_rows(original)}
    private_va = names[private_name]
    base, text_bytes = code_section(original)
    # Reinsert only the local function symbol recovered from the private sidecar.
    [restored_name] = [name for address, kind, name in symbol_rows(sidecar)
                       if int(address, 16) == private_va and kind.lower() == "t"]
    check(restored_name == private_name, "Sidecar did not recover the private source identifier")
    spec = f"{restored_name}=.text:0x{private_va - base:x},local,function"
    output(["objcopy", "--add-symbol", spec, public, root / "restored/app"])
    hashes = {}
    for case in CASES:
        path = root / case / "app"
        raw = path.read_bytes()
        check(raw[:7] == b"\x7fELF\x01\x01\x01" and code_section(path) == (base, text_bytes),
              "Fixture must retain the same ELF32 .text and VMA")
        check((private_name.encode() in raw) == (case != "public"), "Unexpected raw identifier")
        check(statuses(path, args.emulator) == [39, 52, 65], "Unexpected program behavior")
        hashes[case] = sha(raw)
    result = {"schema": "releaseguard-elf-symbol-fixture/v1", "inputs": hashes,
              "private_name": private_name, "private_entry": hex(private_va),
              "public_name": PUBLIC, "public_entry": hex(names[PUBLIC]),
              "text_sha256": sha(text_bytes), "sidecar_sha256": sha(sidecar.read_bytes()),
              "fixture_source_sha256": sha((HERE / "fixture.c").read_bytes()),
              "gcc": output(["gcc", "--version"]).splitlines()[0],
              "objcopy": output(["objcopy", "--version"]).splitlines()[0],
              "compiler_flags": flags, "observed_exit_codes": [39, 52, 65]}
    save(root / "fixture.json", result)


def analyze(args):
    root = args.corpus.resolve()
    fixture = load(root / "fixture.json")
    tool = args.tool
    env = os.environ.copy()
    rows = {}
    with tempfile.TemporaryDirectory(prefix="rg-symbol-probe-") as temp:
        work = Path(temp).resolve()
        if tool == "Ghidra":
            for name in ("home", "tmp", "projects"):
                (work / name).mkdir()
            env.update({"HOME": str(work / "home"), "TMPDIR": str(work / "tmp"), "GHIDRA_HEADLESS_MAXMEM": "1G",
                        "GHIDRA_JAVA_OPTIONS": f"-Duser.home={work}/home -Djava.io.tmpdir={work}/tmp"})
            launcher = launch_command(args, get_ghidra(args, work, env), work, env)
        for case in CASES:
            source = root / case / "app"
            digest = sha(source.read_bytes())
            check(digest == fixture["inputs"][case], "Fixture changed after preparation")
            # Each engine sees only a fresh copy of the ELF, the output path and the two entry addresses.
            case_dir = work / case
            case_dir.mkdir()
            target = case_dir / "app"
            target.write_bytes(source.read_bytes())
            report = case_dir / "obs.json"
            addresses = [fixture["private_entry"], fixture["public_entry"]]
            if tool == "IDA" and args.observations is not None:
                # Windows analyzes the ELF. Linux independently binds its report to this corpus
                # before executing the fixture and the controlled patch.
                row = load(args.observations / (case + ".json"))
            else:
                if tool == "Ghidra":
                    cmd = [*launcher, work / "projects", case, "-import", target, "-readOnly", "-deleteProject",
                           "-analysisTimeoutPerFile", "90", "-max-cpu", "2", "-scriptPath", HERE,
                           "-postScript", "InspectNativeSymbols.java", report, addresses[0]]
                else:
                    runner = args.runner.resolve(strict=True)
                    cmd = ([sys.executable, runner] if runner.suffix == ".py" else [runner]) + [target, report, *addresses]
                proc = subprocess.run(list(map(str, cmd)), cwd=case_dir, env=env, timeout=300, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True, errors="replace", check=False)
                check(proc.returncode == 0 and report.is_file() and
                      (tool != "Ghidra" or "RELEASEGUARD_NATIVE_SYMBOLS_COMPLETE" in proc.stdout),
                      f"{tool} incomplete for {case}: {proc.stdout[-4000:]}")
                row = load(report)
            check(row["tool"] == tool and bool(row["version"]) and row["input_sha256"].lower() == digest
                  and sha(target.read_bytes()) == digest, f"{tool} identity/input mismatch")
            if tool == "Ghidra":
                check(row["version"] == VERSION and row["language"].startswith("x86:LE:32:")
                      and "ELF" in row["format"], "Unexpected Ghidra version or target")
            else:
                check(row["version"] == "5.0.0.879 Freeware", "Unsupported IDA build")
            base, code = code_section(source)
            for label in ("private", "public"):
                entry = int(row[label + "_entry"], 16)
                if tool == "IDA":
                    offset = entry - base
                    check(0 <= offset <= len(code) - 8 and row[label + "_prefix_hex"] == code[offset:offset + 8].hex(),
                          "IDA database bytes do not match the executed ELF")
                check(entry == int(fixture[label + "_entry"], 16)
                      and type(row[label + "_instructions"]) is int and row[label + "_instructions"] > 0, f"{tool} did not disassemble {label}")
            observed_names = {row["private_name"], *row.get("private_aliases", [])}
            recovered = fixture["private_name"] in observed_names
            check(row["public_name"] == PUBLIC and recovered == (case != "public"),
                  f"{tool}: unexpected control in {case}: {row}")
            row["exact_private_name_recovered"] = recovered
            rows[case] = row
        for label in ("private", "public"):
            check(len({r[label + "_instructions"] for r in rows.values()}) == 1,
                  "Same implementation disassembled inconsistently")
        from elf_symbols.patch_control import probe_patch
        patch_dir = work / "patch"
        patch_dir.mkdir()
        patch_result = probe_patch(root / "public/app", rows["public"], patch_dir,
                                   [args.emulator] if args.emulator else [])
    result = {"schema": "releaseguard-elf-symbol-observation/v1", "tool": tool,
              "fixture": fixture, "cases": rows, "patched_client": patch_result}
    if tool == "Ghidra":
        result.update({"ghidra_archive_sha256_verified_in_run": ARCHIVE_SHA if args.archive else None,
                       "script_sha256": sha((HERE / "InspectNativeSymbols.java").read_bytes())})
    save(args.out, result)


def compare(args):
    ghidra, ida = [load(p) for p in (args.ghidra, args.ida)]
    check(ghidra["tool"] == "Ghidra" and ida["tool"] == "IDA" and ghidra["fixture"] == ida["fixture"],
          "Independent analyzers must observe the same corpus")
    for obs in (ghidra, ida):
        check(obs["schema"] == "releaseguard-elf-symbol-observation/v1" and
              all(obs["cases"][c]["input_sha256"].lower() == obs["fixture"]["inputs"][c] and
                  obs["cases"][c]["exact_private_name_recovered"] is (c != "public") for c in CASES),
              "Evidence is incomplete or describes a different ELF")
        patch = obs["patched_client"]
        check(patch["public_elf_sha256"] == obs["fixture"]["inputs"]["public"] and
              patch["client_exit_before_after"] == [39, 42] and
              patch["trust_client"] == {"receipts_verified": [False, True], "handler_calls": 1} and
              patch["verified"] == {"receipts_verified": [False, False, False, True, False], "handler_calls": 1} and
              int(patch["gate_address"], 16) == int(obs["cases"]["public"]["public_entry"], 16) and
              type(patch["gate_file_offset"]) is int and patch["gate_file_offset"] >= 0 and
              patch["patch_hex"] == "b82a000000c3",
              "Patch/service controls missing or unsuccessful")
    check(all(ghidra["patched_client"][key] == ida["patched_client"][key]
              for key in ("patched_elf_sha256", "gate_file_offset")),
          "The tools did not identify the same patch location")
    save(args.out, {"schema": "releaseguard-dual-elf-symbols/v1", "ghidra": ghidra, "ida": ida})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("prepare", help="Create a new project-owned corpus and run functional controls")
    build.set_defaults(func=prepare)
    for name in ("ghidra", "ida"):
        opt = commands.add_parser(name)
        opt.set_defaults(func=analyze, tool={"ghidra": "Ghidra", "ida": "IDA"}[name])
        if name == "ghidra":
            source = opt.add_mutually_exclusive_group(required=True)
            source.add_argument("--archive", type=Path, help="Pinned official Ghidra 12.2 archive")
            source.add_argument("--ghidra-home", type=Path, help="Preverified extracted Ghidra")
            opt.add_argument("--direct-java", action="store_true", help="Use Ghidra Java entry point")
        else:
            source = opt.add_mutually_exclusive_group(required=True)
            source.add_argument("--runner", type=Path, help="Installed IDA adapter")
            source.add_argument("--observations", type=Path, help="Directory of three raw Windows IDA reports")
    for name in ("prepare", "ghidra", "ida"):
        opt = commands.choices[name]
        opt.add_argument("corpus", type=Path)
        opt.add_argument("--emulator", type=Path, help="Optional qemu-i386 for these Linux ELFs")
    both = commands.add_parser("compare")
    both.set_defaults(func=compare)
    both.add_argument("--ghidra", type=Path, required=True)
    both.add_argument("--ida", type=Path, required=True)
    for name in ("ghidra", "ida", "compare"):
        commands.choices[name].add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
