"""Export genuine Ghidra observations of a project-owned ELF's rg_compute function."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
BENCHMARKS = HERE.parent
sys.path.insert(0, str(BENCHMARKS))
from ghidra_token.probe import ARCHIVE_SHA, VERSION, get_ghidra, launch_command, require, sha


def address_set(ranges):
    addresses = set()
    for row in ranges:
        start, size = int(row["start"], 16), row["size"]
        require(0 < size <= 1024 * 1024 and len(addresses) + size <= 1024 * 1024,
                "Invalid function address range")
        current = set(range(start, start + size))
        require(addresses.isdisjoint(current), "Overlapping function address ranges")
        addresses.update(current)
    return addresses


def validate_bytes(result, raw):
    """Check both the analyzer's file provenance and complete function-body coverage."""
    observed = {}
    loaded = {}
    modified = 0
    for row in result["original_byte_ranges"]:
        start, offset = int(row["start"], 16), row["file_offset"]
        data = bytes.fromhex(row["hex"])
        memory = bytes.fromhex(row["loaded_hex"])
        require(len(data) == len(memory) == row["size"] > 0 and offset >= 0 and offset + len(data) <= len(raw),
                "Invalid original-byte range")
        require(raw[offset:offset + len(data)] == data, "Analyzer bytes differ from the input ELF")
        for index, value in enumerate(data):
            require(start + index not in observed, "Overlapping function byte ranges")
            observed[start + index] = value
            loaded[start + index] = memory[index]
            modified += value != memory[index]
    require(modified == result["loaded_function_byte_changes"], "Inconsistent loaded-byte change count")
    body = address_set(result["body_ranges"])
    require(len(body) == result["body_addresses"] and body == observed.keys(),
            "Original byte export does not cover the entire function body")
    decoded = set()
    for row in result["instructions"]:
        start = int(row["address"], 16)
        data = bytes.fromhex(row["hex"])
        require(len(data) == row["size"] > 0, "Invalid instruction length")
        addresses = set(range(start, start + len(data)))
        require(decoded.isdisjoint(addresses) and addresses <= body, "Invalid instruction coverage")
        require(all(loaded[start + index] == value for index, value in enumerate(data)),
                "Instruction bytes differ from the analyzer's loaded function bytes")
        decoded.update(addresses)
    require(len(result["instructions"]) == result["instruction_count"] > 0,
            "Missing decoded instructions")
    undecoded = address_set(result["undecoded_ranges"])
    require(body - decoded == undecoded and len(undecoded) == result["undecoded_bytes"],
            "Inconsistent undecoded byte ranges")
    require(result["cfg_blocks"], "Empty function CFG")
    cfg = address_set([row for block in result["cfg_blocks"] for row in block["ranges"]])
    require(decoded <= cfg <= body, "CFG does not cover every decoded instruction")


def validate_logs(console, headless):
    require("RELEASEGUARD_FUNCTION_EXPORT_COMPLETE" in console, "Export did not complete; see console.log")
    errors = [line for line in (console + "\n" + headless).splitlines()
              if re.search(r"(?:^|\s)ERROR(?:\s|:)", line)]
    # Ghidra 12.2 FileCache.java:119-125,585-592 continues after a failed
    # FileStore query, skipping only its cache free-space precheck.
    cache_errors = [line for line in errors if "(FileCache)" in line and re.search(
        r"Failed to get java FileStore for path .+, will be unable to check free/available space\."
        r"\s*(?:\(FileCache\)\s*)?$", line)]
    require(len(errors) == len(cache_errors), "Ghidra logged an unexplained error; review analyzer logs")
    require("REPORT: Analysis succeeded for file:" in console
            and "REPORT: Post-analysis succeeded for file:" in console,
            "Automatic analysis completion markers are missing")
    return cache_errors


def validate_program_functions(record, code):
    inventory = [row["entry"] for row in record["function_inventory"]]
    observed = [row["entry"] for row in record["functions"]]
    require(0 < len(inventory) == len(set(inventory)) == record["function_count"] <= 2048,
            "Invalid program function inventory")
    require(len(observed) == len(set(observed)) and set(observed) == set(inventory),
            "Program function observations omit or duplicate an inventory entry")
    completed = 0
    failures = []
    function_warnings = []
    warning_counts = {}
    previous_end = 0
    for row in record["functions"]:
        offset, size = row["c_offset"], row["c_bytes"]
        require(previous_end <= offset <= offset + size <= len(code), "Invalid function C output range")
        require(hashlib.sha256(code[offset:offset + size]).hexdigest() == row["c_sha256"],
                "Function C output hash mismatch")
        warnings = decompiler_warnings(code[offset:offset + size])
        if warnings:
            function_warnings.append({"entry": row["entry"], "name": row["name"],
                                      "api_status": row["status"], "warnings": warnings})
            for warning in warnings:
                kind = warning["kind"]
                warning_counts[kind] = warning_counts.get(kind, 0) + 1
        previous_end = offset + size
        require(row["status"] in ("completed", "failed", "timeout", "cancelled"),
                "Unrecognized function decompilation status")
        if row["status"] == "completed":
            require(size > 0, "Completed function has no decompiled C")
            completed += 1
        else:
            require(row.get("message"), "Failed helper is missing its diagnostic")
            failures.append({key: row[key] for key in ("entry", "name", "status", "message")})
    require(completed == record["completed_functions"]
            and len(failures) == record["failed_functions"], "Inconsistent program function status counts")
    return {"recognized_functions": len(inventory), "api_completed_functions": completed,
            "completion_semantics": "Ghidra decompileCompleted() API status",
            "function_failures": failures, "functions_with_warnings": len(function_warnings),
            "warning_counts": dict(sorted(warning_counts.items())), "function_warnings": function_warnings}


def decompiler_warnings(code):
    """Record diagnostics in a hash-verified C slice without rewriting the output."""
    text = code.decode("utf-8")
    warnings = []
    for match in re.finditer(r"/\*.*?\*/|//[^\n]*", text, re.DOTALL):
        comment = match.group()
        if "WARNING:" not in comment:
            continue
        lowered = comment.lower()
        kind = "decompiler_warning"
        if "could not recover jumptable" in lowered:
            kind = "unrecovered_jump_table"
        elif "treating indirect jump as call" in lowered:
            kind = "indirect_jump_as_call"
        elif "truncating control flow" in lowered:
            kind = "truncated_control_flow"
        elif "control flow encountered bad instruction data" in lowered:
            kind = "bad_instruction_data"
        warnings.append({"kind": kind, "c_line": text.count("\n", 0, match.start()) + 1,
                         "text": comment})
    for match in re.finditer(r"(?m)^[ \t]*halt_baddata\s*\([^;]*;", text):
        warnings.append({"kind": "halt_baddata_call", "c_line": text.count("\n", 0, match.start()) + 1,
                         "text": match.group().strip()})
    return sorted(warnings, key=lambda row: row["c_line"])


def allocated_file_offsets(raw):
    require(len(raw) >= 64 and raw[:4] == b"\x7fELF" and raw[4] in (1, 2)
            and raw[5:7] == b"\x01\x01", "Expected a little-endian ELF program")
    is64 = raw[4] == 2
    kind, machine = struct.unpack_from("<HH", raw, 16)
    require(kind in (2, 3) and machine == (62 if is64 else 3), "Expected a linked x86 ELF program")
    section_offset = struct.unpack_from("<Q" if is64 else "<I", raw, 40 if is64 else 32)[0]
    section_size, section_count = struct.unpack_from("<HH", raw, 58 if is64 else 46)
    require(section_size == (64 if is64 else 40) and section_count > 0
            and section_offset + section_size * section_count <= len(raw), "Unsupported ELF section table")
    offsets = set()
    for position in range(section_offset, section_offset + section_size * section_count, section_size):
        _, section_type, flags, _, offset, size = struct.unpack_from("<II4Q" if is64 else "<6I", raw, position)
        if flags & 2 and section_type != 8 and size:
            require(offset + size <= len(raw), "Incomplete allocated ELF section")
            offsets.update(range(offset, offset + size))
    require(offsets, "ELF has no allocated file-backed sections")
    return offsets


def validate_program_memory(record, raw):
    covered_offsets = set()
    loaded_ranges = []
    total = 0
    backed = 0
    changes = 0
    for block in record["blocks"]:
        if not (block["loaded"] and block["initialized"]):
            continue
        start, size = int(block["start"], 16), block["size"]
        total += size
        require(0 < size and total <= 16 * 1024 * 1024, "Invalid initialized program memory budget")
        loaded_ranges.append((start, start + size))
        cursor, block_backed, block_changes = start, 0, 0
        for row in block["memory"]["ranges"]:
            memory = bytes.fromhex(row["loaded_hex"])
            require(int(row["start"], 16) == cursor and 0 < len(memory) == row["size"]
                    and cursor + len(memory) <= start + size, "Incomplete program memory range coverage")
            cursor += len(memory)
            if "file_offset" in row:
                offset = row["file_offset"]
                original = bytes.fromhex(row["hex"])
                require(0 <= offset <= offset + len(memory) <= len(raw) and len(original) == len(memory)
                        and raw[offset:offset + len(original)] == original, "Invalid program file-byte provenance")
                covered_offsets.update(range(offset, offset + len(original)))
                block_backed += len(original)
                block_changes += sum(left != right for left, right in zip(original, memory))
            else:
                require("hex" not in row, "Unbacked program memory claims original file bytes")
        require(cursor == start + size and block_backed == block["memory"]["file_backed_bytes"]
                and size - block_backed == block["memory"]["unbacked_bytes"]
                and block_changes == block["memory"]["loaded_byte_changes"], "Inconsistent program memory summary")
        backed += block_backed
        changes += block_changes
    previous_end = -1
    for start, end in sorted(loaded_ranges):
        require(start >= previous_end, "Overlapping initialized program memory blocks")
        previous_end = end
    require(total == record["initialized_loaded_bytes"] > 0, "Inconsistent initialized program memory count")
    allocated = allocated_file_offsets(raw)
    require(allocated <= covered_offsets, "Program memory export omits an allocated ELF section byte")
    return {"initialized_loaded_bytes": total, "file_backed_bytes": backed,
            "unbacked_bytes": total - backed, "loaded_byte_changes": changes,
            "allocated_file_bytes_verified": len(allocated)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Project-owned complete ELF with public rg_compute")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive", type=Path, help="Pinned official Ghidra ZIP, verified before extraction")
    source.add_argument("--ghidra-home", type=Path, help="Previously verified extracted Ghidra distribution")
    parser.add_argument("--direct-java", action="store_true", help="Use official headless class with JAVA_HOME")
    parser.add_argument("--include-program", action="store_true",
                        help="Also export every recognized internal function, loaded memory, and a complete ELF copy")
    parser.add_argument("--out", required=True, type=Path, help="New observation directory")
    args = parser.parse_args()
    target = args.input.resolve(strict=True)
    require(0 < target.stat().st_size <= 16 * 1024 * 1024, "Input ELF exceeds the 16 MiB budget")
    raw = target.read_bytes()
    require(0 < len(raw) <= 16 * 1024 * 1024 and raw.startswith(b"\x7fELF"),
            "Expected a complete project-owned ELF of at most 16 MiB")
    before = hashlib.sha256(raw).hexdigest()
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    script = HERE / "ExportCompute.java"
    program_summary = None
    if args.include_program:
        (output / "program.elf").write_bytes(raw)

    with tempfile.TemporaryDirectory(prefix="rg-function-", dir=output.parent) as temporary:
        work = Path(temporary)
        for name in ("home", "tmp", "cache", "projects", "input"):
            (work / name).mkdir()
        isolated = work / "input" / "sample.elf"
        isolated.write_bytes(raw)
        env = {key: os.environ[key] for key in ("PATH", "JAVA_HOME", "LD_LIBRARY_PATH") if key in os.environ}
        env.update({"HOME": str(work / "home"), "TMPDIR": str(work / "tmp"), "LANG": "C",
                    "XDG_CACHE_HOME": str(work / "cache"),
                    "GHIDRA_HEADLESS_MAXMEM": "1G",
                    "GHIDRA_JAVA_OPTIONS": f"-Duser.home={work}/home -Djava.io.tmpdir={work}/tmp"})
        require(not args.direct_java or "JAVA_HOME" in env, "--direct-java requires JAVA_HOME")
        home = get_ghidra(args, work, env)
        require((home / "support" / "analyzeHeadless").is_file(), "Not a Ghidra distribution")
        launcher = launch_command(args, home, work, env)
        command = [*launcher, work / "projects", "function_recovery", "-import", isolated,
                   "-loader-applyRelocations", "true", "-readOnly", "-deleteProject",
                   "-analysisTimeoutPerFile", "180", "-max-cpu", "2",
                   "-scriptPath", HERE, "-postScript", script.name, output,
                   *(["include-program"] if args.include_program else []),
                   "-log", output / "headless.log", "-scriptlog", output / "script.log"]
        with (output / "console.log").open("wb") as console:
            process = subprocess.run(list(map(str, command)), cwd=work, env=env,
                                     stdout=console, stderr=subprocess.STDOUT,
                                     timeout=1200 if args.include_program else 360, check=False)
        console = (output / "console.log").read_text(encoding="utf-8", errors="replace")
        require(process.returncode == 0, f"Ghidra exited {process.returncode}; see console.log")
        headless = ""
        if (output / "headless.log").is_file():
            headless = (output / "headless.log").read_text(encoding="utf-8", errors="replace")
        cache_errors = validate_logs(console, headless)
        result = json.loads((output / "function.json").read_bytes())
        require(result["tool"] == "Ghidra" and result["version"] == VERSION,
                "Unexpected analyzer version")
        require(result["input_sha256"].lower() == before and sha(isolated) == before and sha(target) == before,
                "Analyzer input hash mismatch or ELF changed during analysis")
        require("ELF" in result["format"] and result["language"].startswith("x86:LE:")
                and result["analysis_timed_out"] is False, "Wrong import format, architecture or timeout")
        require(result["target"]["name"] == "rg_compute" and not result["target"]["external"],
                "Wrong target function")
        require((output / "decompiled.c").stat().st_size == result["decompiled_c_bytes"]
                and (result["decompile_completed"] or args.include_program),
                "Missing or inconsistent decompiled C")
        validate_bytes(result, raw)
        if args.include_program:
            program = json.loads((output / "program.json").read_bytes())
            memory = json.loads((output / "program-memory.json").read_bytes())
            require(program["input_sha256"].lower() == memory["input_sha256"].lower() == before
                    and sha(output / "program.elf") == before, "Whole-program input hash mismatch")
            program_summary = validate_program_functions(program, (output / "program.c").read_bytes())
            program_summary.update(validate_program_memory(memory, raw))
            warning_report = {"schema": "releaseguard.program-warnings.v1", "input_sha256": before,
                              "program_c_sha256": sha(output / "program.c"),
                              **{key: program_summary[key] for key in (
                                  "completion_semantics", "api_completed_functions", "functions_with_warnings",
                                  "warning_counts", "function_warnings")}}
            (output / "program-warnings.json").write_text(json.dumps(warning_report, indent=2) + "\n",
                                                         encoding="utf-8")

    manifest = {
        "schema": "releaseguard.function-run.v1",
        "completed_utc": datetime.now(timezone.utc).isoformat(),
        "input_sha256": before,
        "input_bytes": len(raw),
        "input_unchanged": True,
        "ghidra_version": result["version"],
        "archive_sha256": ARCHIVE_SHA if args.archive else None,
        "distribution_verification": "pinned archive verified" if args.archive else "caller supplied extracted distribution",
        "automatic_analysis": "default enabled",
        "analysis_timed_out": False,
        "loader_apply_relocations": True,
        "loaded_function_byte_changes": result["loaded_function_byte_changes"],
        "unclassified_error_lines": 0,
        "known_environment_error_lines": cache_errors,
        "file_bytes_and_instruction_coverage_verified": True,
        "headless_exit": process.returncode,
        "export_script_sha256": sha(script),
        "runner_sha256": sha(Path(__file__)),
        "output_sha256": {file.name: sha(file) for file in sorted(output.iterdir()) if file.is_file()},
        "target_entry": result["target"]["entry"],
        "instruction_count": result["instruction_count"],
        "cfg_block_count": len(result["cfg_blocks"]),
        "undecoded_bytes": result["undecoded_bytes"],
        "dependency_counts": {name: len(rows) for name, rows in result["dependencies"].items()},
        "unresolved_computed_transfers": sum(not row["flow_targets"]
                                              for row in result["dependencies"]["computed_transfers"]),
        "target_decompile_completed": result["decompile_completed"],
        "whole_program": program_summary,
    }
    (output / "run.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
