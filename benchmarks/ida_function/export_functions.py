"""Run inside licensed IDA 9.x with IDAPython. Actual engine validation is pending."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_gdl
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_loader
import ida_name
import ida_nalt
import ida_pro
import ida_segment
import ida_ua
import idautils
import idc

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from validation import require, validate_report


def function_bytes(chunks, raw):
    rows = []
    changed = 0
    for start, end in chunks:
        loaded = ida_bytes.get_bytes(start, end - start)
        require(loaded is not None and len(loaded) == end - start, "Incomplete IDA database byte read")
        original = bytearray()
        offsets = []
        for address in range(start, end):
            require(ida_bytes.is_loaded(address), "Function address is not loaded in IDA")
            offset = ida_loader.get_fileregion_offset(address)
            require(0 <= offset < len(raw) and ida_loader.get_fileregion_ea(offset) == address,
                    "IDA function byte has no reversible input-file mapping")
            value = ida_bytes.get_original_byte(address)
            require(0 <= value <= 255 and value == raw[offset], "IDA original byte differs from its input mapping")
            original.append(value)
            offsets.append(offset)
        cursor = 0
        for index in range(1, len(original) + 1):
            if index == len(original) or offsets[index] != offsets[index - 1] + 1:
                rows.append({"start": hex(start + cursor), "file_offset": offsets[cursor],
                             "size": index - cursor, "hex": original[cursor:index].hex(),
                             "loaded_hex": loaded[cursor:index].hex(), "mapping_roundtrip": True})
                cursor = index
        changed += sum(left != right for left, right in zip(original, loaded))
    return rows, changed


def observe_function(entry, raw):
    function = ida_funcs.get_func(entry)
    require(function is not None and function.start_ea == entry, "IDA function start is missing")
    chunks = sorted(set(idautils.Chunks(entry)))
    size = sum(end - start for start, end in chunks)
    require(0 < size <= 1024 * 1024, "Function exceeds the byte budget")
    byte_ranges, changed = function_bytes(chunks, raw)
    instructions = []
    decoded = set()
    for address in sorted(set(idautils.FuncItems(entry))):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(address)):
            continue
        instruction = ida_ua.insn_t()
        length = ida_ua.decode_insn(instruction, address)
        require(length > 0, "IDA marked an instruction that cannot be decoded")
        data = ida_bytes.get_bytes(address, length)
        require(data is not None and len(data) == length, "IDA instruction bytes are missing")
        instructions.append({"address": hex(address), "size": length, "hex": data.hex(),
                             "text": ida_lines.tag_remove(ida_lines.generate_disasm_line(address, 0) or ""),
                             "code_references": [hex(ea) for ea in idautils.CodeRefsFrom(address, False)],
                             "data_references": [hex(ea) for ea in idautils.DataRefsFrom(address)]})
        decoded.update(range(address, address + length))
    cfg = [{"id": block.id, "start": hex(block.start_ea), "end": hex(block.end_ea),
            "successors": [successor.id for successor in block.succs()]}
           for block in ida_gdl.FlowChart(function)]
    return {"observation_status": "completed", "body_bytes": size,
            "body_ranges": [{"start": hex(start), "size": end - start} for start, end in chunks],
            "byte_ranges": byte_ranges, "loaded_byte_changes": changed,
            "instructions": instructions, "instruction_count": len(instructions),
            "undecoded_bytes": size - len(decoded), "cfg_blocks": cfg}


def decompile_function(entry, decompiler, available):
    if not available:
        return b"", {"decompiler_status": "unavailable", "decompiler_error": "Hex-Rays unavailable in this session",
                     "hexrays_warnings": []}
    try:
        function = decompiler.decompile(entry)
        require(function is not None, "Hex-Rays returned no cfunc object")
        code = ("\n".join(ida_lines.tag_remove(line.line) for line in function.get_pseudocode()) + "\n").encode("utf-8")
        require(code.strip(), "Hex-Rays returned empty pseudocode")
        warnings = [{"address": hex(warning.ea), "id": int(warning.id), "text": str(warning.text)}
                    for warning in function.get_warnings()]
        return code, {"decompiler_status": "completed", "decompiler_error": "", "hexrays_warnings": warnings}
    except Exception as error:
        return b"", {"decompiler_status": "failed", "decompiler_error": f"{type(error).__name__} {error}",
                     "hexrays_warnings": []}


def main():
    require(len(idc.ARGV) == 2, "Pass exactly one new output directory to the IDAPython script")
    output = Path(idc.ARGV[1]).resolve()
    output.mkdir(parents=True, exist_ok=False)
    version = ida_kernwin.get_kernel_version()
    require(version.startswith("9."), "This adapter requires an IDA 9.x engine")
    require(ida_ida.inf_get_procname() == "metapc", "This fixture adapter requires x86")
    source = Path(ida_nalt.get_input_file_path()).resolve(strict=True)
    require(0 < source.stat().st_size <= 16 * 1024 * 1024, "Input exceeds the fixture budget")
    raw = source.read_bytes()
    require(raw.startswith(b"\x7fELF"), "This fixture adapter requires a complete ELF")
    digest = hashlib.sha256(raw).hexdigest()
    recorded_digest = ida_nalt.retrieve_input_file_sha256()
    require(recorded_digest is not None and recorded_digest.hex() == digest, "IDA input hash disagrees with the file")
    require(ida_auto.auto_wait() and ida_auto.auto_is_ok(), "IDA automatic analysis did not complete")
    target = ida_name.get_name_ea(ida_idaapi.BADADDR, "rg_compute")
    require(target != ida_idaapi.BADADDR, "Public rg_compute symbol was not found")
    target_function = ida_funcs.get_func(target)
    require(target_function is not None and target_function.start_ea == target, "Public symbol is not a function entry")

    decompiler = None
    hexrays = {"available": False, "version": None, "initialization_error": ""}
    try:
        import ida_hexrays as decompiler
        hexrays["available"] = bool(decompiler.init_hexrays_plugin())
        if hexrays["available"]:
            hexrays["version"] = decompiler.get_hexrays_version()
        else:
            hexrays["initialization_error"] = "init_hexrays_plugin returned false in this session"
    except Exception as error:
        hexrays["initialization_error"] = f"{type(error).__name__} {error}"

    entries = []
    for entry in sorted(set(idautils.Functions())):
        segment = ida_segment.getseg(entry)
        if segment is not None and segment.type != ida_segment.SEG_XTRN:
            entries.append(entry)
    require(target in entries and 0 < len(entries) <= 2048, "Invalid recognized function inventory")
    inventory = [{"entry": hex(entry), "name": ida_funcs.get_func_name(entry)} for entry in entries]
    functions = []
    program_c = bytearray()
    total_function_bytes = 0
    for item, entry in zip(inventory, entries):
        row = dict(item)
        try:
            row.update(observe_function(entry, raw))
            total_function_bytes += row["body_bytes"]
            require(total_function_bytes <= 16 * 1024 * 1024, "Program function bytes exceed the fixture budget")
        except Exception as error:
            row.update(observation_status="failed", observation_error=f"{type(error).__name__} {error}")
        code, status = decompile_function(entry, decompiler, hexrays["available"])
        row.update(status)
        program_c.extend(f"\n/* IDA FUNCTION {entry:#x} */\n".encode("ascii"))
        row.update(c_offset=len(program_c), c_bytes=len(code), c_sha256=hashlib.sha256(code).hexdigest())
        program_c.extend(code)
        require(len(program_c) <= 16 * 1024 * 1024, "Program C exceeds the fixture budget")
        functions.append(row)
        if entry == target:
            (output / "decompiled.c").write_bytes(code)

    report = {"schema": "releaseguard.ida-function-observation.v1", "tool": "IDA", "ida_version": version,
              "hexrays": hexrays, "input_sha256": digest, "idb_input_sha256": recorded_digest.hex(),
              "processor": ida_ida.inf_get_procname(), "address_bits": 64 if ida_ida.inf_is_64bit() else 32,
              "analysis_complete": True, "target_name": "rg_compute", "target_entry": hex(target),
              "function_inventory": inventory, "functions": functions}
    (output / "program.elf").write_bytes(raw)
    (output / "program.c").write_bytes(program_c)
    (output / "functions.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = validate_report(report, raw, program_c)
    require(hashlib.sha256(source.read_bytes()).hexdigest() == digest, "Input changed during analysis")
    manifest = {"schema": "releaseguard.ida-function-run.v1", "completed_utc": datetime.now(timezone.utc).isoformat(),
                "engine_executed": True, "ida_version": version, "hexrays": hexrays, "input_sha256": digest,
                "summary": summary, "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "validation_sha256": hashlib.sha256((HERE / "validation.py").read_bytes()).hexdigest(),
                "output_sha256": {file.name: hashlib.sha256(file.read_bytes()).hexdigest()
                                  for file in sorted(output.iterdir()) if file.is_file()}}
    (output / "run.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("RELEASEGUARD_IDA9_FUNCTION_EXPORT_COMPLETE")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        ida_pro.qexit(1)
    ida_pro.qexit(0)
