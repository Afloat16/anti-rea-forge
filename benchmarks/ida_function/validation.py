"""Engine-independent validation of an IDA 9.x function observation."""

from __future__ import annotations

import hashlib
import re


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_function(row, raw):
    original, loaded = {}, {}
    for block in row["byte_ranges"]:
        start, offset = int(block["start"], 16), block["file_offset"]
        data, memory = bytes.fromhex(block["hex"]), bytes.fromhex(block["loaded_hex"])
        require(0 < len(data) == len(memory) == block["size"] <= 1024 * 1024
                and 0 <= offset <= offset + len(data) <= len(raw), "Invalid IDA byte range")
        require(block["mapping_roundtrip"] is True, "IDA file mapping was not verified")
        require(raw[offset:offset + len(data)] == data, "IDA original bytes differ from the input file")
        for index, value in enumerate(data):
            address = start + index
            require(address not in original, "Overlapping IDA function byte ranges")
            original[address], loaded[address] = value, memory[index]
    body = set()
    for block in row["body_ranges"]:
        start, size = int(block["start"], 16), block["size"]
        require(0 < size <= 1024 * 1024 and len(body) + size <= 1024 * 1024, "Invalid IDA function body")
        addresses = set(range(start, start + size))
        require(body.isdisjoint(addresses), "Overlapping IDA function chunks")
        body.update(addresses)
    require(body == original.keys() and len(body) == row["body_bytes"] > 0,
            "IDA original-byte coverage is incomplete")
    decoded = set()
    for instruction in row["instructions"]:
        start = int(instruction["address"], 16)
        data = bytes.fromhex(instruction["hex"])
        addresses = set(range(start, start + len(data)))
        require(0 < len(data) == instruction["size"] and addresses <= body
                and decoded.isdisjoint(addresses), "Invalid IDA instruction coverage")
        require(all(loaded[start + index] == value for index, value in enumerate(data)),
                "IDA instruction bytes differ from the loaded database")
        decoded.update(addresses)
    require(len(row["instructions"]) == row["instruction_count"] > 0
            and len(body - decoded) == row["undecoded_bytes"], "Inconsistent IDA instruction counts")
    require(sum(original[address] != loaded[address] for address in body) == row["loaded_byte_changes"],
            "Inconsistent IDA loaded-byte change count")


def validate_report(report, raw, code):
    require(report["tool"] == "IDA" and re.match(r"^9\.\d+(?:\D|$)", report["ida_version"]),
            "Require an actual IDA 9.x observation")
    require(hashlib.sha256(raw).hexdigest() == report["input_sha256"] == report["idb_input_sha256"],
            "IDA database/input hash mismatch")
    require(report["analysis_complete"] is True and raw.startswith(b"\x7fELF"),
            "Expected completed analysis of an ELF")
    inventory = [row["entry"] for row in report["function_inventory"]]
    observed = [row["entry"] for row in report["functions"]]
    require(0 < len(inventory) == len(set(inventory)) <= 2048
            and len(observed) == len(set(observed)) and set(observed) == set(inventory),
            "IDA function observations omit or duplicate an inventory entry")
    target = [row for row in report["functions"] if row["entry"] == report["target_entry"]]
    require(len(target) == 1 and target[0]["name"] == "rg_compute"
            and target[0]["observation_status"] == "completed", "Target observation is incomplete")
    byte_failures, decompiler_failures, warnings = [], [], []
    completed = verified = previous_end = 0
    for row in report["functions"]:
        if row["observation_status"] == "completed":
            validate_function(row, raw)
            verified += 1
        else:
            require(row["observation_status"] == "failed" and row.get("observation_error"),
                    "Failed IDA helper observation needs a diagnostic")
            byte_failures.append({key: row[key] for key in ("entry", "name", "observation_error")})
        offset, size = row["c_offset"], row["c_bytes"]
        require(previous_end <= offset <= offset + size <= len(code)
                and hashlib.sha256(code[offset:offset + size]).hexdigest() == row["c_sha256"],
                "IDA C output bounds or hash mismatch")
        previous_end = offset + size
        status = row["decompiler_status"]
        if status == "completed":
            require(report["hexrays"]["available"] is True and size > 0, "Unavailable decompiler claims C output")
            completed += 1
        else:
            require(status in ("unavailable", "failed") and row.get("decompiler_error"),
                    "Failed Hex-Rays helper needs an explicit status and diagnostic")
            decompiler_failures.append({key: row[key] for key in ("entry", "name", "decompiler_status", "decompiler_error")})
        if row["hexrays_warnings"]:
            warnings.append({"entry": row["entry"], "name": row["name"], "warnings": row["hexrays_warnings"]})
    return {"recognized_functions": len(inventory), "byte_verified_functions": verified,
            "api_completed_functions": completed, "completion_semantics": "Hex-Rays returned a cfunc object",
            "observation_failures": byte_failures, "decompiler_failures": decompiler_failures,
            "function_warnings": warnings}
