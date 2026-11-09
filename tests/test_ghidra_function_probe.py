"""Reject incomplete analyzer exports and preserve the observed cache diagnostic."""

from __future__ import annotations

import copy
import hashlib
import struct
import unittest

from benchmarks.ghidra_function.probe import (
    decompiler_warnings, validate_bytes, validate_logs, validate_program_functions, validate_program_memory,
)


class FunctionObservationValidation(unittest.TestCase):
    def setUp(self):
        self.raw = b"\x7fELF\x90\xc3"
        self.report = {
            "original_byte_ranges": [{"start": "0x1000", "file_offset": 4, "size": 2,
                                       "hex": "90c3", "loaded_hex": "90c3"}],
            "loaded_function_byte_changes": 0,
            "body_ranges": [{"start": "0x1000", "size": 2}],
            "body_addresses": 2,
            "instructions": [{"address": "0x1000", "size": 1, "hex": "90"},
                             {"address": "0x1001", "size": 1, "hex": "c3"}],
            "instruction_count": 2,
            "undecoded_ranges": [],
            "undecoded_bytes": 0,
            "cfg_blocks": [{"ranges": [{"start": "0x1000", "size": 2}]}],
        }

    def test_exact_file_and_loaded_instruction_bytes(self):
        validate_bytes(self.report, self.raw)

    def test_relocated_memory_preserves_distinct_original_file_provenance(self):
        self.report["original_byte_ranges"][0]["loaded_hex"] = "91c3"
        self.report["loaded_function_byte_changes"] = 1
        self.report["instructions"][0]["hex"] = "91"
        validate_bytes(self.report, self.raw)

    def test_changed_input_file_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "differ from the input ELF"):
            validate_bytes(self.report, b"\x7fELF\x91\xc3")

    def test_incomplete_or_inconsistent_coverage_is_rejected(self):
        corruptions = [
            ("body", lambda report: report["body_ranges"][0].update(size=3)),
            ("instruction", lambda report: report["instructions"][0].update(hex="91")),
            ("CFG", lambda report: report["cfg_blocks"][0]["ranges"][0].update(size=1)),
            ("undecoded", lambda report: report.update(undecoded_ranges=[{"start": "0x1000", "size": 1}])),
            ("loaded changes", lambda report: report.update(loaded_function_byte_changes=1)),
            ("duplicate byte range", lambda report: report["original_byte_ranges"].append(
                copy.deepcopy(report["original_byte_ranges"][0]))),
        ]
        for label, corrupt in corruptions:
            with self.subTest(corruption=label):
                report = copy.deepcopy(self.report)
                corrupt(report)
                with self.assertRaises(RuntimeError):
                    validate_bytes(report, self.raw)


class FunctionAnalysisLogValidation(unittest.TestCase):
    def setUp(self):
        self.console = (
            "INFO REPORT: Analysis succeeded for file: sample.elf\n"
            "INFO ExportCompute.java> RELEASEGUARD_FUNCTION_EXPORT_COMPLETE (GhidraScript)\n"
            "INFO REPORT: Post-analysis succeeded for file: sample.elf\n"
        )

    def test_completed_analysis_without_diagnostic(self):
        self.assertEqual(validate_logs(self.console, ""), [])

    def test_exact_cache_space_query_diagnostic_is_retained(self):
        console_error = ("ERROR Failed to get java FileStore for path /cache/fscache2, "
                         "will be unable to check free/available space. (FileCache)  ")
        file_error = ("2026-11-09 06:09:59 ERROR (FileCache) Failed to get java FileStore for path "
                      "/cache/fscache2, will be unable to check free/available space.  ")
        self.assertEqual(validate_logs(self.console + console_error, file_error),
                         [console_error, file_error])

    def test_analysis_or_unrelated_cache_error_fails(self):
        for error in ("ERROR Unexpected exception (DecompilerCallConventionAnalyzer)",
                      "ERROR Failed to create file (FileCache)",
                      "ERROR Failed to get java FileStore for path /cache/fscache2, "
                      "will be unable to check free/available space. (OtherComponent)"):
            with self.subTest(error=error):
                with self.assertRaisesRegex(RuntimeError, "unexplained error"):
                    validate_logs(self.console + error, "")

    def test_missing_analysis_completion_is_rejected(self):
        for line in self.console.splitlines():
            with self.subTest(missing=line):
                with self.assertRaises(RuntimeError):
                    validate_logs(self.console.replace(line, ""), "")


class WholeProgramFunctionValidation(unittest.TestCase):
    def setUp(self):
        pieces = [b"root();\n", b"helper();\n"]
        self.code = b"".join(pieces)
        self.record = {
            "function_inventory": [{"entry": "0x1000", "name": "rg_compute"},
                                   {"entry": "0x2000", "name": "vm_helper"}],
            "function_count": 2, "completed_functions": 2, "failed_functions": 0,
            "functions": [],
        }
        offset = 0
        for function, code in zip(self.record["function_inventory"], pieces):
            self.record["functions"].append({**function, "status": "completed", "message": "",
                                             "c_offset": offset, "c_bytes": len(code),
                                             "c_sha256": hashlib.sha256(code).hexdigest()})
            offset += len(code)

    def test_all_recognized_helpers_have_recorded_outputs(self):
        result = validate_program_functions(self.record, self.code)
        self.assertEqual(result["api_completed_functions"], 2)
        self.assertEqual(result["function_failures"], [])

    def test_omitted_helper_is_rejected(self):
        self.record["functions"].pop()
        with self.assertRaisesRegex(RuntimeError, "omit or duplicate an inventory"):
            validate_program_functions(self.record, self.code)

    def test_failed_helper_remains_an_explicit_failure(self):
        helper = self.record["functions"][1]
        helper.update(status="timeout", message="Decompiler exceeded its budget", c_bytes=0,
                      c_sha256=hashlib.sha256(b"").hexdigest())
        self.record.update(completed_functions=1, failed_functions=1)
        result = validate_program_functions(self.record, self.code[:helper["c_offset"]])
        self.assertEqual(result["api_completed_functions"], 1)
        self.assertEqual(result["function_failures"], [
            {"entry": "0x2000", "name": "vm_helper", "status": "timeout",
             "message": "Decompiler exceeded its budget"},
        ])

    def test_modified_helper_c_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "output hash mismatch"):
            validate_program_functions(self.record, self.code[:-1] + b"!")

    def test_api_completed_helper_retains_control_flow_warnings(self):
        helper_code = (
            b"/* WARNING: Could not recover jumptable at 0x2000. Too many branches */\n"
            b"/* WARNING: Treating indirect jump as call */\n"
            b"/* WARNING: Bad instruction - Truncating control flow here */\n"
            b"  halt_baddata();\n"
        )
        helper = self.record["functions"][1]
        helper.update(c_bytes=len(helper_code), c_sha256=hashlib.sha256(helper_code).hexdigest())
        code = self.code[:helper["c_offset"]] + helper_code
        result = validate_program_functions(self.record, code)
        self.assertEqual(result["api_completed_functions"], 2)
        self.assertEqual(result["functions_with_warnings"], 1)
        self.assertEqual(result["warning_counts"], {
            "halt_baddata_call": 1, "indirect_jump_as_call": 1,
            "truncated_control_flow": 1, "unrecovered_jump_table": 1,
        })
        self.assertEqual(result["function_warnings"][0]["entry"], "0x2000")
        self.assertEqual(result["function_warnings"][0]["api_status"], "completed")
        self.assertEqual(code[helper["c_offset"]:], helper_code)

    def test_generic_and_multiline_warning_comments_are_retained(self):
        warnings = decompiler_warnings(
            b"/* WARNING: Unknown calling convention\n -- parameter storage is locked */\n"
            b"/* WARNING: Control flow encountered bad instruction data */\n")
        self.assertEqual([row["kind"] for row in warnings], ["decompiler_warning", "bad_instruction_data"])
        self.assertEqual([row["c_line"] for row in warnings], [1, 3])
        call = decompiler_warnings(b"\n\n  halt_baddata();\n")
        self.assertEqual(call[0]["c_line"], 3)


class WholeProgramMemoryValidation(unittest.TestCase):
    def setUp(self):
        raw = bytearray(256)
        raw[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", raw, 16, 2, 62)
        struct.pack_into("<Q", raw, 40, 128)
        struct.pack_into("<HH", raw, 58, 64, 2)
        struct.pack_into("<II4Q", raw, 192, 0, 1, 2, 0x1000, 64, 2)
        raw[64:66] = b"\x90\xc3"
        self.raw = bytes(raw)
        self.record = {
            "initialized_loaded_bytes": 3,
            "blocks": [
                {"start": "0x1000", "size": 2, "loaded": True, "initialized": True,
                 "memory": {"ranges": [{"start": "0x1000", "size": 2, "file_offset": 64,
                                         "hex": "90c3", "loaded_hex": "90c3"}],
                            "file_backed_bytes": 2, "unbacked_bytes": 0, "loaded_byte_changes": 0}},
                {"start": "0x2000", "size": 1, "loaded": True, "initialized": True,
                 "memory": {"ranges": [{"start": "0x2000", "size": 1, "loaded_hex": "00"}],
                            "file_backed_bytes": 0, "unbacked_bytes": 1, "loaded_byte_changes": 0}},
            ],
        }

    def test_original_and_unbacked_memory_are_accounted_for(self):
        result = validate_program_memory(self.record, self.raw)
        self.assertEqual(result["allocated_file_bytes_verified"], 2)
        self.assertEqual(result["unbacked_bytes"], 1)

    def test_missing_allocated_data_is_rejected(self):
        self.record["blocks"].pop(0)
        self.record["initialized_loaded_bytes"] = 1
        with self.assertRaisesRegex(RuntimeError, "omits an allocated ELF section byte"):
            validate_program_memory(self.record, self.raw)

    def test_modified_original_data_is_rejected(self):
        self.record["blocks"][0]["memory"]["ranges"][0]["hex"] = "91c3"
        with self.assertRaisesRegex(RuntimeError, "file-byte provenance"):
            validate_program_memory(self.record, self.raw)

    def test_synthetic_memory_cannot_claim_unmapped_original_bytes(self):
        self.record["blocks"][1]["memory"]["ranges"][0]["hex"] = "00"
        with self.assertRaisesRegex(RuntimeError, "claims original file bytes"):
            validate_program_memory(self.record, self.raw)


if __name__ == "__main__":
    unittest.main()
