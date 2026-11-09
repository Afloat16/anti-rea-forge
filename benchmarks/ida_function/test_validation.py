"""Synthetic validator tests. Genuine IDA 9.x execution remains pending."""

import ast
import copy
import hashlib
from pathlib import Path
import unittest

from benchmarks.ida_function.validation import validate_report


class ModernIDAValidation(unittest.TestCase):
    def setUp(self):
        self.raw = b"\x7fELF\x90\xc3"
        self.code = b"unsigned rg_compute(unsigned x) { return x; }\n"
        digest = hashlib.sha256(self.raw).hexdigest()
        self.function = {
            "entry": "0x1000", "name": "rg_compute", "observation_status": "completed",
            "body_ranges": [{"start": "0x1000", "size": 2}], "body_bytes": 2,
            "byte_ranges": [{"start": "0x1000", "size": 2, "file_offset": 4,
                             "hex": "90c3", "loaded_hex": "90c3", "mapping_roundtrip": True}],
            "instructions": [{"address": "0x1000", "size": 1, "hex": "90"},
                             {"address": "0x1001", "size": 1, "hex": "c3"}],
            "instruction_count": 2, "undecoded_bytes": 0, "loaded_byte_changes": 0,
            "c_offset": 0, "c_bytes": len(self.code), "c_sha256": hashlib.sha256(self.code).hexdigest(),
            "decompiler_status": "completed", "decompiler_error": "", "hexrays_warnings": [],
        }
        self.report = {
            "tool": "IDA", "ida_version": "9.0", "hexrays": {"available": True},
            "input_sha256": digest, "idb_input_sha256": digest, "analysis_complete": True,
            "target_entry": "0x1000", "function_inventory": [{"entry": "0x1000", "name": "rg_compute"}],
            "functions": [self.function],
        }

    def test_exporter_has_valid_python_syntax(self):
        ast.parse((Path(__file__).parent / "export_functions.py").read_text())

    def test_synthetic_valid_record(self):
        summary = validate_report(self.report, self.raw, self.code)
        self.assertEqual(summary["byte_verified_functions"], 1)
        self.assertEqual(summary["api_completed_functions"], 1)

    def test_historical_engine_version_is_rejected(self):
        self.report["ida_version"] = "5.0"
        with self.assertRaisesRegex(RuntimeError, "IDA 9.x"):
            validate_report(self.report, self.raw, self.code)

    def test_wrong_file_mapping_is_rejected(self):
        self.function["byte_ranges"][0]["file_offset"] = 3
        with self.assertRaisesRegex(RuntimeError, "original bytes"):
            validate_report(self.report, self.raw, self.code)

    def test_omitted_helper_is_rejected(self):
        self.report["function_inventory"].append({"entry": "0x2000", "name": "helper"})
        with self.assertRaisesRegex(RuntimeError, "omit or duplicate"):
            validate_report(self.report, self.raw, self.code)

    def test_helper_failure_and_warning_are_retained(self):
        self.function["hexrays_warnings"] = [{"address": "0x1000", "id": 1, "text": "test warning"}]
        helper = copy.deepcopy(self.function)
        helper.update(entry="0x2000", name="helper", observation_status="failed", observation_error="unmapped byte",
                      decompiler_status="failed", decompiler_error="decompilation failed", hexrays_warnings=[],
                      c_offset=len(self.code), c_bytes=0, c_sha256=hashlib.sha256(b"").hexdigest())
        self.report["function_inventory"].append({"entry": "0x2000", "name": "helper"})
        self.report["functions"].append(helper)
        summary = validate_report(self.report, self.raw, self.code)
        self.assertEqual(len(summary["observation_failures"]), 1)
        self.assertEqual(len(summary["decompiler_failures"]), 1)
        self.assertEqual(len(summary["function_warnings"]), 1)

    def test_unavailable_hexrays_cannot_claim_completed_c(self):
        self.report["hexrays"]["available"] = False
        with self.assertRaisesRegex(RuntimeError, "Unavailable decompiler"):
            validate_report(self.report, self.raw, self.code)

    def test_unavailable_hexrays_is_retained_with_valid_disassembly(self):
        self.report["hexrays"]["available"] = False
        self.function.update(decompiler_status="unavailable", decompiler_error="init returned false",
                             c_bytes=0, c_sha256=hashlib.sha256(b"").hexdigest())
        summary = validate_report(self.report, self.raw, b"")
        self.assertEqual(summary["byte_verified_functions"], 1)
        self.assertEqual(summary["api_completed_functions"], 0)
        self.assertEqual(summary["decompiler_failures"][0]["decompiler_status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
