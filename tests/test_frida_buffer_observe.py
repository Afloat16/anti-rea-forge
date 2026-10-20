"""Check observation classification; these tests do not stand in for Frida runs."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "benchmarks" / "frida_buffer_observe.py"
SPEC = importlib.util.spec_from_file_location("frida_buffer_observe", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BENCHMARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)


def rows():
    common = {"kind": "checkpoint", "byte_count": 32, "locked": True,
              "dump_excluded": True, "guard_pages": True}
    return [dict(common, phase=1, public_pattern_matches=True, all_zero=False),
            dict(common, phase=2, public_pattern_matches=False, all_zero=True)]


class FridaBufferObservationTests(unittest.TestCase):
    def test_expected_live_read_and_owned_clear_are_both_required(self):
        self.assertTrue(BENCHMARK.observations_match(rows()))
        for partial in ([], rows()[:1], rows()[1:], rows()[::-1], [rows()[0], rows()[0]]):
            with self.subTest(partial=partial):
                self.assertFalse(BENCHMARK.observations_match(partial))

    def test_no_live_read_or_uncleared_data_cannot_complete(self):
        for index, field, value in ((0, "public_pattern_matches", False),
                                    (0, "all_zero", True), (1, "all_zero", False),
                                    (1, "public_pattern_matches", True)):
            with self.subTest(index=index, field=field):
                observed = rows()
                observed[index][field] = value
                self.assertFalse(BENCHMARK.observations_match(observed))

    def test_unexpected_payload_or_wrong_types_are_rejected(self):
        for field, value in (("raw_bytes", "not allowed"), ("all_zero", 0),
                             ("phase", True), ("byte_count", 31)):
            with self.subTest(field=field):
                observed = rows()
                observed[0][field] = value
                self.assertFalse(BENCHMARK.observations_match(observed))

    def test_missing_frida_is_not_a_protection_success(self):
        with mock.patch.object(BENCHMARK.platform, "system", return_value="Linux"), \
             mock.patch.object(BENCHMARK.importlib, "import_module",
                               side_effect=ModuleNotFoundError("frida unavailable in test")):
            report = BENCHMARK.experiment()
        self.assertEqual(report["status"], "environment_failure")
        self.assertEqual(report["protection_outcome"], "not_evaluated")
        self.assertFalse(report["scope"]["real_frida_instrumentation_completed"])
        self.assertFalse(report["scope"]["rea_agent_model_pipeline"])
        self.assertEqual(report["error"]["stage"], "load_frida")
        json.dumps(report)

    def test_cli_does_not_accept_an_external_binary_or_pid(self):
        for argument in ("--binary", "--pid", "--script"):
            with self.subTest(argument=argument):
                result = subprocess.run([sys.executable, str(SCRIPT), argument, "external"],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("unrecognized arguments", result.stderr)


if __name__ == "__main__":
    unittest.main()
