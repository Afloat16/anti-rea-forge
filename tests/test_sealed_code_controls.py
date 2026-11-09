"""Regression checks for public-byte extraction and sealed-code control failures."""

from argparse import Namespace
from contextlib import redirect_stderr
import copy
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from benchmarks import sealed_code_controls as controls
from releaseguard.sealed import seal_asset


KEY = bytes(range(32))


def memory_record(parts):
    return {"blocks": [{"loaded": True, "initialized": True, "execute": True,
                        "memory": {"ranges": [{"start": hex(start), "loaded_hex": data.hex()}]}}
                       for start, data in parts]}


class PublicCandidateExtraction(unittest.TestCase):
    def setUp(self):
        self.envelope = seal_asset(b"owned VM payload", KEY, **controls.CONTEXT)

    def test_adjacent_export_ranges_are_merged_without_private_inputs(self):
        memory = memory_record([(0x1000, KEY[:13]), (0x100d, KEY[13:])])
        with patch.object(Path, "read_bytes", side_effect=AssertionError("Extractor read a file")):
            recovered, report = controls.candidate_keys(memory, self.envelope, controls.CONTEXT)
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0][0], KEY)
        self.assertEqual(report["distinct_32byte_candidates"], 1)
        self.assertTrue(report["all_candidates_tested_with_public_envelope"])
        self.assertEqual(report["successful_key_decryptions"], 1)
        self.assertNotIn(KEY.hex(), json.dumps(report))

    def test_gap_prevents_a_false_contiguous_key(self):
        memory = memory_record([(0x1000, KEY[:13]), (0x100e, KEY[13:]), (0x2000, bytes(32))])
        recovered, report = controls.candidate_keys(memory, self.envelope, controls.CONTEXT)
        self.assertEqual(recovered, [])
        self.assertEqual(report["distinct_32byte_candidates"], 1)

    def test_duplicate_candidates_are_tested_once(self):
        recovered, report = controls.candidate_keys(
            memory_record([(0x1000, KEY), (0x2000, KEY)]), self.envelope, controls.CONTEXT)
        self.assertEqual(len(recovered), 1)
        self.assertEqual(report["distinct_32byte_candidates"], 1)

    def test_loaded_export_bytes_are_the_candidate_source(self):
        memory = memory_record([(0x1000, bytes(32))])
        memory["blocks"][0]["memory"]["ranges"][0]["hex"] = KEY.hex()
        recovered, _ = controls.candidate_keys(memory, self.envelope, controls.CONTEXT)
        self.assertEqual(recovered, [])

    def test_wrong_context_does_not_authenticate_a_present_key(self):
        recovered, _ = controls.candidate_keys(memory_record([(0x1000, KEY)]), self.envelope,
                                             {**controls.CONTEXT, "asset_id": "other"})
        self.assertEqual(recovered, [])

    def test_overlapping_or_empty_exports_are_rejected(self):
        for memory in (memory_record([(0x1000, KEY), (0x1001, KEY)]), memory_record([])):
            with self.subTest(memory=memory), self.assertRaises(RuntimeError):
                controls.candidate_keys(memory, self.envelope, controls.CONTEXT)


class GatePatchValidation(unittest.TestCase):
    def setUp(self):
        image = bytearray(192)
        image[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", image, 16, 2, 62)
        struct.pack_into("<Q", image, 32, 64)
        struct.pack_into("<HH", image, 54, 56, 1)
        struct.pack_into("<II6Q", image, 64, 1, 5, 128, 0x401000, 0, 32, 32, 4096)
        image[128:160] = b"\x90" * 31 + b"\xc3"
        self.image = bytes(image)
        self.gate = {"name": "rg_code_gate", "status": "completed", "entry": "0x401000",
                     "body_ranges": [{"start": "0x401000", "size": 16}], "body_addresses": 16}
        self.memory = memory_record([(0x401000, self.image[128:160])])
        row = self.memory["blocks"][0]["memory"]["ranges"][0]
        row.update(file_offset=128, hex=self.image[128:160].hex())

    def test_gate_patch_uses_verified_native_file_mapping(self):
        modified, report = controls.gate_patch(self.image, self.memory, self.gate)
        self.assertEqual(report["gate_file_offset"], 128)
        self.assertEqual(modified[:128], self.image[:128])
        self.assertEqual(modified[128:134], controls.PATCH)
        self.assertEqual(modified[134:], self.image[134:])

    def test_wrong_gate_provenance_and_short_body_fail(self):
        memory = copy.deepcopy(self.memory)
        memory["blocks"][0]["memory"]["ranges"][0]["file_offset"] += 1
        with self.assertRaisesRegex(RuntimeError, "provenance"):
            controls.gate_patch(self.image, memory, self.gate)
        gate = {**self.gate, "body_ranges": [{"start": "0x401000", "size": 5}], "body_addresses": 5}
        with self.assertRaisesRegex(RuntimeError, "too short"):
            controls.gate_patch(self.image, self.memory, gate)

    def test_nonexecutable_and_unbacked_addresses_fail(self):
        image = bytearray(self.image)
        struct.pack_into("<I", image, 68, 4)
        with self.assertRaisesRegex(RuntimeError, "executable mapping"):
            controls.gate_patch(bytes(image), self.memory, self.gate)
        with self.assertRaisesRegex(RuntimeError, "executable mapping"):
            controls.executable_file_offset(self.image, 0x401020, 6)


class FailureAccounting(unittest.TestCase):
    def test_tool_failures_do_not_count_as_authorization_rejections(self):
        for code, output, error in ((-11, b"", b""), (2, b"", b""), (0, b"", b""),
                                    (1, b"unexpected", b""), (1, b"", b"failed")):
            process = subprocess.CompletedProcess([], code, output, error)
            with self.subTest(code=code, output=output, error=error), self.assertRaises(RuntimeError):
                controls.rejected(process)
        good = subprocess.CompletedProcess([], 1, b"", controls.HOOK_MARKER)
        self.assertTrue(controls.rejected(good, controls.HOOK_MARKER)["authorization_rejected"])
        with self.assertRaises(RuntimeError):
            controls.rejected(good)

    def test_timeout_is_an_explicit_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "app"
            binary.write_bytes(b"placeholder")
            with patch.object(controls.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 120)):
                with self.assertRaisesRegex(RuntimeError, "timed out"):
                    controls.invoke(binary, KEY, b"1234")

    def test_missing_whole_program_export_fails_before_extraction(self):
        record = {"schema": "releaseguard.function-run.v1", "ghidra_version": controls.probe.VERSION,
                  "headless_exit": 0, "analysis_timed_out": False, "input_unchanged": True,
                  "file_bytes_and_instruction_coverage_verified": True,
                  "input_sha256": controls.digest(b"ELF"), "input_bytes": 3, "output_sha256": {}}
        with patch.object(controls, "load", return_value=record):
            with self.assertRaisesRegex(RuntimeError, "include-program"):
                controls.observe(Path("observation"), b"ELF")
        for field, value in (("analysis_timed_out", True), ("headless_exit", 1), ("input_unchanged", False)):
            with self.subTest(field=field), patch.object(controls, "load", return_value={**record, field: value}):
                with self.assertRaisesRegex(RuntimeError, "Incomplete"):
                    controls.observe(Path("observation"), b"ELF")

    def test_existing_report_is_preserved_before_analysis(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            report.write_text("keep")
            with patch.object(controls, "analyze") as analyze, redirect_stderr(io.StringIO()):
                result = controls.main(["analyze", str(root), "--observations", str(root), "--out", str(report)])
            self.assertEqual(result, 2)
            analyze.assert_not_called()
            self.assertEqual(report.read_text(), "keep")

    def test_leak_is_a_used_real_key_and_gate_calls_initialization(self):
        source = controls.driver_source("releaseguard::module", KEY)
        self.assertIn(b"__attribute__((used))", source)
        self.assertIn(b"CRYPTO_memcmp(raw, accidentally_bundled_key, 32)", source)
        self.assertIn(b"releaseguard::module::initialize_native_code(key)", source)
        self.assertIn(b'extern "C" __attribute__((noinline)) int rg_code_gate', source)

    def test_required_native_controls_fail_when_tool_configuration_is_missing(self):
        with patch.dict(os.environ, {"RELEASEGUARD_REQUIRE_NATIVE_VIRTUALIZATION": "1"}, clear=True):
            with self.assertRaisesRegex(AssertionError, "requires RELEASEGUARD_LLVM_BIN"):
                SealedControlsLLVM.setUpClass()


class SealedControlsLLVM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        llvm = os.environ.get("RELEASEGUARD_LLVM_BIN")
        plugin = os.environ.get("RELEASEGUARD_AMICE_PLUGIN")
        if not llvm or not plugin:
            reason = "requires RELEASEGUARD_LLVM_BIN and RELEASEGUARD_AMICE_PLUGIN"
            if os.environ.get("RELEASEGUARD_REQUIRE_NATIVE_VIRTUALIZATION") == "1":
                raise AssertionError(reason)
            raise unittest.SkipTest(reason)
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name) / "corpus"
        cls.fixture = controls.prepare(Namespace(
            corpus=cls.root, llvm_bin=Path(llvm), plugin=Path(plugin), seed=None,
            plugin_sha256=controls.digest(Path(plugin).read_bytes())))

    def test_three_native_cases_and_negative_controls(self):
        self.assertEqual({path.name for path in (self.root / "public").iterdir()}, set(controls.CASES))
        key = (self.root / "private/key.bin").read_bytes()
        ciphertext = controls._envelope(controls.load(self.root / "envelope.json"))[2]
        for case, row in self.fixture["cases"].items():
            image = (self.root / "public" / case).read_bytes()
            self.assertEqual(key in image, case == "key_leak")
            self.assertTrue(row["good_key"]["ok"])
            self.assertEqual(row["wrong_key"]["returncode"], 0 if case == "plaintext" else 1)
            if case != "plaintext":
                self.assertIn(ciphertext, image)
        self.assertTrue(self.fixture["forced_final"]["good_key"]["ok"])
        self.assertTrue(self.fixture["forced_final"]["wrong_key"]["authorization_rejected"])
        for row in self.fixture["negative_controls"].values():
            self.assertTrue(row["python_aead_rejected"])
            self.assertTrue(row["native"]["authorization_rejected"])

    def test_changed_private_reference_fails(self):
        with patch.object(controls, "artifact", return_value={"sha256": "wrong", "bytes": 0}):
            with self.assertRaisesRegex(RuntimeError, "Private manifest changed"):
                controls.load_private(self.root, self.fixture)


if __name__ == "__main__":
    unittest.main()
