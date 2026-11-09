"""Native control regressions, with optional real LLVM 18 fixture builds."""

from argparse import Namespace
from contextlib import redirect_stderr
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from benchmarks import native_code_controls as controls


SEED = "00112233445566778899aabbccddeeff"


class NativeControlValidation(unittest.TestCase):
    def test_required_native_configuration_cannot_silently_skip(self):
        with patch.dict(os.environ, {"RELEASEGUARD_LLVM_BIN": "", "RELEASEGUARD_OBF_PLUGIN": "",
                                     "RELEASEGUARD_REQUIRE_NATIVE_OBFUSCATION": "1"}):
            with self.assertRaisesRegex(AssertionError, "RELEASEGUARD_LLVM_BIN"):
                NativeCodeControlsLLVM.setUpClass()

    def test_reproducible_kernel_has_only_noinline_attribute(self):
        source = controls.kernel_source(SEED)
        self.assertEqual(source, controls.kernel_source(SEED))
        self.assertNotEqual(source, controls.kernel_source("ff" * 16))
        self.assertIn(b"__attribute__((noinline))", source)
        self.assertNotIn(b"used", source)

    def test_fresh_values_exclude_original_values(self):
        values = controls.fresh_inputs(SEED, 1000, range(65536))
        self.assertEqual(len(set(values)), 1000)
        self.assertFalse(set(values).intersection(range(65536)))
        self.assertEqual(values, controls.fresh_inputs(SEED, 1000, range(65536)))

    def test_empty_partial_extra_and_wrong_output_fail(self):
        reference = struct.pack("<2I", 1, 2)
        for output, differences in ((b"", 2), (reference[:5], 1),
                                    (reference + b"\0", 0), (struct.pack("<2I", 1, 7), 1)):
            with self.subTest(output=output):
                result = controls.compare_output(reference, output, {"ok": True})
                self.assertFalse(result["ok"])
                self.assertEqual(result["difference_count"], differences)
        self.assertTrue(controls.compare_output(reference, reference, {"ok": True})["ok"])

    def test_exit_stderr_and_timeout_cannot_pass(self):
        for code, stderr in ((1, b""), (0, b"warning")):
            proc = subprocess.CompletedProcess(["fixture"], code, b"1234", stderr)
            with patch.object(controls.subprocess, "run", return_value=proc):
                output, record = controls.execute(["fixture"])
                self.assertFalse(controls.compare_output(output, output, record)["ok"])
        failure = subprocess.TimeoutExpired(["fixture"], 120, output=b"1234")
        with patch.object(controls.subprocess, "run", side_effect=failure):
            output, record = controls.execute(["fixture"])
            self.assertTrue(record["timed_out"])
            self.assertIsNone(record["returncode"])
            self.assertFalse(controls.compare_output(output, output, record)["ok"])

    def test_missing_transformation_coverage_is_rejected(self):
        report = {"ok": True, "transformation_applied": True, "profile": "flatten",
                  "requested": ["rg_compute"], "functions": [
                      {"name": "rg_compute", "requested": True, "changed": True,
                       "dispatcher": True, "new_dispatchers": 1}]}
        controls.validate_coverage(report, "flatten")
        for field in ("requested", "changed", "dispatcher", "new_dispatchers"):
            changed = copy.deepcopy(report)
            changed["functions"][0][field] = False
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "coverage"):
                controls.validate_coverage(changed, "flatten")
        with self.assertRaisesRegex(RuntimeError, "coverage"):
            controls.validate_coverage({**report, "functions": []}, "flatten")

    def test_existing_corpus_and_report_are_preserved_before_tool_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            existing = root / "existing.json"
            existing.write_bytes(b"keep")
            with patch.object(controls, "toolchain") as toolchain:
                with self.assertRaises(FileExistsError):
                    controls.prepare(Namespace(corpus=root))
                with redirect_stderr(io.StringIO()):
                    code = controls.main(["cost", str(root), "--llvm-bin", str(root),
                                          "--out", str(existing)])
                self.assertEqual(code, 2)
                toolchain.assert_not_called()
            self.assertEqual(existing.read_bytes(), b"keep")
            alias = root / "dangling"
            alias.symlink_to(root / "missing")
            with self.assertRaises(FileExistsError):
                controls.new_path(alias)
            self.assertTrue(alias.is_symlink())

    def test_cost_rejects_inadequate_sample_count(self):
        with self.assertRaisesRegex(RuntimeError, "seven"):
            controls.cost(Namespace(samples=6))

    def test_cost_rejects_nonpositive_iterations(self):
        with self.assertRaisesRegex(RuntimeError, "positive"):
            controls.cost(Namespace(samples=7, iterations=0))

    def test_vm_options_must_be_paired_before_building(self):
        with tempfile.TemporaryDirectory() as temporary:
            for plugin, sha in ((Path("vm.so"), None), (None, "00" * 32)):
                args = Namespace(corpus=Path(temporary) / "new", vm_plugin=plugin,
                                 vm_plugin_sha256=sha)
                with self.subTest(plugin=plugin), self.assertRaisesRegex(RuntimeError, "together"):
                    controls.prepare(args)
                self.assertFalse(args.corpus.exists())

    def test_virtualize_coverage_uses_native_api_report(self):
        controls.validate_coverage({"ok": True, "transformation_applied": True,
                                    "profile": "virtualize", "requested": ["rg_compute"],
                                    "functions": [{"name": "rg_compute", "requested": True,
                                                   "changed": True}]}, "virtualize")


class NativeCodeControlsLLVM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        llvm = os.environ.get("RELEASEGUARD_LLVM_BIN")
        plugin = os.environ.get("RELEASEGUARD_OBF_PLUGIN")
        if not llvm or not plugin:
            if os.environ.get("RELEASEGUARD_REQUIRE_NATIVE_OBFUSCATION") == "1":
                raise AssertionError("requires RELEASEGUARD_LLVM_BIN and RELEASEGUARD_OBF_PLUGIN")
            raise unittest.SkipTest("requires RELEASEGUARD_LLVM_BIN and RELEASEGUARD_OBF_PLUGIN")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.work = Path(cls.temporary.name)
        cls.llvm = Path(llvm)
        cls.plugin = Path(plugin)
        cls.corpus = cls.work / "corpus"
        cls.args = Namespace(corpus=cls.corpus, llvm_bin=cls.llvm, plugin=cls.plugin,
                             plugin_sha256=hashlib.sha256(cls.plugin.read_bytes()).hexdigest(), seed=SEED)
        cls.prepared = controls.prepare(cls.args)

    def test_public_contains_only_equivalent_native_executables(self):
        self.assertTrue(self.prepared["ok"])
        self.assertEqual({path.name for path in (self.corpus / "public").iterdir()}, set(controls.PROFILES))
        self.assertEqual(self.prepared["input_groups"]["low16_exhaustive"], 65536)
        self.assertEqual(self.prepared["input_groups"]["fresh_random"], 16384)
        for row in self.prepared["profiles"].values():
            self.assertTrue(row["functional"]["ok"])
            self.assertTrue(row["functional"]["length_matches"])
            self.assertEqual(row["functional"]["difference_count"], 0)
        ir = (self.corpus / "private/kernel.ll").read_text()
        self.assertNotIn("@llvm.compiler.used", ir)
        self.assertNotIn("@llvm.used", ir)

    def test_same_seed_reproduces_sources_inputs_and_binaries(self):
        args = Namespace(**vars(self.args))
        args.corpus = self.work / "repeated"
        repeated = controls.prepare(args)
        self.assertEqual(self.prepared["files"], repeated["files"])
        for profile in controls.PROFILES:
            self.assertEqual(self.prepared["profiles"][profile]["binary"],
                             repeated["profiles"][profile]["binary"])

    def test_known_source_positive_control_and_bad_candidates(self):
        sources = {
            "known-source": (self.corpus / "private/kernel.c").read_bytes(),
            "constant-zero": b"#include <stdint.h>\nuint32_t rg_compute(uint32_t x) {(void)x; return 0;}\n",
            "empty-output": b"#include <stdint.h>\n#include <stdlib.h>\nuint32_t rg_compute(uint32_t x) {(void)x; exit(0);}\n",
        }
        for name, source in sources.items():
            candidate = self.work / (name + ".c")
            candidate.write_bytes(source)
            with self.subTest(candidate=name):
                result = controls.score(Namespace(corpus=self.corpus, llvm_bin=self.llvm,
                                                   candidate=candidate, seed=None))
                self.assertEqual(result["ok"], name == "known-source")
                self.assertEqual(result["input_count"], self.prepared["input_count"] + 1_000_000)
                self.assertEqual(result["new_distinct_inputs"], 1_000_000)
                if name == "empty-output":
                    self.assertEqual(result["candidate"]["stdout_bytes"], 0)
                    self.assertEqual(result["candidate"]["difference_count"], result["input_count"])
                if name == "constant-zero":
                    self.assertGreater(result["candidate"]["difference_count"], 0)

    def test_changed_private_input_is_rejected(self):
        manifest = json.loads((self.corpus / "private/manifest.json").read_bytes())
        manifest["files"]["inputs.bin"]["sha256"] = "00" * 32
        with patch.object(controls.json, "loads", return_value=manifest):
            with self.assertRaisesRegex(RuntimeError, "artifact changed"):
                controls.load_corpus(self.corpus)


if __name__ == "__main__":
    unittest.main()
