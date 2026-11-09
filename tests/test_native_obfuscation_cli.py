"""Public native-obfuscate arguments, failure behavior and real LLVM builds."""

from contextlib import redirect_stderr, redirect_stdout
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from releaseguard.cli import main

try:
    from tests.test_native_obfuscation import SEED, SOURCE
except ImportError:
    from test_native_obfuscation import SEED, SOURCE


class NativeObfuscationCLI(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native obfuscation cli ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.source = self.work / "input module.ll"
        self.source.write_bytes(b"synthetic input for argument validation")
        self.plugin = self.work / "plugin.so"
        self.plugin.write_bytes(b"synthetic plugin for argument validation")
        self.digest = hashlib.sha256(self.plugin.read_bytes()).hexdigest()
        self.binary_dir = self.work / "toolchain bin"
        self.binary_dir.mkdir()
        self.output = self.work / "build output"
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")

    def arguments(self, *extra):
        return ["native-obfuscate", "--input", str(self.source), "--out", str(self.output),
                "--llvm-bin", str(self.binary_dir), "--plugin", str(self.plugin),
                "--plugin-sha256", self.digest, "--function", "target", *extra]

    def call(self, *extra, expected=2):
        process = subprocess.run([sys.executable, "-m", "releaseguard", *self.arguments(*extra)],
                                 cwd=self.work, env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, expected, process.stdout + process.stderr)
        self.assertNotIn("Traceback", process.stderr)
        self.assertEqual(process.stdout if expected == 2 else process.stderr, "")
        report = json.loads(process.stderr if expected == 2 else process.stdout)
        self.assertEqual(report["ok"], expected == 0)
        return report

    def test_arguments_are_forwarded_and_build_status_is_preserved(self):
        expected = {"ok": True, "transformation_applied": True,
                    "functional_evaluation": "not_performed", "recovery_evaluation": "not_performed"}
        for extra, seed, profile, functions in (
            ([], None, "flatten", ["target"]),
            (["--function", "_Z5otherj", "--seed", SEED, "--profile", "split-flatten-substitution"],
             SEED, "split-flatten-substitution", ["target", "_Z5otherj"]),
        ):
            with self.subTest(profile=profile):
                output, errors = io.StringIO(), io.StringIO()
                with patch("releaseguard.native_obfuscation.obfuscate_native_ir", return_value=expected) as build:
                    with redirect_stdout(output), redirect_stderr(errors):
                        code = main(self.arguments(*extra))
                self.assertEqual(code, 0)
                self.assertEqual(errors.getvalue(), "")
                self.assertEqual(json.loads(output.getvalue()), expected)
                build.assert_called_once_with(self.source, self.output, self.binary_dir, self.plugin,
                                               self.digest, functions, seed=seed, profile=profile)

    def test_invalid_seed_digest_and_duplicate_targets_return_json_errors(self):
        for arguments, message in (
            (["--seed", "0x" + SEED], "32-digit"),
            (["--seed", "z" * 32], "32-digit"),
            (["--plugin-sha256", "0" * 64], "does not match"),
            (["--plugin-sha256", "invalid"], "64-digit"),
            (["--function", "target"], "distinct"),
        ):
            with self.subTest(arguments=arguments):
                self.assertIn(message, self.call(*arguments)["error"])
                self.assertFalse(self.output.exists())

    def test_existing_output_missing_input_and_size_limit_preserve_files(self):
        self.output.mkdir()
        sentinel = self.output / "keep"
        sentinel.write_bytes(b"existing content")
        self.assertIn("new directory", self.call()["error"])
        self.assertEqual(sentinel.read_bytes(), b"existing content")
        sentinel.unlink()
        self.output.rmdir()
        self.source.unlink()
        self.assertIn("error", self.call())
        self.assertFalse(self.output.exists())
        with self.source.open("wb") as stream:
            stream.truncate((64 << 20) + 1)
        self.assertIn("byte budget", self.call()["error"])
        self.assertFalse(self.output.exists())

    def test_required_function_and_profile_choices_use_argparse_errors(self):
        arguments = self.arguments()
        for invalid in (arguments[:-2], arguments + ["--profile", "unknown"]):
            process = subprocess.run([sys.executable, "-m", "releaseguard", *invalid],
                                     cwd=self.work, env=self.env, capture_output=True, text=True, timeout=30)
            self.assertEqual(process.returncode, 2)
            self.assertEqual(process.stdout, "")
            self.assertIn("usage:", process.stderr)
            self.assertNotIn("Traceback", process.stderr)


class NativeObfuscationLLVMCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary_dir = os.environ.get("RELEASEGUARD_LLVM_BIN")
        plugin = os.environ.get("RELEASEGUARD_OBF_PLUGIN")
        if not binary_dir or not plugin:
            reason = "requires RELEASEGUARD_LLVM_BIN and RELEASEGUARD_OBF_PLUGIN for LLVM 18 CLI builds"
            if os.environ.get("RELEASEGUARD_REQUIRE_NATIVE_OBFUSCATION") == "1":
                raise AssertionError(reason)
            raise unittest.SkipTest(reason)
        cls.bin = Path(binary_dir).resolve()
        cls.plugin = Path(plugin).resolve()
        cls.digest = hashlib.sha256(cls.plugin.read_bytes()).hexdigest()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="real native cli ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        source = self.work / "owned fixture.c"
        source.write_text(SOURCE, encoding="ascii")
        self.bitcode = self.work / "input module.bc"
        subprocess.run([self.bin / "clang", "-O2", "-fPIC", "-fno-vectorize", "-fno-slp-vectorize",
                        "-fno-unroll-loops", "-emit-llvm", "-c", source, "-o", self.bitcode],
                       check=True, capture_output=True, timeout=30)
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        self.env.update(LLVM_OBF_SEED="injected", LLVM_OBF_DEBUG_SEED="y",
                        LLVM_OBF_SCALAROPTIMIZERLATE_PASSES="bogus,unknown")

    def call(self, directory, functions, *extra, expected=0):
        args = ["native-obfuscate", "--input", self.bitcode, "--out", self.work / directory,
                "--llvm-bin", self.bin, "--plugin", self.plugin, "--plugin-sha256", self.digest, "--seed", SEED]
        for name in functions:
            args += ["--function", name]
        process = subprocess.run([sys.executable, "-m", "releaseguard", *map(str, args), *extra],
                                 env=self.env, cwd=self.work, capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, expected, process.stdout + process.stderr)
        self.assertNotIn("Traceback", process.stderr)
        self.assertEqual(process.stderr if expected == 0 else process.stdout, "")
        report = json.loads(process.stdout if expected == 0 else process.stderr)
        self.assertEqual(report["ok"], expected == 0)
        return report

    def test_both_profiles_build_and_execute_with_repeatable_targets(self):
        for profile in ("flatten", "split-flatten-substitution"):
            with self.subTest(profile=profile):
                report = self.call(profile, ["rg_transform", "rg_secondary"], "--profile", profile)
                self.assertEqual(report["requested"], ["rg_transform", "rg_secondary"])
                self.assertEqual(report["functional_evaluation"], "not_performed")
                self.assertEqual(report["recovery_evaluation"], "not_performed")
                self.assertTrue(report["transformation_applied"])
                self.assertEqual(json.loads(Path(report["report"]).read_bytes()), report)
                self.assertEqual(hashlib.sha256(Path(report["object"]).read_bytes()).hexdigest(),
                                 report["object_sha256"])
                library_path = self.work / (profile + ".so")
                subprocess.run([self.bin / "clang", "-shared", report["object"], "-o", library_path],
                               check=True, capture_output=True, timeout=30)
                function = ctypes.CDLL(str(library_path)).rg_secondary
                function.argtypes, function.restype = [ctypes.c_uint], ctypes.c_uint
                self.assertEqual(function(101), 26 * 17 + 13)
                self.assertEqual(function(100), 100 * 17 + 13)
                self.assertFalse(list(self.work.glob(".native-obfuscation-*")))

    def test_missing_single_block_and_malformed_ir_fail_without_outputs(self):
        for target, message in (("absent", "missing"), ("rg_linear", "two basic blocks")):
            with self.subTest(target=target):
                self.assertIn(message, self.call(target, [target], expected=2)["error"])
                self.assertFalse((self.work / target).exists())
        self.bitcode.write_bytes(b"malformed LLVM input")
        self.assertIn("LLVM opt failed", self.call("malformed", ["rg_transform"], expected=2)["error"])
        self.assertFalse((self.work / "malformed").exists())
        self.assertFalse(list(self.work.glob(".native-obfuscation-*")))


if __name__ == "__main__":
    unittest.main()
