"""Experimental virtualize CLI configuration, coverage failures and execution."""

from contextlib import redirect_stderr, redirect_stdout
import ctypes
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
    from tests import test_native_obfuscation_cli as native_cli
    from tests import test_native_virtualization as native_vm
except ImportError:
    import test_native_obfuscation_cli as native_cli
    import test_native_virtualization as native_vm


class NativeVirtualizationCLI(unittest.TestCase):
    setUp = native_cli.NativeObfuscationCLI.setUp
    arguments = native_cli.NativeObfuscationCLI.arguments
    call = native_cli.NativeObfuscationCLI.call

    def test_virtualize_arguments_and_evaluation_status_are_forwarded(self):
        expected = {"ok": True, "profile": "virtualize", "seed": None, "experimental": True,
                    "transformation_applied": True, "functional_evaluation": "not_performed",
                    "recovery_evaluation": "not_performed"}
        output, errors = io.StringIO(), io.StringIO()
        with patch("releaseguard.native_obfuscation.obfuscate_native_ir", return_value=expected) as build:
            with redirect_stdout(output), redirect_stderr(errors):
                code = main(self.arguments("--profile", "virtualize", "--function", "second"))
        self.assertEqual(code, 0)
        self.assertEqual(errors.getvalue(), "")
        self.assertEqual(json.loads(output.getvalue()), expected)
        build.assert_called_once_with(self.source, self.output, self.binary_dir, self.plugin,
                                       self.digest, ["target", "second"], seed=None, profile="virtualize")

    def test_virtualize_seed_and_plugin_digest_errors_are_json(self):
        for arguments, message in ((["--seed", native_vm.SEED], "does not support a build seed"),
                                    (["--plugin-sha256", "0" * 64], "SHA-256")):
            with self.subTest(arguments=arguments):
                report = self.call("--profile", "virtualize", *arguments)
                self.assertIn(message, report["error"])
                self.assertFalse(self.output.exists())


class SealedVirtualizationCLI(unittest.TestCase):
    setUp = native_cli.NativeObfuscationCLI.setUp
    arguments = native_cli.NativeObfuscationCLI.arguments
    call = native_cli.NativeObfuscationCLI.call

    def options(self):
        keyfile = self.work / "private-key"
        if not keyfile.exists():
            keyfile.write_bytes(bytes(range(32)))
        return ["--profile", "sealed-virtualize", "--key-file", str(keyfile),
                "--product", "owned-test", "--release", "v11", "--module-id", "compute"]

    def test_code_key_is_loaded_and_only_raw_key_context_is_forwarded(self):
        expected = {"ok": True, "profile": "sealed-virtualize", "seed": None,
                    "transformation_applied": True, "recovery_evaluation": "not_performed"}
        output, errors = io.StringIO(), io.StringIO()
        with patch("releaseguard.native_obfuscation.obfuscate_native_ir", return_value=expected) as build:
            with redirect_stdout(output), redirect_stderr(errors):
                code = main(self.arguments(*self.options()))
        self.assertEqual(code, 0)
        self.assertEqual(errors.getvalue(), "")
        self.assertEqual(json.loads(output.getvalue()), expected)
        build.assert_called_once_with(self.source, self.output, self.binary_dir, self.plugin,
                                       self.digest, ["target"], seed=None, profile="sealed-virtualize",
                                       code_key=bytes(range(32)), product="owned-test", release="v11", module_id="compute")

    def test_missing_context_seed_wrong_key_length_and_links_return_json(self):
        options = self.options()
        for flag in ("--key-file", "--product", "--release", "--module-id"):
            partial = options.copy()
            index = partial.index(flag)
            del partial[index:index + 2]
            with self.subTest(flag=flag):
                self.assertIn("requires", self.call(*partial)["error"])
        self.assertIn("does not support a build seed", self.call(*options, "--seed", native_vm.SEED)["error"])
        keyfile = self.work / "private-key"
        keyfile.write_bytes(b"short")
        self.assertIn("key", self.call(*options)["error"].lower())
        keyfile.unlink()
        try:
            keyfile.symlink_to(self.plugin)
        except (OSError, NotImplementedError):
            return
        self.assertIn("key", self.call(*options)["error"].lower())
        self.assertFalse(self.output.exists())

    def test_other_profiles_reject_key_options_before_reading_key(self):
        output, errors = io.StringIO(), io.StringIO()
        with patch("releaseguard.cli.load_asset_key") as load:
            with redirect_stdout(output), redirect_stderr(errors):
                code = main(self.arguments("--key-file", str(self.work / "missing-private-key")))
        self.assertEqual(code, 2)
        self.assertIn("require the sealed-virtualize profile", json.loads(errors.getvalue())["error"])
        load.assert_not_called()


class NativeVirtualizationRealCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin, cls.plugin, cls.digest = native_vm.configured_vm_toolchain()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native vm cli ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.source = self.work / "source.c"
        self.bitcode = self.work / "input.bc"
        self.compile()
        self.environment = os.environ.copy()
        self.environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        config = self.work / "injected.toml"
        config.write_text('[vm_virtualize]\nenable = false\nprofile_path = "missing"\n')
        self.environment.update(AMICE_CONFIG_PATH=str(config), AMICE_VM_PROFILE_PATH="missing",
                                AMICE_VM_VIRTUALIZE="false", AMICE_PASS_ORDER="StringEncryption",
                                AMICE_VM_EMIT_MARKERS="true", AMICE_VM_DUMP_BYTECODE="true",
                                AMICE_VM_DUMP_LOWERING="true", LLVM_OBF_SEED="injected")

    def compile(self, source=native_vm.VM_SOURCE):
        self.source.write_text(source, encoding="ascii")
        subprocess.run([self.bin / "clang", "-O2", "-fPIC", "-fno-vectorize", "-fno-slp-vectorize",
                        "-fno-unroll-loops", "-emit-llvm", "-c", self.source, "-o", self.bitcode],
                       check=True, capture_output=True, timeout=30)

    def call(self, directory, names, *extra, expected=0):
        arguments = ["native-obfuscate", "--input", self.bitcode, "--out", self.work / directory,
                     "--llvm-bin", self.bin, "--plugin", self.plugin, "--plugin-sha256", self.digest,
                     "--profile", "virtualize"]
        for name in names:
            arguments.extend(("--function", name))
        process = subprocess.run([sys.executable, "-m", "releaseguard", *map(str, arguments), *extra],
                                 cwd=self.work, env=self.environment, capture_output=True, text=True, timeout=120)
        self.assertEqual(process.returncode, expected, process.stdout + process.stderr)
        self.assertEqual(process.stderr if expected == 0 else process.stdout, "")
        self.assertNotIn("Traceback", process.stderr)
        return json.loads(process.stdout if expected == 0 else process.stderr)

    def test_real_vm_builds_executes_and_cleans_inherited_configuration(self):
        report = self.call("vm", ["rg_transform", "rg_secondary"])
        self.assertEqual(report["requested"], ["rg_transform", "rg_secondary"])
        self.assertTrue(report["experimental"])
        self.assertIsNone(report["seed"])
        self.assertEqual(report["functional_evaluation"], "not_performed")
        self.assertEqual(report["recovery_evaluation"], "not_performed")
        self.assertFalse(report["vm_configuration"]["emit_markers"])
        self.assertEqual(json.loads(Path(report["report"]).read_bytes()), report)
        for function in report["functions"]:
            if function["requested"]:
                self.assertTrue(function["vm_coverage"]["wrapper_replaced"])
        library = self.work / "vm.so"
        subprocess.run([self.bin / "clang", "-shared", report["object"], "-o", library],
                       check=True, capture_output=True, timeout=30)
        function = ctypes.CDLL(str(library)).rg_secondary
        function.argtypes, function.restype = [ctypes.c_uint32], ctypes.c_uint32
        self.assertEqual(function(101), 26 * 17 + 13)
        self.assertEqual(function(100), 100 * 17 + 13)
        self.assertFalse(list(self.work.glob(".native-obfuscation-*")))

    def test_missing_target_used_skip_and_invalid_ir_return_json(self):
        self.assertIn("missing", self.call("missing", ["absent"], expected=2)["error"])
        self.compile(native_vm.VM_SOURCE.replace("noinline", "noinline, used"))
        original = self.bitcode.read_bytes()
        self.assertIn("verified VM", self.call("skipped", ["rg_transform"], expected=2)["error"])
        self.assertEqual(self.bitcode.read_bytes(), original)
        self.bitcode.write_bytes(b"malformed LLVM IR")
        self.assertIn("LLVM opt failed", self.call("invalid", ["rg_transform"], expected=2)["error"])
        for name in ("missing", "skipped", "invalid"):
            self.assertFalse((self.work / name).exists())
        self.assertFalse(list(self.work.glob(".native-obfuscation-*")))

    def test_sealed_vm_cli_executes_only_after_external_key_initialization(self):
        key = bytes.fromhex("8454fa99d05b633edfe92e6f4e551c41bf51655e77c562f745d36603f9c1d208")
        keyfile = self.work / "private-key"
        keyfile.write_bytes(key)
        report = self.call("sealed", ["rg_transform", "rg_secondary", "rg_linear"],
                           "--profile", "sealed-virtualize", "--key-file", str(keyfile),
                           "--product", "cli-test", "--release", "v11", "--module-id", "compute")
        directory = Path(report["object"]).parent
        self.assertEqual(report["profile"], "sealed-virtualize")
        self.assertEqual(report["vm_coverage_stage"], "before_sealing")
        self.assertEqual(len(report["sealed_files"]), 4)
        self.assertNotIn(key.hex(), json.dumps(report))
        self.assertNotIn(str(keyfile), json.dumps(report))
        driver = self.work / "driver.cpp"
        driver.write_text('''#include "releaseguard_native_code.hpp"
#include <openssl/crypto.h>
#include <iostream>
namespace selected_code = CODE_NAMESPACE;
extern "C" unsigned rg_secondary(unsigned);
int main() {
    releaseguard::native_asset_key key{};
    std::cin.read(reinterpret_cast<char *>(key.data()), key.size());
    if (std::cin.gcount() != static_cast<std::streamsize>(key.size())) return 3;
    bool ready = selected_code::initialize_native_code(key);
    OPENSSL_cleanse(key.data(), key.size());
    unsigned result = rg_secondary(101);
    selected_code::clear_native_code();
    std::cout << ready << " " << result << " " << rg_secondary(101) << "\\n";
    return 0;
}
'''.replace("CODE_NAMESPACE", report["code_seal"]["cpp_namespace"]), encoding="ascii")
        executable = self.work / "driver"
        subprocess.run(["g++", "-std=c++17", "-O2", "-I", str(directory), str(driver),
                        str(directory / "releaseguard_native_code.cpp"), report["object"], "-lcrypto",
                        "-o", str(executable)], capture_output=True, check=True, timeout=120)
        for candidate, expected in ((key, b"1 455 0\n"), (bytes(32), b"0 0 0\n")):
            result = subprocess.run([executable], input=candidate, capture_output=True, check=True, timeout=30)
            self.assertEqual(result.stdout, expected)
            self.assertEqual(result.stderr, b"")
        malformed = subprocess.run([executable], input=b"short", capture_output=True, timeout=30)
        self.assertEqual(malformed.returncode, 3)
        self.assertFalse(list(self.work.glob(".native-obfuscation-*")))


if __name__ == "__main__":
    unittest.main()
