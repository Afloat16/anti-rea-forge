"""Sealed VM build integration, publication and externally keyed execution."""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
import types
import unittest
from unittest.mock import Mock, patch

from releaseguard.core import GuardError, write_new
from releaseguard.native_obfuscation import obfuscate_native_ir

try:
    from tests import test_native_obfuscation as native_tests
    from tests import test_native_virtualization as native_vm
except ImportError:
    import test_native_obfuscation as native_tests
    import test_native_virtualization as native_vm


KEY = bytes.fromhex("7947e7d5c0cbf75c1c834ca20f305b860b42ac389ab6d9067a71dbe2d3ee6f16")
CONTEXT = {"product": "owned-test", "release": "v11", "module_id": "compute"}


class SealedNativeObfuscationFiles(unittest.TestCase):
    setUp = native_tests.NativeObfuscationFiles.setUp
    assert_clean = native_tests.NativeObfuscationFiles.assert_clean

    def fake_run(self, tool, args, work, environment):
        if args[-1] == "sealed-verified.ll":
            self.calls.append((tool, args, work, environment))
            (work / "sealed-verified.ll").write_bytes((work / "sealed.ll").read_bytes())
            return b""
        return native_tests.NativeObfuscationFiles.fake_run(self, tool, args, work, environment)

    def build(self, **overrides):
        self.after = native_vm.vm_fixture()
        options = {"input_path": self.source, "output_dir": self.output, "toolchain_dir": self.bin,
                   "plugin_path": self.plugin, "plugin_sha256": self.digest, "functions": ["target"],
                   "profile": "sealed-virtualize", "code_key": KEY, **CONTEXT}
        options.update(overrides)
        with patch("releaseguard.native_obfuscation._run", side_effect=self.fake_run):
            return obfuscate_native_ir(**options)

    def sealer(self, files=None, error=None):
        helper = Mock(side_effect=error) if error else Mock(return_value=(native_vm.vm_fixture(),
            files if files is not None else {"code.hpp": b"encrypted test data", "code.cpp": b"loader"},
            {"format": "synthetic-code-seal-test", "payload_sha256": "0" * 64}))
        module = types.ModuleType("releaseguard.native_code_seal")
        module.seal_virtualized_ir = helper
        return helper, patch.dict(sys.modules, {"releaseguard.native_code_seal": module})

    def test_sealed_artifacts_are_verified_published_and_reported_without_key(self):
        helper, fake_module = self.sealer()
        with fake_module:
            report = self.build()
        helper.assert_called_once()
        args = helper.call_args.args
        self.assertEqual(args[0], native_vm.vm_fixture())
        self.assertTrue(args[1][0]["vm_coverage"]["wrapper_replaced"])
        self.assertEqual(args[2:], (KEY, CONTEXT["product"], CONTEXT["release"], CONTEXT["module_id"]))
        self.assertEqual({path.name for path in self.output.iterdir()}, {"protected.o", "report.json", "code.hpp", "code.cpp"})
        self.assertEqual(report["vm_coverage_stage"], "before_sealing")
        self.assertEqual(report["sealed_ir_sha256"], hashlib.sha256(native_vm.vm_fixture().encode()).hexdigest())
        self.assertEqual(report["sealed_files"]["code.cpp"]["sha256"], hashlib.sha256(b"loader").hexdigest())
        self.assertEqual(report["functional_evaluation"], "not_performed")
        self.assertEqual(report["recovery_evaluation"], "not_performed")
        self.assertIsNone(report["seed"])
        self.assertNotIn(KEY.hex(), json.dumps(report))
        for _, args, _, _ in self.calls:
            self.assertNotIn(KEY.hex(), " ".join(args))
        self.assertIn("sealed-verified.ll", self.calls[-1][1])
        self.assertFalse(list(self.work.glob(".native-obfuscation-*")))

    def test_key_context_profile_mismatch_and_seed_fail_before_tools(self):
        cases = [{field: None} for field in ("code_key", "product", "release", "module_id")]
        cases += [{"code_key": b"short"}, {"code_key": bytearray(KEY)}, {"product": " spaced"},
                  {"release": ""}, {"module_id": "line\nbreak"}, {"seed": native_tests.SEED}, {"profile": "virtualize"}]
        for options in cases:
            with self.subTest(options=options), self.assertRaises(GuardError):
                self.build(**options)
            self.assert_clean()
        self.assertEqual(self.calls, [])

    def test_dependency_and_pointer_inputs_are_rejected(self):
        for body in ("  %a = call i32 @external(i32 %x)\n", "  %a = load i32, ptr @table\n"):
            self.before = native_tests.BEFORE.replace("  %condition = icmp eq i32 %x, 0", body)
            with self.subTest(body=body), self.assertRaisesRegex(GuardError, "self-contained"):
                self.build()
            self.assert_clean()

    def test_original_global_storage_is_rejected_before_sealing(self):
        for declaration in ('@exposed = constant i32 12345\n',
                            '@"exposed value" = constant [3 x i8] c"abc"\n'):
            self.before = declaration + native_tests.BEFORE
            helper, fake_module = self.sealer()
            with self.subTest(declaration=declaration), fake_module:
                with self.assertRaisesRegex(GuardError, "original global storage"):
                    self.build()
                helper.assert_not_called()
                self.assert_clean()

    def test_module_assembly_is_rejected_before_sealing(self):
        self.before = 'module asm ".ascii \\22unsealed-constant\\22"\n' + native_tests.BEFORE
        helper, fake_module = self.sealer()
        with fake_module, self.assertRaisesRegex(GuardError, "module-level assembly"):
            self.build()
        helper.assert_not_called()
        self.assert_clean()

    def test_linker_metadata_is_rejected_before_sealing(self):
        for name in ("llvm.linker.options", "llvm.dependent-libraries"):
            self.before = native_tests.BEFORE + f'\n!{name} = !{{!99}}\n!99 = !{{!"unsealed-value"}}\n'
            helper, fake_module = self.sealer()
            with self.subTest(name=name), fake_module:
                with self.assertRaisesRegex(GuardError, "embedded linker dependencies"):
                    self.build()
                helper.assert_not_called()
                self.assert_clean()

    def test_helper_failure_unsafe_names_and_publication_failure_roll_back(self):
        helper, fake_module = self.sealer(error=GuardError("injected sealing failure"))
        with fake_module, self.assertRaisesRegex(GuardError, "sealing failure"):
            self.build()
        self.assert_clean()
        for filename in ("../escaped", "/absolute", "folder/header", "protected.o", "report.json"):
            _, fake_module = self.sealer({filename: b"synthetic"})
            with self.subTest(filename=filename), fake_module, self.assertRaisesRegex(GuardError, "artifact"):
                self.build()
            self.assert_clean()
        _, fake_module = self.sealer()
        def fail(path, data, **kwargs):
            if path.name == "code.cpp":
                raise OSError("injected artifact publication failure")
            return write_new(path, data, **kwargs)
        with fake_module, patch("releaseguard.native_obfuscation.write_new", side_effect=fail):
            with self.assertRaisesRegex(OSError, "publication failure"):
                self.build()
        self.assert_clean()

    def test_skipped_target_never_reaches_sealing(self):
        original = self.fake_run
        def skipped(tool, args, work, environment):
            if args[-1] == "after.ll":
                self.after = native_tests.BEFORE
            return original(tool, args, work, environment)
        self.fake_run = skipped
        helper, fake_module = self.sealer()
        with fake_module, self.assertRaisesRegex(GuardError, "verified VM"):
            self.build()
        helper.assert_not_called()
        self.assert_clean()


class SealedNativeObfuscationLLVM(unittest.TestCase):
    setUp = native_vm.NativeVirtualizationLLVM.setUp
    compile = native_vm.NativeVirtualizationLLVM.compile
    run_tool = native_vm.NativeVirtualizationLLVM.run_tool
    baseline = native_vm.NativeVirtualizationLLVM.baseline
    load = native_vm.NativeVirtualizationLLVM.load

    @classmethod
    def setUpClass(cls):
        cls.bin, cls.plugin, cls.digest = native_vm.configured_vm_toolchain()
        compiler = shutil.which("g++")
        if not compiler:
            raise AssertionError("configured sealed VM tests require a C++17 compiler and OpenSSL")
        cls.compiler = compiler

    def build(self, names, directory="sealed", **overrides):
        options = {"code_key": KEY, **CONTEXT}
        options.update(overrides)
        return obfuscate_native_ir(self.bitcode, self.work / directory, self.bin, self.plugin, self.digest,
                                   names, profile="sealed-virtualize", **options)

    def load_sealed(self, report):
        directory = Path(report["object"]).parent
        shim = self.work / "test_api.cpp"
        shim.write_text('''#include "releaseguard_native_code.hpp"
#include <openssl/crypto.h>
#include <cstring>
namespace selected_code = CODE_NAMESPACE;
extern "C" bool test_unlock(const unsigned char *raw) {
    releaseguard::native_asset_key key{};
    std::memcpy(key.data(), raw, key.size());
    bool result = selected_code::initialize_native_code(key);
    OPENSSL_cleanse(key.data(), key.size());
    return result;
}
extern "C" void test_clear() { selected_code::clear_native_code(); }
'''.replace("CODE_NAMESPACE", report["code_seal"]["cpp_namespace"]), encoding="ascii")
        library = self.work / "sealed.so"
        subprocess.run([self.compiler, "-std=c++17", "-O2", "-fPIC", "-shared", "-I", str(directory),
                        str(shim), str(directory / "releaseguard_native_code.cpp"), report["object"],
                        "-lcrypto", "-o", str(library)], capture_output=True, check=True, timeout=120)
        loaded = ctypes.CDLL(str(library))
        loaded.test_unlock.argtypes, loaded.test_unlock.restype = [ctypes.c_char_p], ctypes.c_bool
        loaded.test_clear.argtypes, loaded.test_clear.restype = [], None
        return loaded

    def test_decrypted_multiple_functions_match_baseline_and_failure_clears_state(self):
        self.compile()
        original = self.baseline()
        report = self.build(["rg_transform", "rg_secondary", "rg_linear"])
        sealed = self.load_sealed(report)
        for library in (original, sealed):
            for name, count in (("rg_transform", 2), ("rg_secondary", 1), ("rg_linear", 1)):
                function = getattr(library, name)
                function.argtypes, function.restype = [ctypes.c_uint32] * count, ctypes.c_uint32
        self.assertEqual(sealed.rg_linear(5), 0)
        self.assertFalse(sealed.test_unlock(bytes(32)))
        self.assertEqual(sealed.rg_linear(5), 0)
        self.assertTrue(sealed.test_unlock(KEY))
        generator = random.Random(20261112)
        edges = [0, 1, 31, 32, 100, 101, 0x7fffffff, 0x80000000, 0xffffffff]
        pairs = [(x, y) for x in edges for y in edges]
        pairs += [(generator.getrandbits(32), generator.getrandbits(32)) for _ in range(512)]
        for x, y in pairs:
            self.assertEqual(sealed.rg_transform(x, y), original.rg_transform(x, y))
            self.assertEqual(sealed.rg_secondary(x), original.rg_secondary(x))
            self.assertEqual(sealed.rg_linear(x), original.rg_linear(x))
        self.assertFalse(sealed.test_unlock(bytes(32)))
        self.assertEqual(sealed.rg_transform(1, 2), 0)
        self.assertTrue(sealed.test_unlock(KEY))
        sealed.test_clear()
        self.assertEqual(sealed.rg_secondary(101), 0)
        self.assertFalse(list(self.work.glob(".native-obfuscation-*")))
        for file in Path(report["object"]).parent.iterdir():
            self.assertNotIn(KEY, file.read_bytes())
            self.assertNotIn(KEY.hex().encode(), file.read_bytes())
        self.assertEqual(len(report["sealed_files"]), 4)
        self.assertEqual(report["recovery_evaluation"], "not_performed")

    def test_used_skip_and_pointer_dependency_fail_before_publication(self):
        for source, name, message in (
            (native_vm.VM_SOURCE.replace("noinline", "noinline,used"), "rg_transform", "original global storage"),
            ("unsigned f(unsigned *p) { return *p; }", "f", "self-contained"),
            ("extern unsigned other(unsigned); unsigned f(unsigned x) { return other(x); }", "f", "self-contained"),
            ("const unsigned exposed = 12345; unsigned f(unsigned x) { return x + exposed; }",
             "f", "original global storage"),
            ('__asm__(".pushsection .rodata\\n.ascii \\\"unsealed-constant\\\"\\n.popsection"); '
             'unsigned f(unsigned x) { return x * 173u; }', "f", "module-level assembly"),
        ):
            with self.subTest(name=name, message=message):
                self.compile(source)
                with self.assertRaisesRegex(GuardError, message):
                    self.build([name])
                self.assertFalse((self.work / "sealed").exists())

    def test_linker_dependencies_are_rejected_by_real_llvm_build(self):
        for name, values in (("llvm.linker.options", '!"-l", !"PRIVATE_LINK_OPTION_2619"'),
                             ("llvm.dependent-libraries", '!"PRIVATE_LIBRARY_4851"')):
            self.compile("unsigned f(unsigned x) { return x * 173u; }")
            ir = self.run_tool("opt", "-S", "-passes=verify", str(self.bitcode), "-o", "-").stdout.decode()
            self.bitcode.write_text(ir + f'\n!{name} = !{{!999}}\n!999 = !{{{values}}}\n')
            with self.subTest(name=name), self.assertRaisesRegex(GuardError, "embedded linker dependencies"):
                self.build(["f"])
            self.assertFalse((self.work / "sealed").exists())

    def test_source_file_and_ident_strings_are_absent_from_sealed_object(self):
        self.compile("unsigned f(unsigned x) { return x * 173u; }")
        ir = self.run_tool("opt", "-S", "-passes=verify", str(self.bitcode), "-o", "-").stdout.decode()
        filename = "PRIVATE_SOURCE_FILE_41a9"
        ident = "PRIVATE_FUNCTION_LITERAL_91d5"
        ir = re.sub(r'^source_filename = .*$', f'source_filename = "{filename}"', ir, flags=re.MULTILINE)
        ir = re.sub(r'^!llvm.ident = .*$', '!llvm.ident = !{!999}', ir, flags=re.MULTILINE)
        self.bitcode.write_text(ir + f'\n!999 = !{{!"{ident}"}}\n')
        original = self.work / "original.o"
        self.run_tool("llc", "-O=2", "-relocation-model=pic", "-filetype=obj", str(self.bitcode), "-o", str(original))
        for marker in (filename, ident):
            self.assertIn(marker.encode(), original.read_bytes())
        report = self.build(["f"])
        for marker in (filename, ident):
            self.assertNotIn(marker.encode(), Path(report["object"]).read_bytes())


if __name__ == "__main__":
    unittest.main()
