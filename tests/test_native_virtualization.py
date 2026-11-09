"""Experimental Amice coverage checks and real LLVM 18 execution regressions."""

from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import platform
import random
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from releaseguard.core import GuardError
from releaseguard.native_obfuscation import (
    _VM_ENVIRONMENT, _body_shape, _functions, _preflight, _vm_coverage, _vm_globals, obfuscate_native_ir,
)

try:
    from tests import test_native_obfuscation as native_tests
except ImportError:
    import test_native_obfuscation as native_tests


BEFORE, SEED, SOURCE = native_tests.BEFORE, native_tests.SEED, native_tests.SOURCE
VM_SOURCE = '''
__attribute__((noinline)) unsigned rg_transform(unsigned x, unsigned y) {
    if ((x ^ y) & 1u) x = (x >> 3) ^ (y * 2654435761u);
    else x = (x << 5) + y;
    return x ^ ((y >> 1) | (y << 31));
}
''' + SOURCE[SOURCE.index("__attribute__((noinline)) unsigned int rg_secondary"):]


def vm_fixture():
    wrapper = '''define i32 @target(i32 %x) {
entry:
  %returns = alloca [3 x i64], align 8
  %parts = alloca [2 x i64], align 8
  %args = alloca [16 x i64], align 8
  %first = getelementptr [2 x i64], ptr %parts, i64 0, i64 0
  %second = getelementptr [2 x i64], ptr %parts, i64 0, i64 1
  store i64 1, ptr %first, align 8
  store i64 2, ptr %second, align 8
  %token = load i64, ptr %first, align 8
  %arg = zext i32 %x to i64
'''
    for index in range(16):
        value = "%arg" if index == 0 else "0"
        wrapper += f"  %slot{index} = getelementptr [16 x i64], ptr %args, i64 0, i64 {index}\n"
        wrapper += f"  store i64 {value}, ptr %slot{index}, align 8\n"
    wrapper += '''  %value = call i64 @runtime(i64 %token, ptr %returns, ptr %args)
  %result = trunc i64 %value to i32
  ret i32 %result
}
define private i64 @runtime(i64 %token, ptr %returns, ptr %args) {
entry:
  %offset = alloca i64, align 8
'''
    for index in range(8):
        wrapper += f"  %d{index} = getelementptr inbounds [8 x i64], ptr @descriptor, i64 0, i64 %token\n"
        wrapper += f"  %v{index} = load i64, ptr %d{index}, align 8\n"
    wrapper += '''  %code = getelementptr i8, ptr @bytecode, i64 %v0
  %opcode = call i64 @reader(ptr %code, i64 %v1, i64 %v2, ptr %offset)
  switch i64 %opcode, label %exit [
    i64 1, label %again
  ]
again:
  br label %exit
exit:
  ret i64 %opcode
}
define private i64 @reader(ptr %code, i64 %length, i64 %key, ptr %offset) {
entry:
  %byte = load i8, ptr %code, align 1
  %value = zext i8 %byte to i64
  ret i64 %value
}
'''
    return ('target triple = "x86_64-pc-linux-gnu"\n'
            '@bytecode = private constant [3 x i8] c"A\\\\\\FF"\n'
            '@descriptor = private constant [8 x i64] [i64 0, i64 3, i64 0, i64 0, i64 0, i64 0, i64 0, i64 0]\n'
            + wrapper)


class NativeVirtualizationFiles(unittest.TestCase):
    setUp = native_tests.NativeObfuscationFiles.setUp
    fake_run = native_tests.NativeObfuscationFiles.fake_run
    assert_clean = native_tests.NativeObfuscationFiles.assert_clean
    test_crlf_tool_output_keeps_coverage_and_original_byte_hashes = (
        native_tests.NativeObfuscationFiles.test_crlf_tool_output_keeps_coverage_and_original_byte_hashes)

    def build(self, **overrides):
        self.after = getattr(self, "vm_after", vm_fixture())
        return native_tests.NativeObfuscationFiles.build(self, profile="virtualize", seed=None, **overrides)

    def test_wrapper_runtime_bytecode_and_configuration_are_reported(self):
        with patch.dict(os.environ, {"AMICE_CONFIG_PATH": "untrusted.toml", "AMICE_VM_PROFILE_PATH": "untrusted",
                                     "AMICE_VM_EMIT_MARKERS": "true", "AMICE_PASS_ORDER": "StringEncryption",
                                     "LLVM_OBF_SEED": "injected", "LLVM_OBF_DEBUG_SEED": "y"}):
            report = self.build()
        self.assertTrue(report["experimental"])
        self.assertTrue(report["transformation_applied"])
        self.assertIsNone(report["seed"])
        self.assertEqual(report["pass_pipeline"], "default<O2>")
        self.assertEqual(report["functional_evaluation"], "not_performed")
        self.assertEqual(report["recovery_evaluation"], "not_performed")
        self.assertEqual(report["vm_configuration"]["runtime_scope"], "module")
        self.assertFalse(report["vm_configuration"]["emit_markers"])
        coverage = report["functions"][0]["vm_coverage"]
        self.assertTrue(coverage["wrapper_replaced"])
        self.assertTrue(coverage["original_body_absent"])
        self.assertEqual(coverage["runtime_function"], "runtime")
        self.assertEqual(coverage["bytecode_globals"], [{"name": "bytecode", "bytes": 3,
                                                       "sha256": hashlib.sha256(b"A\\\xff").hexdigest()}])
        for _, _, _, environment in self.calls:
            controlled = {key: value for key, value in environment.items() if key.startswith(("AMICE_", "LLVM_OBF_"))}
            self.assertEqual(controlled, _VM_ENVIRONMENT)

    def test_seed_is_rejected_before_tools(self):
        with self.assertRaisesRegex(GuardError, "does not support a build seed"):
            native_tests.NativeObfuscationFiles.build(self, profile="virtualize", seed=SEED)
        self.assertEqual(self.calls, [])
        self.assert_clean()

    def test_vm_coverage_rejects_noop_missing_dependencies_and_constant_return(self):
        source = vm_fixture()
        cases = [BEFORE, BEFORE.replace("ret i32 5", "ret i32 6"),
                 source.replace("ptr @bytecode,", "ptr @unrelated,"),
                 source.replace("ptr @descriptor,", "ptr @unrelated,"),
                 source.replace("switch i64 %opcode,", "switch i64 %v0,"),
                 source.replace("load i8, ptr %code", "load i8, ptr @other"),
                 source.replace("ret i32 %result", "ret i32 5"),
                 source.replace("private constant [3 x i8]", "private constant [4 x i8]"),
                 source.replace("define private i64 @runtime", "define i64 @runtime")]
        for index, after in enumerate(cases):
            with self.subTest(index=index):
                self.vm_after = after
                with self.assertRaisesRegex(GuardError, "verified VM"):
                    self.build()
                self.assert_clean()

    def test_original_body_retained_under_another_symbol_is_rejected(self):
        copy = BEFORE[BEFORE.index("define "):].replace("@target(", "@retained(")
        copy = copy.replace("%x", "%renamed").replace("entry:", "renamed_entry:")
        self.vm_after = vm_fixture() + copy
        with self.assertRaisesRegex(GuardError, "verified VM"):
            self.build()
        self.assert_clean()
        original = _functions(BEFORE)["target"]["body"]
        self.assertEqual(_body_shape(original), _body_shape(_functions(copy)["retained"]["body"]))

    def test_preexisting_copy_of_original_body_is_rejected(self):
        retained = BEFORE[BEFORE.index("define "):].split("\nattributes #", 1)[0]
        retained = retained.replace("@target(", "@existing_copy(").replace(" #0 {", " {") + "\n"
        self.before = BEFORE + retained
        self.vm_after = vm_fixture() + retained
        with self.assertRaisesRegex(GuardError, "verified VM"):
            self.build()
        self.assert_clean()

    def test_vm_requires_x86_64_and_rejects_all_annotation_configuration(self):
        for triple in ("i386-pc-linux-gnu", "x86_64-pc-linux-gnux32"):
            self.before = BEFORE.replace("x86_64-pc-linux-gnu", triple)
            with self.subTest(triple=triple), self.assertRaisesRegex(GuardError, "x86-64 Linux"):
                self.build()
            self.assert_clean()
        self.before = '@llvm.global.annotations = appending global [0 x ptr] zeroinitializer\n' + BEFORE
        with self.assertRaisesRegex(GuardError, "annotations"):
            self.build()
        self.assert_clean()

    def test_bad_plugin_missing_target_and_failed_publication_leave_no_output(self):
        for option, message in (({"plugin_sha256": "0" * 64}, "SHA-256"),
                                ({"functions": ["missing"]}, "missing")):
            with self.subTest(option=option), self.assertRaisesRegex(GuardError, message):
                self.build(**option)
            self.assert_clean()
        native_tests.NativeObfuscationFiles.test_publication_failure_rolls_back_only_new_outputs(self)

    def test_preexisting_runtime_and_bytecode_do_not_count_as_new_coverage(self):
        self.before = BEFORE + vm_fixture().replace("@target(", "@existing_wrapper(")
        with self.assertRaisesRegex(GuardError, "verified VM"):
            self.build()
        self.assert_clean()

    def test_unverified_types_memory_operations_and_abi_are_rejected(self):
        function = _functions(BEFORE)["target"]
        for body in ("%a = fadd float 1.0, 2.0", "%a = add <2 x i32> zeroinitializer, zeroinitializer",
                     "%a = load atomic i32, ptr %x monotonic, align 4", "%a = load volatile i32, ptr %x",
                     "%a = atomicrmw add ptr %x, i32 1 seq_cst", "fence seq_cst", "%a = add i128 1, 2",
                     "%a = freeze i32 undef", "%a = call i32 %callback(i32 1)"):
            with self.subTest(body=body), self.assertRaises(GuardError):
                _preflight("target", {**function, "body": body}, "virtualize")
        for header in ("define { i32, i32 } @target(i32 %x) {", "define i32 @target(...) {",
                       "define i32 @target(ptr byval(i32) %x) {", "define fastcc i32 @target(i32 %x) {",
                       "define i32 @target(i32 %x) prefix i64 1 {",
                       "define i32 @target(i32 %x) prologue i64 1 {"):
            with self.subTest(header=header), self.assertRaises(GuardError):
                _preflight("target", {**function, "header": header}, "virtualize")
        with self.assertRaises(GuardError):
            _preflight("other", {**function, "attributes": "optnone"}, "virtualize", required=False)


def configured_vm_toolchain():
    binary_dir = os.environ.get("RELEASEGUARD_LLVM_BIN")
    plugin = os.environ.get("RELEASEGUARD_AMICE_PLUGIN")
    reason = None
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        reason = "Amice VM execution tests require Linux x86-64"
    if not binary_dir or not plugin:
        reason = "requires RELEASEGUARD_LLVM_BIN and RELEASEGUARD_AMICE_PLUGIN for VM builds"
    if reason:
        if os.environ.get("RELEASEGUARD_REQUIRE_NATIVE_VIRTUALIZATION") == "1":
            raise AssertionError(reason)
        raise unittest.SkipTest(reason)
    tools, plugin_path = Path(binary_dir).resolve(), Path(plugin).resolve()
    if not all((tools / name).is_file() for name in ("clang", "opt", "llc")):
        raise AssertionError("configured LLVM toolchain is incomplete")
    return tools, plugin_path, hashlib.sha256(plugin_path.read_bytes()).hexdigest()


class NativeVirtualizationLLVM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin, cls.plugin, cls.digest = configured_vm_toolchain()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native-vm-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.source = self.work / "fixture.c"
        self.bitcode = self.work / "input.bc"

    def compile(self, source=VM_SOURCE, *extra):
        self.source.write_text(source, encoding="ascii")
        self.run_tool("clang", "-O2", "-fPIC", "-fno-vectorize", "-fno-slp-vectorize", "-fno-unroll-loops",
                      "-emit-llvm", "-c", str(self.source), "-o", str(self.bitcode), *extra)

    def run_tool(self, tool, *args):
        return subprocess.run([str(self.bin / tool), *args], capture_output=True, check=True, timeout=120)

    def build(self, names, directory="protected", **extra):
        return obfuscate_native_ir(self.bitcode, self.work / directory, self.bin, self.plugin, self.digest,
                                   names, profile="virtualize", **extra)

    def load(self, object_path, name):
        library = self.work / (name + ".so")
        self.run_tool("clang", "-shared", str(object_path), "-o", str(library))
        return ctypes.CDLL(str(library))

    def baseline(self):
        artifact = self.work / "baseline.o"
        self.run_tool("llc", "-O=2", "-relocation-model=pic", "-filetype=obj", str(self.bitcode), "-o", str(artifact))
        return self.load(artifact, "baseline")

    def test_multi_function_vm_executes_edges_and_random_inputs(self):
        self.compile()
        original = self.baseline()
        report = self.build(["rg_transform", "rg_secondary", "rg_linear"])
        protected = self.load(report["object"], "vm")
        for library in (original, protected):
            for name, count in (("rg_transform", 2), ("rg_secondary", 1), ("rg_linear", 1)):
                function = getattr(library, name)
                function.argtypes, function.restype = [ctypes.c_uint32] * count, ctypes.c_uint32
        edges = [0, 1, 2, 3, 31, 32, 99, 100, 101, 0x7fffffff, 0x80000000, 0xffffffff]
        generator = random.Random(20261110)
        pairs = [(x, y) for x in edges for y in edges]
        pairs += [(generator.getrandbits(32), generator.getrandbits(32)) for _ in range(1000)]
        for x, y in pairs:
            self.assertEqual(protected.rg_transform(x, y), original.rg_transform(x, y))
            self.assertEqual(protected.rg_secondary(x), original.rg_secondary(x))
            self.assertEqual(protected.rg_linear(x), original.rg_linear(x))
        for observation in report["functions"]:
            self.assertTrue(observation["changed"])
            self.assertTrue(observation["vm_coverage"]["original_body_absent"])
            self.assertEqual(observation["blocks_after"], 1)
        self.assertIsNone(report["seed"])
        self.assertFalse(list(self.work.glob(".native-obfuscation-*")))

    def test_scalar_pointer_side_effects_direct_calls_and_u64_execution(self):
        self.compile('''
__attribute__((noinline)) unsigned long long rg_wide(unsigned long long x, unsigned long long y) {
    return (x >> 37) ^ (x * 0xd6e8feb86659fd93ULL) ^ (y << 19);
}
__attribute__((noinline)) unsigned *rg_memory(unsigned *value, unsigned x) {
    *value = (*value << 7) ^ x;
    return value;
}
__attribute__((noinline)) void rg_store(unsigned *value, unsigned x) { *value = x + 1; }
__attribute__((noinline)) unsigned long long rg_call(unsigned long long x) { return rg_wide(x, x + 7); }
''')
        original = self.baseline()
        report = self.build(["rg_wide", "rg_memory", "rg_store", "rg_call"])
        protected = self.load(report["object"], "vm")
        for library in (original, protected):
            library.rg_wide.argtypes, library.rg_wide.restype = [ctypes.c_uint64] * 2, ctypes.c_uint64
            library.rg_call.argtypes, library.rg_call.restype = [ctypes.c_uint64], ctypes.c_uint64
            library.rg_memory.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32]
            library.rg_memory.restype = ctypes.c_void_p
            library.rg_store.argtypes = library.rg_memory.argtypes
            library.rg_store.restype = None
        generator = random.Random(20261111)
        values = [0, 1, (1 << 31) - 1, 1 << 31, (1 << 32) - 1, 1 << 32, 1 << 63, (1 << 64) - 1]
        values += [generator.getrandbits(64) for _ in range(128)]
        for x in values:
            y = generator.getrandbits(64)
            self.assertEqual(protected.rg_wide(x, y), original.rg_wide(x, y))
            self.assertEqual(protected.rg_call(x), original.rg_call(x))
            expected, actual = ctypes.c_uint32(x), ctypes.c_uint32(x)
            original.rg_memory(ctypes.byref(expected), y)
            self.assertEqual(protected.rg_memory(ctypes.byref(actual), y), ctypes.addressof(actual))
            self.assertEqual(actual.value, expected.value)
            original.rg_store(ctypes.byref(expected), x)
            protected.rg_store(ctypes.byref(actual), x)
            self.assertEqual(actual.value, expected.value)

    def test_used_attribute_skip_is_rejected_without_mutating_input(self):
        self.compile(VM_SOURCE.replace("noinline", "noinline, used"))
        original = self.bitcode.read_bytes()
        with self.assertRaisesRegex(GuardError, "verified VM"):
            self.build(["rg_transform", "rg_secondary"])
        self.assertEqual(self.bitcode.read_bytes(), original)
        self.assertFalse((self.work / "protected").exists())
        self.assertFalse(list(self.work.glob(".native-obfuscation-*")))

    def test_vm_rejects_prefix_and_executable_prologue_that_upstream_discards(self):
        for attribute in ("prologue", "prefix"):
            source = ('target triple = "x86_64-pc-linux-gnu"\n'
                      f'define i32 @target(i32 %x) {attribute} i64 -8029759185035868285 {{\n'
                      'entry:\n  %r = add i32 %x, 1234567\n  ret i32 %r\n}\n')
            self.bitcode.write_text(source)
            if attribute == "prologue":
                original = self.baseline()
                original.target.argtypes, original.target.restype = [ctypes.c_uint32], ctypes.c_uint32
                self.assertEqual(original.target(0), 1234568)
            for profile in ("virtualize", "sealed-virtualize"):
                context = ({"code_key": bytes(range(32)), "product": "regression", "release": "1",
                            "module_id": "prologue"} if profile == "sealed-virtualize" else {})
                with self.subTest(attribute=attribute, profile=profile):
                    with self.assertRaisesRegex(GuardError, "prefix or prologue"):
                        obfuscate_native_ir(self.bitcode, self.work / "protected", self.bin,
                                            self.plugin, self.digest, ["target"], profile=profile, **context)
                    self.assertFalse((self.work / "protected").exists())

    def test_upstream_loop_phi_skip_is_rejected(self):
        self.compile(SOURCE)
        with self.assertRaisesRegex(GuardError, "verified VM.*rg_transform"):
            self.build(["rg_transform"])
        self.assertFalse((self.work / "protected").exists())

    def test_missing_target_wrong_digest_and_nonplugin_fail_closed(self):
        self.compile()
        with self.assertRaisesRegex(GuardError, "missing"):
            self.build(["absent"])
        original_plugin, original_digest = self.plugin, self.digest
        self.digest = "0" * 64
        with self.assertRaisesRegex(GuardError, "SHA-256"):
            self.build(["rg_transform"])
        self.plugin = self.work / "not-a-plugin.so"
        self.plugin.write_bytes(b"not a loadable LLVM plugin")
        self.digest = hashlib.sha256(self.plugin.read_bytes()).hexdigest()
        with self.assertRaisesRegex(GuardError, "LLVM opt failed"):
            self.build(["rg_transform"])
        self.plugin, self.digest = original_plugin, original_digest
        self.assertFalse((self.work / "protected").exists())

    def test_float_vector_atomic_annotations_and_x86_32_are_rejected(self):
        cases = [
            ("float f(float x) { return x * 1.5f; }", (), "scalar integer"),
            ("typedef unsigned v4 __attribute__((vector_size(16))); v4 f(v4 x) { return x+x; }", (), "scalar integer"),
            ("unsigned f(unsigned *p) { return __atomic_fetch_add(p, 1, __ATOMIC_SEQ_CST); }", (), "scalar integer"),
            ('__attribute__((annotate("vm_profile=untrusted"))) unsigned f(unsigned x) { return x+1; }', (), "annotations"),
            ("unsigned f(unsigned x) { return x+1; }", ("-m32",), "x86-64 Linux"),
        ]
        for source, flags, message in cases:
            with self.subTest(source=source):
                self.compile(source, *flags)
                with self.assertRaisesRegex(GuardError, message):
                    self.build(["f"])
                self.assertFalse((self.work / "protected").exists())


if __name__ == "__main__":
    unittest.main()
