"""Coverage checks plus real, opt-in LLVM 18 builds of project-owned C functions."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from releaseguard.core import GuardError, write_new
from releaseguard.native_obfuscation import _dispatchers, _functions, _preflight, obfuscate_native_ir


SEED = "00112233445566778899aabbccddeeff"
BEFORE = '''source_filename = "fixture.c"
target triple = "x86_64-pc-linux-gnu"
define i32 @target(i32 %x) #0 {
entry:
  %condition = icmp eq i32 %x, 0
  br i1 %condition, label %yes, label %no
yes:
  ret i32 5
no:
  ret i32 %x
}
attributes #0 = { noinline nounwind }
'''
AFTER = '''source_filename = "fixture.c"
target triple = "x86_64-pc-linux-gnu"
define i32 @target(i32 %x) #0 {
entry:
  %switchVar = alloca i32, align 4
  store i32 1, ptr %switchVar, align 4
  br label %loopEntry
loopEntry:
  %switchVar1 = load i32, ptr %switchVar, align 4
  switch i32 %switchVar1, label %switchDefault [
    i32 1, label %yes
    i32 2, label %no
  ]
yes:
  ret i32 5
no:
  ret i32 %x
switchDefault:
  br label %loopEnd
loopEnd:
  br label %loopEntry
}
attributes #0 = { noinline nounwind }
'''


def object_fixture():
    data = bytearray(64)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", data, 16, 1, 62)
    return bytes(data)


class NativeObfuscationFiles(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.source = self.work / "source.ll"
        self.source.write_text(BEFORE, encoding="utf-8")
        self.plugin = self.work / "plugin.so"
        self.plugin.write_bytes(b"synthetic plugin for mocked tools")
        self.digest = hashlib.sha256(self.plugin.read_bytes()).hexdigest()
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.output = self.work / "result"
        self.calls = []
        self.before = BEFORE
        self.after = AFTER

    def fake_run(self, tool, args, work, environment):
        self.calls.append((tool, args, work, environment))
        if args == ["--version"]:
            return b"Ubuntu LLVM version 18.1.3\n"
        if args[-1] == "before.ll":
            (work / "before.ll").write_text(self.before, encoding="utf-8")
        elif args[-1] == "after.ll":
            self.assertEqual((work / "plugin.so").read_bytes(), self.plugin.read_bytes())
            (work / "after.ll").write_text(self.after, encoding="utf-8")
        elif args[-1] == "protected.o":
            (work / "protected.o").write_bytes(object_fixture())
        else:
            self.fail(f"Unexpected mocked tool arguments {args}")
        return b""

    def build(self, **overrides):
        options = dict(input_path=self.source, output_dir=self.output, toolchain_dir=self.bin,
                       plugin_path=self.plugin, plugin_sha256=self.digest,
                       functions=["target"], seed=SEED)
        options.update(overrides)
        with patch("releaseguard.native_obfuscation._run", side_effect=self.fake_run):
            return obfuscate_native_ir(**options)

    def assert_clean(self):
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.work.glob(".native-obfuscation-*")))

    def test_exact_outputs_and_coverage_report(self):
        result = self.build()
        self.assertEqual({p.name for p in self.output.iterdir()}, {"protected.o", "report.json"})
        self.assertEqual(json.loads((self.output / "report.json").read_bytes()), result)
        self.assertTrue(result["transformation_applied"])
        self.assertEqual(result["functional_evaluation"], "not_performed")
        self.assertEqual(result["recovery_evaluation"], "not_performed")
        self.assertEqual(result["requested"], ["target"])
        self.assertEqual(result["changed"], ["target"])
        self.assertTrue(result["functions"][0]["dispatcher"])
        self.assertEqual(result["functions"][0]["new_dispatchers"], 1)
        self.assertEqual(self.source.read_text(), BEFORE)
        self.assertFalse(list(self.work.glob(".native-obfuscation-*")))
        for _, args, _, _ in self.calls:
            if args != ["--version"] and args[-1].endswith(".ll"):
                self.assertIn("-verify-each", args)

    def test_environment_injection_is_removed_and_seed_is_recorded(self):
        with patch.dict(os.environ, {"LLVM_OBF_DEBUG_SEED": "y", "LLVM_OBF_SCALAROPTIMIZERLATE_PASSES": "bogus",
                                     "LLVM_OBF_SEED": "untrusted"}):
            result = self.build(seed=SEED.upper())
        self.assertEqual(result["seed"], SEED)
        for _, _, _, environment in self.calls:
            self.assertEqual({key: value for key, value in environment.items() if key.startswith("LLVM_OBF_")},
                             {"LLVM_OBF_SEED": SEED})
        shutil.rmtree(self.output)
        self.assertRegex(self.build(seed=None)["seed"], r"^[0-9a-f]{32}$")

    def test_invalid_arguments_fail_before_tools(self):
        cases = [{"seed": item} for item in ("", "0x" + SEED, "z" * 32, 7)]
        cases += [{"plugin_sha256": item} for item in ("", "z" * 64, None)]
        cases += [{"functions": item} for item in ([], "target", ["target", "target"], ["bad name"], [None])]
        cases += [{"profile": item} for item in ("bogus", None, [])]
        for options in cases:
            with self.subTest(options=options):
                with self.assertRaises(GuardError):
                    self.build(**options)
                self.assert_clean()
        self.assertEqual(self.calls, [])

    def test_bad_plugin_hash_and_missing_target_are_rejected(self):
        with self.assertRaisesRegex(GuardError, "SHA-256"):
            self.build(plugin_sha256="0" * 64)
        self.assert_clean()
        with self.assertRaisesRegex(GuardError, "missing"):
            self.build(functions=["absent"])
        self.assert_clean()

    def test_noop_and_changed_without_dispatcher_are_rejected(self):
        for after in (BEFORE, BEFORE.replace("ret i32 5", "ret i32 6")):
            self.after = after
            with self.assertRaisesRegex(GuardError, "skipped or has no verified dispatcher"):
                self.build()
            self.assert_clean()

    def test_preexisting_dispatcher_is_not_evidence_of_a_new_transform(self):
        self.before = AFTER
        self.after = AFTER.replace("ret i32 5", "ret i32 6")
        with self.assertRaisesRegex(GuardError, "skipped or has no verified dispatcher"):
            self.build()
        self.assert_clean()

    def test_wrong_target_missing_definition_and_invalid_object_are_rejected(self):
        self.before = BEFORE.replace("x86_64-pc-linux-gnu", "aarch64-pc-linux-gnu")
        with self.assertRaisesRegex(GuardError, "target triple"):
            self.build()
        self.assert_clean()
        self.before = BEFORE
        self.after = AFTER.replace("@target(", "@other(")
        with self.assertRaisesRegex(GuardError, "definition set"):
            self.build()
        self.assert_clean()
        self.after = AFTER
        with patch(__name__ + ".object_fixture", return_value=b"invalid object"):
            with self.assertRaisesRegex(GuardError, "relocatable ELF"):
                self.build()
        self.assert_clean()

    def test_input_changes_and_destination_race_preserve_existing_files(self):
        original = self.fake_run
        for victim in (self.source, self.plugin):
            def mutate(tool, args, work, environment):
                result = original(tool, args, work, environment)
                if args[-1] == "protected.o":
                    victim.write_bytes(victim.read_bytes() + b"\n")
                return result
            self.fake_run = mutate
            with self.subTest(victim=victim), self.assertRaisesRegex(GuardError, "changed after scanning"):
                self.build()
            self.assert_clean()
            self.source.write_text(BEFORE)
            self.plugin.write_bytes(b"synthetic plugin for mocked tools")
        def race(tool, args, work, environment):
            result = original(tool, args, work, environment)
            if args[-1] == "protected.o":
                self.output.mkdir()
                (self.output / "keep").write_bytes(b"other owner")
            return result
        self.fake_run = race
        with self.assertRaises(FileExistsError):
            self.build()
        self.assertEqual((self.output / "keep").read_bytes(), b"other owner")

    def test_existing_output_and_input_or_plugin_links_are_preserved(self):
        self.output.mkdir()
        sentinel = self.output / "keep"
        sentinel.write_bytes(b"existing")
        with self.assertRaises(GuardError):
            self.build()
        self.assertEqual(sentinel.read_bytes(), b"existing")
        shutil.rmtree(self.output)
        alias = self.work / "alias"
        try:
            alias.symlink_to(self.source)
        except (OSError, NotImplementedError):
            return
        for option in ("input_path", "plugin_path"):
            with self.assertRaises(GuardError):
                self.build(**{option: alias})
            self.assertTrue(alias.is_symlink())
            self.assert_clean()
        self.output.symlink_to(self.work / "missing")
        with self.assertRaises(GuardError):
            self.build()
        self.assertTrue(self.output.is_symlink())

    def test_publication_failure_rolls_back_only_new_outputs(self):
        def fail(path, data, **kwargs):
            if path.name == "report.json":
                raise OSError("injected report failure")
            return write_new(path, data, **kwargs)
        with patch("releaseguard.native_obfuscation.write_new", side_effect=fail):
            with self.assertRaisesRegex(OSError, "injected"):
                self.build()
        self.assert_clean()

    def test_version_mismatch_and_codegen_failure_leave_no_outputs(self):
        original = self.fake_run
        for failure in ("old", "mismatch", "codegen"):
            def fail(tool, args, work, environment):
                if failure == "old" and args == ["--version"]:
                    return b"LLVM version 17.0.6\n"
                if failure == "mismatch" and tool.name == "llc":
                    return b"LLVM version 18.1.8\n"
                if failure == "codegen" and args[-1] == "protected.o":
                    raise GuardError("injected codegen failure")
                return original(tool, args, work, environment)
            self.fake_run = fail
            with self.subTest(failure=failure), self.assertRaises(GuardError):
                self.build()
            self.assert_clean()
        self.fake_run = original


class NativeIRChecks(unittest.TestCase):
    def test_canonical_function_parser_and_dispatcher(self):
        before, after = _functions(BEFORE), _functions(AFTER)
        self.assertEqual(before["target"]["blocks"], 3)
        self.assertFalse(_dispatchers(before["target"]))
        self.assertTrue(_dispatchers(after["target"]))
        _preflight("target", before["target"], "flatten")
        _preflight("target", before["target"], "split-flatten-substitution")

    def test_unsupported_control_flow_attributes_and_substitution_types(self):
        for opcode in ("invoke", "callbr", "indirectbr", "landingpad", "catchpad", "cleanuppad",
                       "catchswitch", "catchret", "cleanupret", "resume"):
            function = {**_functions(BEFORE)["target"], "body": f"  %value = {opcode} i32 0\n"}
            with self.subTest(opcode=opcode), self.assertRaises(GuardError):
                _preflight("target", function, "flatten")
        for attribute in ("optnone", "naked", "returns_twice", "convergent"):
            function = {**_functions(BEFORE)["target"], "attributes": attribute}
            with self.subTest(attribute=attribute), self.assertRaises(GuardError):
                _preflight("target", function, "flatten")
        for value in ("<4 x i32>", "i128", "i7", "double", "poison", "undef", "freeze", "atomicrmw"):
            function = {**_functions(BEFORE)["target"], "body": "  %value = add " + value + " 1, 2\n"}
            with self.subTest(value=value), self.assertRaises(GuardError):
                _preflight("target", function, "split-flatten-substitution")

    def test_single_block_requires_split_profile(self):
        function = {**_functions(BEFORE)["target"], "blocks": 1}
        with self.assertRaisesRegex(GuardError, "two basic blocks"):
            _preflight("target", function, "flatten")
        _preflight("target", function, "split-flatten-substitution")

    def test_local_names_and_comments_do_not_impersonate_type_tokens(self):
        text = BEFORE.replace("%x", "%poison").replace("%condition", "%i128")
        text = text.replace("ret i32 5", "ret i32 5 ; poison i128 <4 x i32>")
        function = _functions(text)["target"]
        _preflight("target", function, "split-flatten-substitution")

    def test_unrequested_functions_are_checked_for_transforms_too(self):
        function = {**_functions(BEFORE)["target"], "body": "  %value = add i128 1, 2\n"}
        with self.assertRaises(GuardError):
            _preflight("other", function, "split-flatten-substitution", required=False)
        _preflight("other", {**function, "attributes": "optnone"},
                   "split-flatten-substitution", required=False)


SOURCE = r'''
__attribute__((noinline)) unsigned int rg_transform(unsigned int x, unsigned int y) {
    for (unsigned int i = 0; i < 7; ++i) {
        if ((x ^ y) & 1u) x = (x >> 3) ^ (y * 2654435761u + i);
        else x = (x << 5) + y + i;
        y = (y >> 1) | (y << 31);
    }
    return x ^ y;
}
__attribute__((noinline)) unsigned int rg_secondary(unsigned int x) {
    while (x > 100) x = (x >> 2) + (x & 3u);
    return x * 17u + 13u;
}
unsigned int rg_linear(unsigned int x) { return x + 1u; }
'''


class NativeObfuscationLLVM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary_dir = os.environ.get("RELEASEGUARD_LLVM_BIN")
        plugin = os.environ.get("RELEASEGUARD_OBF_PLUGIN")
        if not binary_dir or not plugin:
            reason = "requires RELEASEGUARD_LLVM_BIN and RELEASEGUARD_OBF_PLUGIN for LLVM 18 builds"
            if os.environ.get("RELEASEGUARD_REQUIRE_NATIVE_OBFUSCATION") == "1":
                raise AssertionError(reason)
            raise unittest.SkipTest(reason)
        cls.bin = Path(binary_dir).resolve()
        cls.plugin = Path(plugin).resolve()
        cls.digest = hashlib.sha256(cls.plugin.read_bytes()).hexdigest()
        if not all((cls.bin / name).is_file() for name in ("clang", "opt", "llc")):
            raise AssertionError("configured LLVM toolchain is incomplete")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.source = self.work / "fixture.c"
        self.source.write_text(SOURCE, encoding="ascii")
        self.bitcode = self.work / "input.bc"
        self.run_tool("clang", "-O2", "-fPIC", "-fno-vectorize", "-fno-slp-vectorize", "-fno-unroll-loops",
                      "-emit-llvm", "-c", str(self.source), "-o", str(self.bitcode))

    def run_tool(self, tool, *args):
        return subprocess.run([str(self.bin / tool), *args], capture_output=True, check=True, timeout=120)

    def build(self, name="protected", **kwargs):
        return obfuscate_native_ir(self.bitcode, self.work / name, self.bin, self.plugin, self.digest,
                                   functions=["rg_transform"], seed=SEED, **kwargs)

    def load(self, object_path, name):
        library = self.work / (name + ".so")
        self.run_tool("clang", "-shared", str(object_path), "-o", str(library))
        loaded = ctypes.CDLL(str(library))
        for symbol, arguments in (("rg_transform", 2), ("rg_secondary", 1), ("rg_linear", 1)):
            function = getattr(loaded, symbol)
            function.argtypes = [ctypes.c_uint] * arguments
            function.restype = ctypes.c_uint
        return loaded

    def test_both_profiles_execute_identically_on_edges_and_random_inputs(self):
        baseline_object = self.work / "baseline.o"
        self.run_tool("llc", "-O=2", "-relocation-model=pic", "-filetype=obj", str(self.bitcode),
                      "-o", str(baseline_object))
        baseline = self.load(baseline_object, "baseline")
        generator = random.Random(20261109)
        values = [0, 1, 2, 3, 31, 32, 99, 100, 101, 0x7fffffff, 0x80000000, 0xffffffff]
        pairs = [(x, y) for x in values for y in values]
        pairs += [(generator.getrandbits(32), generator.getrandbits(32)) for _ in range(1000)]
        for profile in ("flatten", "split-flatten-substitution"):
            with self.subTest(profile=profile):
                result = self.build(profile, profile=profile)
                transformed = self.load(Path(result["object"]), profile)
                for x, y in pairs:
                    self.assertEqual(transformed.rg_transform(x, y), baseline.rg_transform(x, y))
                    self.assertEqual(transformed.rg_secondary(x), baseline.rg_secondary(x))
                    self.assertEqual(transformed.rg_linear(x), baseline.rg_linear(x))
                self.assertIn("rg_secondary", result["changed"])
                self.assertEqual(result["requested"], ["rg_transform"])
                self.assertNotEqual(Path(result["object"]).read_bytes(), baseline_object.read_bytes())

    def test_same_seed_reproduces_ir_and_object_and_another_seed_changes_object(self):
        first, second = self.build("first"), self.build("second")
        for field in ("before_ir_sha256", "after_ir_sha256", "object_sha256"):
            self.assertEqual(first[field], second[field])
        third = obfuscate_native_ir(self.bitcode, self.work / "third", self.bin, self.plugin, self.digest,
                                    ["rg_transform"], seed="ff" * 16)
        self.assertNotEqual(first["object_sha256"], third["object_sha256"])

    def test_optnone_and_single_block_targets_fail_without_outputs(self):
        with self.assertRaisesRegex(GuardError, "two basic blocks"):
            obfuscate_native_ir(self.bitcode, self.work / "linear", self.bin, self.plugin, self.digest,
                                ["rg_linear"], seed=SEED)
        self.assertFalse((self.work / "linear").exists())
        self.source.write_text(SOURCE.replace("noinline", "noinline,optnone"), encoding="ascii")
        self.run_tool("clang", "-O2", "-emit-llvm", "-c", str(self.source), "-o", str(self.bitcode))
        with self.assertRaisesRegex(GuardError, "attribute"):
            self.build()
        self.assertFalse((self.work / "protected").exists())

    def test_real_cpp_exception_handling_is_explicitly_rejected(self):
        source = self.work / "exception.cpp"
        source.write_text('extern int external_call(int);\nextern "C" int guarded(int x) {\n'
                          'try { return external_call(x); } catch (...) { return 7; }\n}\n', encoding="ascii")
        self.run_tool("clang", "-x", "c++", "-std=c++17", "-O1", "-emit-llvm", "-c", str(source),
                      "-o", str(self.bitcode))
        with self.assertRaisesRegex(GuardError, "unsupported control flow"):
            obfuscate_native_ir(self.bitcode, self.work / "exception", self.bin, self.plugin, self.digest,
                                ["guarded"], seed=SEED)
        self.assertFalse((self.work / "exception").exists())

    def test_text_ir_and_x86_32_codegen(self):
        self.run_tool("clang", "-m32", "-O2", "-fno-unroll-loops", "-fPIC", "-S", "-emit-llvm",
                      str(self.source), "-o", str(self.bitcode))
        result = self.build("x86")
        artifact = Path(result["object"]).read_bytes()
        self.assertEqual(artifact[4], 1)
        self.assertEqual(struct.unpack_from("<HH", artifact, 16), (1, 3))
        self.assertTrue(result["target_triple"].startswith("i386-"))

    def test_real_asm_goto_is_explicitly_rejected(self):
        self.source.write_text('int jump(int x) { asm goto("" : : : : next); return x;\n'
                               'next: return x + 1; }\n', encoding="ascii")
        self.run_tool("clang", "-O1", "-emit-llvm", "-c", str(self.source), "-o", str(self.bitcode))
        with self.assertRaisesRegex(GuardError, "callbr"):
            obfuscate_native_ir(self.bitcode, self.work / "jump", self.bin, self.plugin, self.digest,
                                ["jump"], seed=SEED)
        self.assertFalse((self.work / "jump").exists())

    def test_entry_return_with_unreachable_blocks_rejects_upstream_miscompile(self):
        self.bitcode.write_text('target triple = "x86_64-pc-linux-gnu"\ndefine i32 @target() {\n'
                                'entry:\n  ret i32 9\ndead:\n  ret i32 27\n}\n', encoding="ascii")
        for profile in ("flatten", "split-flatten-substitution"):
            with self.subTest(profile=profile), self.assertRaisesRegex(GuardError, "multi-block entry"):
                obfuscate_native_ir(self.bitcode, self.work / profile, self.bin, self.plugin, self.digest,
                                    ["target"], seed=SEED, profile=profile)
            self.assertFalse((self.work / profile).exists())

    def test_supported_integer_widths_execute_modular_arithmetic(self):
        functions = []
        for width in (1, 8, 16, 32, 64):
            extension = "zeroext " if width < 32 else ""
            functions.append(f'''define {extension}i{width} @width_{width}(i{width} {extension}%x, i{width} {extension}%y) {{
entry:
  %condition = icmp ugt i{width} %x, %y
  br i1 %condition, label %left, label %right
left:
  %sum = add i{width} %x, %y
  %masked = and i{width} %sum, %x
  %a = xor i{width} %masked, %y
  ret i{width} %a
right:
  %difference = sub i{width} %x, %y
  %merged = or i{width} %difference, %y
  %b = xor i{width} %merged, %x
  ret i{width} %b
}}
''')
        self.bitcode.write_text('source_filename = "widths.ll"\ntarget triple = "x86_64-pc-linux-gnu"\n'
                                + "\n".join(functions), encoding="ascii")
        scalar_types = {1: ctypes.c_bool, 8: ctypes.c_uint8, 16: ctypes.c_uint16,
                        32: ctypes.c_uint32, 64: ctypes.c_uint64}
        for profile in ("flatten", "split-flatten-substitution"):
            result = obfuscate_native_ir(self.bitcode, self.work / profile, self.bin, self.plugin, self.digest,
                                        ["width_" + str(width) for width in scalar_types], seed=SEED, profile=profile)
            library_path = self.work / (profile + "-widths.so")
            self.run_tool("clang", "-shared", result["object"], "-o", str(library_path))
            library = ctypes.CDLL(str(library_path))
            for width, scalar_type in scalar_types.items():
                with self.subTest(profile=profile, width=width):
                    function = getattr(library, "width_" + str(width))
                    function.argtypes, function.restype = [scalar_type, scalar_type], scalar_type
                    mask = (1 << width) - 1
                    values = [0, 1, mask >> 1, (mask >> 1) + 1, mask]
                    generator = random.Random(width)
                    pairs = [(x, y) for x in values for y in values]
                    pairs += [(generator.getrandbits(width), generator.getrandbits(width)) for _ in range(1000)]
                    for x, y in pairs:
                        expected = ((((x + y) & mask) & x) ^ y if x > y
                                    else (((x - y) & mask) | y) ^ x)
                        self.assertEqual(function(x, y), expected)


if __name__ == "__main__":
    unittest.main()
