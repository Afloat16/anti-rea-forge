"""Real LLVM baseline, VM and sealed VM execution across every allowed integer width."""

import ctypes
import itertools
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest

from releaseguard.native_obfuscation import obfuscate_native_ir

try:
    from tests import test_native_virtualization as native_vm
except ImportError:
    import test_native_virtualization as native_vm


WIDTHS = (1, 8, 16, 32, 64)
KEY = bytes.fromhex("ab59efcd2e199d94a082c946af14f6540cb35f361dbb033138e520cd6da28068")


def integer_ir():
    functions = []
    for width in WIDTHS:
        extension = "zeroext " if width < 32 else ""
        functions.append(f'''define {extension}i{width} @vm_integer_{width}(i{width} {extension}%x, i{width} {extension}%y) #0 {{
entry:
  %condition = icmp ugt i{width} %x, %y
  br i1 %condition, label %greater, label %otherwise
greater:
  %sum = add i{width} %x, %y
  %masked = and i{width} %sum, %x
  %first = xor i{width} %masked, %y
  ret i{width} %first
otherwise:
  %difference = sub i{width} %x, %y
  %merged = or i{width} %difference, %y
  %second = xor i{width} %merged, %x
  ret i{width} %second
}}
''')
    return ('source_filename = "vm-integer-matrix.ll"\n'
            'target triple = "x86_64-pc-linux-gnu"\n'
            + "\n".join(functions) + '\nattributes #0 = { noinline nounwind }\n')


def reference(width, x, y):
    """Unsigned comparison and modulo-2**width add/sub, with no LLVM overflow flags."""
    mask = (1 << width) - 1
    if x > y:
        return ((((x + y) & mask) & x) ^ y) & mask
    return ((((x - y) & mask) | y) ^ x) & mask


def input_pairs(width):
    if width in (1, 8):
        return itertools.product(range(1 << width), repeat=2)
    mask = (1 << width) - 1
    edges = [0, 1, mask >> 1, (mask >> 1) + 1, mask]
    generator = random.Random(20261112 + width)
    random_pairs = [(generator.getrandbits(width), generator.getrandbits(width)) for _ in range(1000)]
    return itertools.chain(itertools.product(edges, repeat=2), random_pairs)


class NativeVMIntegerExecution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The common helper makes missing tools an error when REQUIRE_NATIVE_VIRTUALIZATION=1.
        cls.bin, cls.plugin, cls.digest = native_vm.configured_vm_toolchain()
        cls.compiler = shutil.which("g++")
        if not cls.compiler:
            raise AssertionError("configured integer VM tests require C++17 and OpenSSL development files")
        temporary = tempfile.TemporaryDirectory(prefix="native-vm-integers-")
        cls.addClassCleanup(temporary.cleanup)
        cls.work = Path(temporary.name).resolve()
        cls.input = cls.work / "integers.ll"
        cls.input.write_text(integer_ir(), encoding="ascii")
        verified = cls.work / "baseline.ll"
        cls.run_tool(cls.bin / "opt", "-S", "-passes=verify", "-verify-each", cls.input, "-o", verified)
        baseline_object = cls.work / "baseline.o"
        cls.run_tool(cls.bin / "llc", "-O=2", "-relocation-model=pic", "-filetype=obj", verified,
                     "-o", baseline_object)
        cls.baseline = cls.link("baseline", baseline_object)
        cls.libraries = {}
        cls.reports = {}
        names = [f"vm_integer_{width}" for width in WIDTHS]
        for profile in ("virtualize", "sealed-virtualize"):
            options = {}
            if profile == "sealed-virtualize":
                options = {"code_key": KEY, "product": "integer-matrix", "release": "v11",
                           "module_id": "five-widths"}
            report = obfuscate_native_ir(cls.input, cls.work / profile, cls.bin, cls.plugin,
                                         cls.digest, names, profile=profile, **options)
            cls.reports[profile] = report
            cls.libraries[profile] = cls.link(profile, Path(report["object"]), report)

    @classmethod
    def run_tool(cls, tool, *args):
        result = subprocess.run([str(tool), *map(str, args)], capture_output=True, timeout=120)
        if result.returncode:
            raise AssertionError(result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))

    @classmethod
    def link(cls, name, artifact, report=None):
        # Export uint64_t bridges so ctypes never relies on unspecified upper return-register bits.
        scalar_types = {1: "bool", 8: "std::uint8_t", 16: "std::uint16_t",
                        32: "std::uint32_t", 64: "std::uint64_t"}
        source = ["#include <cstdint>"]
        for width, ctype in scalar_types.items():
            source.append(f'extern "C" {ctype} vm_integer_{width}({ctype}, {ctype});')
            source.append(f'''extern "C" std::uint64_t check_integer_{width}(std::uint64_t x, std::uint64_t y) {{
    return static_cast<std::uint64_t>(vm_integer_{width}(static_cast<{ctype}>(x), static_cast<{ctype}>(y)));
}}''')
        extra = []
        if report and report["profile"] == "sealed-virtualize":
            directory = artifact.parent
            source.extend(('#include "releaseguard_native_code.hpp"', "#include <cstring>",
                           "#include <openssl/crypto.h>",
                           "namespace selected_code = " + report["code_seal"]["cpp_namespace"] + ";",
                           '''extern "C" bool unlock_integer_code(const unsigned char *raw) {
    releaseguard::native_asset_key key{};
    std::memcpy(key.data(), raw, key.size());
    const bool result = selected_code::initialize_native_code(key);
    OPENSSL_cleanse(key.data(), key.size());
    return result;
}
extern "C" void clear_integer_code() { selected_code::clear_native_code(); }'''))
            extra = ["-I", directory, directory / "releaseguard_native_code.cpp", "-lcrypto"]
        shim = cls.work / (name + ".cpp")
        shim.write_text("\n".join(source) + "\n", encoding="ascii")
        library_path = cls.work / (name + ".so")
        cls.run_tool(cls.compiler, "-std=c++17", "-O2", "-fPIC", "-shared", shim, artifact,
                     *extra, "-o", library_path)
        library = ctypes.CDLL(str(library_path))
        for width in WIDTHS:
            function = getattr(library, f"check_integer_{width}")
            function.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
            function.restype = ctypes.c_uint64
        if report and report["profile"] == "sealed-virtualize":
            library.unlock_integer_code.argtypes = [ctypes.c_char_p]
            library.unlock_integer_code.restype = ctypes.c_bool
            library.clear_integer_code.argtypes = []
            library.clear_integer_code.restype = None
        return library

    def check_matrix(self, profile):
        library = self.libraries[profile]
        for width in WIDTHS:
            baseline = getattr(self.baseline, f"check_integer_{width}")
            protected = getattr(library, f"check_integer_{width}")
            count = 0
            for x, y in input_pairs(width):
                expected = reference(width, x, y)
                observed_baseline = baseline(x, y)
                observed_protected = protected(x, y)
                if observed_baseline != expected or observed_protected != expected:
                    self.fail(f"{profile} i{width} x={x} y={y}: reference={expected}, "
                              f"LLVM baseline={observed_baseline}, protected={observed_protected}")
                count += 1
            self.assertEqual(count, {1: 4, 8: 65536}.get(width, 1025))
            observation = next(item for item in self.reports[profile]["functions"]
                               if item["name"] == f"vm_integer_{width}")
            self.assertTrue(observation["requested"])
            self.assertTrue(observation["vm_coverage"]["wrapper_replaced"])

    def check_locked(self, library):
        for width in WIDTHS:
            function = getattr(library, f"check_integer_{width}")
            mask = (1 << width) - 1
            for x, y in ((0, 1), (1, 0), (mask, 1), (mask, mask)):
                self.assertEqual(function(x, y), 0, f"locked i{width} x={x} y={y}")

    def test_virtualize_all_integer_widths_match_baseline_and_reference(self):
        self.check_matrix("virtualize")

    def test_sealed_virtualize_all_widths_and_locked_lifecycle(self):
        library = self.libraries["sealed-virtualize"]
        self.check_locked(library)
        self.assertFalse(library.unlock_integer_code(bytes(32)))
        self.check_locked(library)
        self.assertTrue(library.unlock_integer_code(KEY))
        self.check_matrix("sealed-virtualize")
        self.assertFalse(library.unlock_integer_code(bytes(32)))
        self.check_locked(library)
        self.assertTrue(library.unlock_integer_code(KEY))
        library.clear_integer_code()
        self.check_locked(library)


if __name__ == "__main__":
    unittest.main()
