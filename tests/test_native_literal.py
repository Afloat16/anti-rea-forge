"""Compile and inspect our own C++17 masking fixture; no third-party binaries.

The assertions establish literal-byte masking and correct runtime behavior for
these fixtures/compiler settings. They do not measure reverse-engineering
resistance, and an analyst can recover the strings by executing the decoder.
"""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INCLUDE = ROOT / "src" / "releaseguard" / "data" / "include"
FIXTURE = ROOT / "tests" / "fixtures" / "native_literal.cpp"
SEED = 0x1AF38C4E60B975D2


def find_compiler() -> list[str] | None:
    if os.environ.get("CXX"):
        command = shlex.split(os.environ["CXX"], posix=os.name != "nt")
        if command and shutil.which(command[0]):
            return command
    for name in ("g++", "clang++", "cl"):
        if path := shutil.which(name):
            return [path]
    return None


class NativeLiteralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = find_compiler()
        if not cls.compiler:
            raise unittest.SkipTest("C++17 compiler (g++, clang++ or cl) unavailable")
        cls.msvc = Path(cls.compiler[0]).stem.lower() in {"cl", "clang-cl"}
        cls.temporary = tempfile.TemporaryDirectory(prefix="rg-native-")
        cls.directory = Path(cls.temporary.name)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    def compile(
        self,
        name: str,
        optimization: str = "O2",
        *,
        seed: int | None = SEED,
        source: str | None = None,
        lto: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        build = self.directory / name
        build.mkdir(exist_ok=True)
        if seed is not None:
            (build / "releaseguard_build.hpp").write_text(
                f"#pragma once\n#define RELEASEGUARD_BUILD_SEED 0x{seed:016x}ULL\n",
                encoding="utf-8",
            )
        source_path = FIXTURE
        if source is not None:
            source_path = build / "sample.cpp"
            source_path.write_text(source, encoding="utf-8")
        executable = build / ("sample.exe" if os.name == "nt" else "sample")
        if self.msvc:
            flags = ["/Od"] if optimization == "O0" else ["/O2"]
            if lto:
                flags.append("/GL")
            command = self.compiler + [
                "/nologo", "/std:c++17", "/EHsc", "/utf-8", "/W4",
                f"/I{INCLUDE}", f"/I{build}", *flags, str(source_path),
                f"/Fe:{executable}", f"/Fo:{build / 'sample.obj'}",
            ]
            if lto:
                command.extend(["/link", "/LTCG"])
        else:
            command = self.compiler + [
                "-std=c++17", "-Wall", "-Wextra", "-pedantic", "-pthread",
                f"-{optimization}", "-I", str(INCLUDE), "-I", str(build),
                str(source_path), "-o", str(executable),
            ]
            if lto:
                command.append("-flto")
        process = subprocess.run(
            command, capture_output=True, text=True, timeout=120, cwd=build,
        )
        return process, executable

    def assert_compiled(self, process: subprocess.CompletedProcess[str]):
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)

    @staticmethod
    def units(value: str, encoding: str) -> list[int]:
        raw = value.encode(encoding)
        width = 2 if encoding.startswith("utf-16") else 4 if encoding.startswith("utf-32") else 1
        return [int.from_bytes(raw[i:i + width], "little") for i in range(0, len(raw), width)]

    def assert_fixture(self, executable: Path) -> str:
        result = subprocess.run(
            [str(executable)], capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = result.stdout.splitlines()
        wide_width = int(lines[0].split(":")[1])
        self.assertIn(wide_width, (2, 4))
        examples = {
            "char": ("RG_ASCII_SENTINEL_6dd935a7654147df", "utf-8"),
            "utf8": ("RG_UTF8_SENTINEL_5e24571f_中文_🔒", "utf-8"),
            "wide": ("RG_WIDE_SENTINEL_c45849ad_中文_🔒", f"utf-{wide_width * 8}-le"),
            "utf16": ("RG_UTF16_SENTINEL_774f62a3_中文_🔒", "utf-16-le"),
            "utf32": ("RG_UTF32_SENTINEL_f107b3d6_中文_🔒", "utf-32-le"),
            "empty": ("", "utf-8"),
            "embedded": ("RG_NUL_SENTINEL_3107\0AFTER_NUL", "utf-8"),
            "repeat1": ("RG_REPEAT_SENTINEL_173d6d2f", "utf-8"),
            "repeat2": ("RG_REPEAT_SENTINEL_173d6d2f", "utf-8"),
        }
        self.assertEqual(len(lines), 1 + len(examples) + 8)
        for line, (name, (text, encoding)) in zip(lines[1:], examples.items()):
            actual_name, actual_size, actual_values = line.split(":")
            expected = self.units(text, encoding)
            self.assertEqual(actual_name, name)
            self.assertEqual(int(actual_size), len(expected))
            self.assertEqual([int(v, 16) for v in actual_values.split(",") if v], expected)
        for index, line in enumerate(lines[1 + len(examples):]):
            actual_name, actual_values = line.split(":")
            self.assertEqual(actual_name, "thread")
            self.assertEqual(
                bytes(int(v, 16) for v in actual_values.split(",") if v),
                (chr(ord("A") + index) + "G_THREAD_SENTINEL_15989c25").encode(),
            )
        binary = executable.read_bytes()
        for text, encoding in examples.values():
            if text:
                self.assertNotIn(text.encode(encoding), binary, f"plaintext marker found: {encoding}")
        for marker, encoding in (
            ("RG_WIPE_SENTINEL_fdb72118", "utf-8"),
            ("RG_WIPE_UTF16_SENTINEL_11d44cbd", "utf-16-le"),
            ("RG_THREAD_SENTINEL_15989c25", "utf-8"),
        ):
            self.assertNotIn(marker.encode(encoding), binary)
        return result.stdout

    def test_o0_runtime_and_static_markers(self):
        process, binary = self.compile("o0", "O0")
        self.assert_compiled(process)
        self.assert_fixture(binary)

    def test_o2_runtime_and_static_markers(self):
        process, binary = self.compile("o2", "O2")
        self.assert_compiled(process)
        self.assert_fixture(binary)

    def test_o3_runtime_and_static_markers(self):
        if self.msvc:
            self.skipTest("MSVC uses /O2; covered by the O2 test")
        process, binary = self.compile("o3", "O3")
        self.assert_compiled(process)
        self.assert_fixture(binary)

    def test_lto_runtime_and_static_markers(self):
        probe, _ = self.compile("lto-probe", source="int main() {}\n", lto=True)
        if probe.returncode:
            self.skipTest("compiler/linker LTO unavailable: " + (probe.stderr + probe.stdout)[-1200:])
        process, binary = self.compile("lto", "O3", lto=True)
        self.assert_compiled(process)
        self.assert_fixture(binary)

    def test_seed_changes_binary_without_changing_plaintext(self):
        first, first_binary = self.compile("seed-first", seed=SEED)
        second, second_binary = self.compile("seed-second", seed=SEED ^ 0xD0F1E2A394857667)
        self.assert_compiled(first)
        self.assert_compiled(second)
        self.assertEqual(self.assert_fixture(first_binary), self.assert_fixture(second_binary))
        self.assertNotEqual(first_binary.read_bytes(), second_binary.read_bytes())

    def test_missing_seed_is_a_compile_error(self):
        process, _ = self.compile(
            "missing-seed", seed=None,
            source='#include "releaseguard/literal.hpp"\nint main() {}\n',
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("RELEASEGUARD_BUILD_SEED must be defined", process.stdout + process.stderr)

    def test_temporary_pointer_access_is_a_compile_error(self):
        for access in ("c_str", "data"):
            with self.subTest(access=access):
                process, _ = self.compile(
                    "rvalue-" + access,
                    source='#include "releaseguard_build.hpp"\n'
                           '#include "releaseguard/literal.hpp"\n'
                           f'int main() {{ const char* p = RG_TEXT("sample").{access}(); (void)p; }}\n',
                )
                self.assertNotEqual(process.returncode, 0)


if __name__ == "__main__":
    unittest.main()
