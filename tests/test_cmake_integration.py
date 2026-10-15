"""Build and execute only this project's own Linux C/C++ test programs."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from releaseguard import native


REPOSITORY = Path(__file__).resolve().parents[1]
MARKER = "releaseguard-demo-private-literal"
PUBLIC_MESSAGE = "ReleaseGuard example: build mitigations enabled."


class CMakeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not sys.platform.startswith("linux"):
            raise unittest.SkipTest("Real CMake integration fixtures currently target Linux GCC")
        requested = os.environ.get("RELEASEGUARD_CMAKE")
        cmake = shutil.which(requested or "cmake")
        if not cmake:
            if requested:
                raise RuntimeError("RELEASEGUARD_CMAKE does not name an executable CMake")
            raise unittest.SkipTest("CMake is not installed; set RELEASEGUARD_CMAKE to its executable")
        cls.cmake = cmake
        sibling_ctest = Path(cmake).resolve().with_name("ctest")
        cls.ctest = str(sibling_ctest) if sibling_ctest.is_file() else shutil.which("ctest")
        cls.cc, cls.cxx = shutil.which("gcc"), shutil.which("g++")
        if not cls.ctest or not cls.cc or not cls.cxx:
            raise unittest.SkipTest("CMake integration requires CTest, gcc and g++")
        if shutil.which("make"):
            cls.generator = "Unix Makefiles"
        elif shutil.which("ninja"):
            cls.generator = "Ninja"
        else:
            raise unittest.SkipTest("CMake integration requires Make or Ninja")

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="releaseguard cmake ")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.build = self.base / "build with spaces"

    def run_command(self, *arguments: object, expected: int | None = 0) -> subprocess.CompletedProcess[str]:
        command = [str(value) for value in arguments]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=60, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            self.fail(f"Command exceeded its 60-second timeout: {command!r}\n{exc.output!r}")
        if expected is not None:
            self.assertEqual(
                result.returncode, expected,
                f"Command: {command!r}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
            )
        return result

    def configure(self, source: Path, *, c_only: bool = False) -> None:
        arguments = [
            self.cmake, "-S", source, "-B", self.build, "-G", self.generator,
            "-DCMAKE_BUILD_TYPE=Release", f"-DPython3_EXECUTABLE={sys.executable}",
            f"-DCMAKE_C_COMPILER={self.cc}",
        ]
        if not c_only:
            arguments.append(f"-DCMAKE_CXX_COMPILER={self.cxx}")
        self.run_command(*arguments)

    def build_project(self, *, expected: int | None = 0) -> subprocess.CompletedProcess[str]:
        return self.run_command(
            self.cmake, "--build", self.build, "--config", "Release", "--parallel", "2",
            expected=expected,
        )

    def run_ctest(self) -> None:
        self.run_command(self.ctest, "--test-dir", self.build, "-C", "Release", "--output-on-failure")

    def gate_report(self, artifact: Path, policy: Path, *, expected: int = 0) -> dict:
        result = self.run_command(
            sys.executable, "-m", "releaseguard", "gate", artifact, "--policy", policy,
            expected=expected,
        )
        return json.loads(result.stdout)

    def write_fixture(self, cmake: str, sources: dict[str, str], *, literal: str | None = None) -> Path:
        source = self.base / "source with spaces"
        source.mkdir()
        # Exercise the distributable module and its relative include directory.
        native.init_native(source / "assets")
        (source / "CMakeLists.txt").write_text(cmake, encoding="utf-8")
        for name, content in sources.items():
            (source / name).write_text(content, encoding="utf-8")
        policy = {"version": 1, "formats": ["elf"]}
        if literal is not None:
            policy["forbid_literals"] = [literal]
        (source / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
        return source

    def test_release_examples_gate_failure_and_recovery(self) -> None:
        checkout = self.base / "repository with spaces"
        shutil.copytree(REPOSITORY / "examples", checkout / "examples")
        shutil.copytree(REPOSITORY / "cmake", checkout / "cmake")
        shutil.copytree(REPOSITORY / "src/releaseguard/data", checkout / "src/releaseguard/data")
        source = checkout / "examples"
        policy = source / "policy.json"
        original_policy = policy.read_bytes()

        self.configure(source)
        self.build_project()
        self.run_ctest()
        protected = self.build / "releaseguard-example"
        plain = self.build / "releaseguard-example-plain"
        self.assertEqual(self.run_command(protected).stdout, self.run_command(plain).stdout)
        self.assertIn(MARKER.encode(), plain.read_bytes())
        self.assertNotIn(MARKER.encode(), protected.read_bytes())
        self.assertTrue(self.gate_report(protected, policy)["ok"])

        generated = self.build / "releaseguard-generated/releaseguard-example"
        seed_header = generated / "releaseguard_build.hpp"
        seed_before = seed_header.read_bytes()
        manifest_before = (generated / "releaseguard-native.json").read_bytes()
        self.assertIn(" ", str(seed_header))
        self.configure(source)
        self.assertEqual(seed_header.read_bytes(), seed_before)
        self.assertEqual((generated / "releaseguard-native.json").read_bytes(), manifest_before)

        # A policy-only change must cause the build's POST_BUILD gate to reject
        # the known unmasked prefix. Restore the same project and build again.
        bad_policy = json.loads(original_policy)
        bad_policy["forbid_literals"] = [PUBLIC_MESSAGE]
        policy.write_text(json.dumps(bad_policy), encoding="utf-8")
        rejected = self.build_project(expected=None)
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertIn("forbidden_literal", rejected.stdout + rejected.stderr)
        policy.write_bytes(original_policy)
        self.build_project()
        self.run_ctest()
        self.assertTrue(self.gate_report(protected, policy)["ok"])

    def test_cpp_standard_and_seed_header_are_supplied_by_protect(self) -> None:
        literal = "cmake-forced-header-private-literal"
        source = self.write_fixture(
            '''cmake_minimum_required(VERSION 3.20)
project(AutomaticCppSetup LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
include("${CMAKE_CURRENT_LIST_DIR}/assets/cmake/ReleaseGuard.cmake")
add_executable(automatic main.cpp)
releaseguard_protect(automatic POLICY "${CMAKE_CURRENT_LIST_DIR}/policy.json")
enable_testing()
add_test(NAME automatic COMMAND automatic)
''',
            {"main.cpp": '''#include <releaseguard/literal.hpp>
#include <iostream>
#if __cplusplus < 201703L
#error "releaseguard_protect must supply at least C++17"
#endif
int main() {
    auto message = RG_TEXT("cmake-forced-header-private-literal");
    std::cout << message.c_str() << '\\n';
    return 0;
}
'''},
            literal=literal,
        )
        self.configure(source)
        self.build_project()
        self.run_ctest()
        artifact = self.build / "automatic"
        self.assertEqual(self.run_command(artifact).stdout, literal + "\n")
        self.assertNotIn(literal.encode(), artifact.read_bytes())
        self.assertTrue(self.gate_report(artifact, source / "policy.json")["ok"])

    def test_pure_c_shared_library_keeps_public_runtime_api(self) -> None:
        source = self.write_fixture(
            '''cmake_minimum_required(VERSION 3.20)
project(CSharedLibrary LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
include("${CMAKE_CURRENT_LIST_DIR}/assets/cmake/ReleaseGuard.cmake")
add_library(public_fixture SHARED library.c)
releaseguard_protect(public_fixture POLICY "${CMAKE_CURRENT_LIST_DIR}/policy.json" SEED 0123456789abcdef)
add_executable(abi_probe probe.c)
target_link_libraries(abi_probe PRIVATE ${CMAKE_DL_LIBS})
enable_testing()
add_test(NAME public-api COMMAND abi_probe "$<TARGET_FILE:public_fixture>")
''',
            {
                "library.c": '''#ifndef RELEASEGUARD_BUILD_SEED
#error "C compilation must receive the generated seed header too"
#endif
_Static_assert(RELEASEGUARD_BUILD_SEED != 0, "test seed must be nonzero");
int releaseguard_public_api(int value) { return value + 17; }
''',
                "probe.c": '''#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\\n", dlerror()); return 2; }
    dlerror();
    int (*function)(int) = (int (*)(int))dlsym(library, "releaseguard_public_api");
    const char *error = dlerror();
    if (error || !function) { fprintf(stderr, "public API not exported\\n"); return 3; }
    int result = function(25);
    dlclose(library);
    return result == 42 ? 0 : 4;
}
''',
            },
        )
        self.configure(source, c_only=True)
        self.build_project()
        self.run_ctest()
        library = self.build / "libpublic_fixture.so"
        self.assertTrue(self.gate_report(library, source / "policy.json")["ok"])


if __name__ == "__main__":
    unittest.main()
