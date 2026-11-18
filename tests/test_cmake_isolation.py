"""Actual CMake controls for the selected interpreter's installed package."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import unittest

from tests.test_cmake_integration import CMakeFixture


class CMakePythonIsolationTests(CMakeFixture):
    def setUp(self):
        super().setUp()
        self.command_cwd = None
        self.command_env = None

    def run_command(self, *arguments: object, expected: int | None = 0) -> subprocess.CompletedProcess[str]:
        return super().run_command(*arguments, expected=expected,
                                   cwd=self.command_cwd, env=self.command_env)

    def source_fixture(self):
        # This C program intentionally exposes an owned marker. A successful
        # link must still fail the real POST_BUILD release policy.
        return self.write_fixture(
            '''cmake_minimum_required(VERSION 3.20)
project(PythonIsolation LANGUAGES C)
include("${CMAKE_CURRENT_LIST_DIR}/assets/cmake/ReleaseGuard.cmake")
add_executable(isolation main.c)
releaseguard_protect(isolation POLICY "${CMAKE_CURRENT_LIST_DIR}/policy.json")
''',
            {"main.c": '#include <stdio.h>\nint main(void) { puts("CMAKE-OWNED-PRIVATE-MARKER"); return 0; }\n'},
            literal="CMAKE-OWNED-PRIVATE-MARKER",
        )

    def install_shadow(self, directory: Path, location: str):
        directory.mkdir(exist_ok=True)
        self.invocations = self.base / "unexpected-shadow-invocation.txt"
        (directory / "releaseguard.py").write_text(
            "from pathlib import Path\nimport sys\n"
            + f"Path({str(self.invocations)!r}).write_text('shadow executed', encoding='utf-8')\n"
              "if 'native-init' in sys.argv:\n"
              "    output = Path(sys.argv[sys.argv.index('--out') + 1])\n"
              "    output.mkdir(parents=True, exist_ok=True)\n"
              "    (output / 'releaseguard_build.hpp').write_text('#pragma once\\n', encoding='utf-8')\n"
              "print('{\"ok\": true}')\n", encoding="utf-8")
        if location == "cwd":
            self.command_cwd = directory
        else:
            self.command_env = {**os.environ, "PYTHONPATH": str(directory)}

    def check_native_init(self, location):
        source = self.source_fixture()
        directory = source if location == "cwd" else self.base / "python search path"
        self.install_shadow(directory, location)
        self.configure(source, c_only=True)
        self.assertFalse(self.invocations.exists(), "native-init imported the shadow module")
        generated = self.build / "releaseguard-generated/isolation"
        self.assertTrue((generated / "releaseguard-native.json").is_file())
        self.assertTrue((generated / "include/releaseguard/literal.hpp").is_file())

    def check_post_build_gate(self, location):
        source = self.source_fixture()
        self.configure(source, c_only=True)
        directory = self.build if location == "cwd" else self.base / "python search path"
        self.install_shadow(directory, location)
        result = self.build_project(expected=None)
        self.assertNotEqual(result.returncode, 0, "The policy-rejected executable passed the build gate")
        self.assertIn("forbidden_literal", result.stdout + result.stderr)
        self.assertFalse(self.invocations.exists(), "POST_BUILD imported the shadow module")

    def test_native_init_ignores_working_directory_shadow(self):
        self.check_native_init("cwd")

    def test_native_init_ignores_pythonpath_shadow(self):
        self.check_native_init("pythonpath")

    def test_post_build_gate_ignores_working_directory_shadow(self):
        self.check_post_build_gate("cwd")

    def test_post_build_gate_ignores_pythonpath_shadow(self):
        self.check_post_build_gate("pythonpath")


if __name__ == "__main__":
    unittest.main()
