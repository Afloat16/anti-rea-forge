"""Real Apple toolchain controls; set RELEASEGUARD_REQUIRE_MACHO_TOOLCHAIN in CI."""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from releaseguard import macho
from releaseguard.distribution import scan_release


class RealDarwinMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        required = os.environ.get("RELEASEGUARD_REQUIRE_MACHO_TOOLCHAIN") == "1"
        if sys.platform != "darwin":
            if required:
                raise AssertionError("Mandatory Mach-O controls require macOS")
            raise unittest.SkipTest("Apple clang/strip/lipo controls require macOS")
        if not shutil.which("xcrun") or not shutil.which("codesign"):
            if required:
                raise AssertionError("Mandatory Mach-O controls need xcrun and codesign")
            raise unittest.SkipTest("Apple developer tools are unavailable")
        for name in ("clang", "strip", "nm", "dsymutil", "lipo"):
            result = subprocess.run(["xcrun", "--find", name], capture_output=True, text=True, timeout=30)
            if result.returncode:
                if required:
                    raise AssertionError("Missing mandatory Apple tool: " + name)
                raise unittest.SkipTest("Apple tool is unavailable: " + name)

    def test_real_clang_strip_dsym_and_universal_controls_preserve_public_api(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            source = base / "owned.c"
            source.write_text(
                "#include <stdio.h>\n"
                "__attribute__((noinline)) static int private_pricing_rule(int x) { return x * 37 + 19; }\n"
                '__attribute__((visibility("default"), noinline)) int rg_public_api(int x) { return private_pricing_rule(x); }\n'
                'int main(void) { printf("%d\\n", rg_public_api(3)); return 0; }\n',
                encoding="utf-8")

            def run(*arguments):
                return subprocess.run([str(value) for value in arguments], check=True,
                                      capture_output=True, text=True, timeout=60).stdout

            def tool(name, *arguments):
                return run("xcrun", name, *arguments)

            def inspect(path):
                before = hashlib.sha256(path.read_bytes()).hexdigest()
                result = macho.audit_macho(path)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
                return result

            clean = {}
            unstripped = {}
            for arch in ("x86_64", "arm64"):
                obj = base / (arch + ".o")
                ordinary = base / ("ordinary-" + arch)
                stripped = base / ("stripped-" + arch)
                tool("clang", "-arch", arch, "-g", "-O0", "-fno-inline", "-c", source, "-o", obj)
                tool("clang", "-arch", arch, "-g", obj,
                     "-Wl,-exported_symbol,_rg_public_api", "-Wl,-exported_symbol,_main", "-o", ordinary)
                self.assertTrue(inspect(obj)["evidence"]["debug_metadata_present"])
                ordinary_report = inspect(ordinary)
                self.assertTrue(ordinary_report["evidence"]["debug_metadata_present"])
                self.assertTrue(ordinary_report["evidence"]["private_symbols_present"])
                self.assertIn("_private_pricing_rule", tool("nm", "-a", ordinary))

                dsym = base / ("symbols-" + arch + ".dSYM")
                tool("dsymutil", ordinary, "-o", dsym)
                debug_file = dsym / "Contents" / "Resources" / "DWARF" / ordinary.name
                self.assertTrue(inspect(debug_file)["evidence"]["debug_metadata_present"])

                public_before = set(tool("nm", "-gUj", ordinary).splitlines())
                imports_before = set(tool("nm", "-uj", ordinary).splitlines())
                tool("strip", "-S", "-x", "-o", stripped, ordinary)
                # These are owned test executables. Re-sign ad hoc after stripping
                # so arm64 execution checks a valid fixture, not a stale signature.
                run("codesign", "--force", "--sign", "-", stripped)
                report = inspect(stripped)
                self.assertEqual(report["evidence"], {
                    "debug_metadata_present": False, "private_symbols_present": False})
                self.assertIn("_rg_public_api", public_before)
                self.assertIn("_printf", imports_before)
                self.assertEqual(set(tool("nm", "-gUj", stripped).splitlines()), public_before)
                self.assertEqual(set(tool("nm", "-uj", stripped).splitlines()), imports_before)
                self.assertNotIn("_private_pricing_rule", tool("nm", "-a", stripped))
                clean[arch], unstripped[arch] = stripped, ordinary

            host = "arm64" if platform.machine() == "arm64" else "x86_64"
            self.assertEqual(run(unstripped[host]), "130\n")
            self.assertEqual(run(clean[host]), "130\n")
            release = base / "release"
            release.mkdir()
            universal = release / "universal.blob"
            tool("lipo", "-create", clean["x86_64"], clean["arm64"], "-output", universal)
            report = inspect(universal)
            self.assertEqual(report["slice_count"], 2)
            self.assertFalse(any(report["evidence"].values()))
            policy = base / "policy.json"
            policy.write_text('{"version":1}', encoding="utf-8")
            self.assertTrue(scan_release(release, policy)["ok"])

            mixed = base / "mixed.blob"
            tool("lipo", "-create", clean["x86_64"], unstripped["arm64"], "-output", mixed)
            report = inspect(mixed)
            self.assertEqual(report["slice_count"], 2)
            self.assertTrue(report["evidence"]["debug_metadata_present"])
            self.assertTrue(report["evidence"]["private_symbols_present"])
            self.assertEqual(sum(item["evidence"]["private_symbols_present"]
                                 for item in report["architectures"]), 1)


if __name__ == "__main__":
    unittest.main()
