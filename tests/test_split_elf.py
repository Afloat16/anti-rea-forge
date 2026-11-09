from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from unittest.mock import patch

from releaseguard.core import GuardError
from releaseguard.split_elf import _check_load_image, split_elf_debug

PRIVATE = "merchant_private_discount_curve"
SOURCE = f"""#include <stdio.h>
__attribute__((noinline)) static int {PRIVATE}(int value) {{ return value * 3 + 1; }}
int public_quote(int value) {{ return {PRIVATE}(value); }}
int main(void) {{ printf("%d\\n", public_quote(7)); return 0; }}
"""


def gnu_linux_tools():
    return (sys.platform.startswith("linux") and all(shutil.which(exe) for exe in
            ("cc", "objcopy", "nm", "addr2line")) and
            b"GNU objcopy" in subprocess.check_output(["objcopy", "--version"]))


@unittest.skipUnless(gnu_linux_tools(), "requires GNU/Linux ELF build and debugger tools")
class SplitElfTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.source = self.root / "quote.c"
        self.source.write_text(SOURCE, encoding="ascii")
        self.app = self.root / "app"
        self.public = self.root / "public"
        self.private = self.root / "private"

    def build(self, *flags):
        subprocess.run(["cc", "-g", "-O1", *flags, str(self.source), "-o", str(self.app)], check=True)

    def split(self, *markers):
        return split_elf_debug(self.app, self.public, self.private, markers)

    def assert_no_outputs(self):
        self.assertFalse(self.public.exists())
        self.assertFalse(self.private.exists())

    def test_executable_private_symbols_and_line_numbers_with_unchanged_code(self):
        self.build("-rdynamic")
        original, info = self.app.read_bytes(), self.app.stat()
        result = self.split(PRIVATE)
        self.assertTrue(result["ok"])
        release, sidecar = Path(result["public_elf"]), Path(result["private_debug"])
        self.assertEqual(release.name, self.app.name)
        self.assertEqual(sidecar.name, self.app.name + ".debug")
        self.assertEqual(self.app.read_bytes(), original)
        self.assertEqual(self.app.stat().st_mtime_ns, info.st_mtime_ns)
        self.assertEqual(stat.S_IMODE(release.stat().st_mode), stat.S_IMODE(info.st_mode))
        self.assertEqual(stat.S_IMODE(sidecar.stat().st_mode), 0o600)
        self.assertEqual(subprocess.check_output([release]), subprocess.check_output([self.app]))
        self.assertEqual(subprocess.check_output([release]), b"22\n")
        self.assertNotIn(PRIVATE.encode(), release.read_bytes())
        defs = subprocess.check_output(["nm", "--defined-only", sidecar], text=True)
        address = next(row.split()[0] for row in defs.splitlines() if row.split()[-1] == PRIVATE)
        lines = subprocess.check_output(["addr2line", "-f", "-e", sidecar, address], text=True)
        self.assertIn(PRIVATE, lines)
        self.assertIn("quote.c:2", lines)
        self.assert_debuglink(release, sidecar)

    def assert_debuglink(self, release, sidecar):
        link = self.root / "debuglink-data"
        subprocess.run(["objcopy", "--dump-section", f".gnu_debuglink={link}",
                        release, self.root / "inspection-copy"], check=True)
        label = os.fsencode(sidecar.name) + b"\0"
        byteorder = "little" if release.read_bytes()[5] == 1 else "big"
        self.assertEqual(link.read_bytes(), label + b"\0" * (-len(label) % 4)
                         + zlib.crc32(sidecar.read_bytes()).to_bytes(4, byteorder))

    def test_shared_library_keeps_working_dynamic_exports(self):
        self.build("-shared", "-fPIC")
        release = Path(self.split(PRIVATE)["public_elf"])
        for file in (self.app, release):
            fn = ctypes.CDLL(str(file)).public_quote
            fn.argtypes, fn.restype = [ctypes.c_int], ctypes.c_int
            self.assertEqual(fn(13), 40)
        self.assertNotIn(PRIVATE.encode(), release.read_bytes())
        moved = self.private.rename(self.root / "moved-private-symbols")
        self.assert_debuglink(release, moved / (self.app.name + ".debug"))

    def test_export_or_diagnostic_leaking_name_blocks_release(self):
        self.build("-rdynamic")
        self.assertEqual(self.split("public_quote")["findings"], [
            {"code": "private_name_in_public", "name": "public_quote"}])
        self.assert_no_outputs()
        self.source.write_text(SOURCE + f'const char *diagnostic = "{PRIVATE}";\n', encoding="ascii")
        self.build()
        self.assertFalse(self.split(PRIVATE)["ok"])
        self.assert_no_outputs()

    def test_wide_character_and_big_endian_diagnostic_leaks(self):
        fixtures = {
            "host wchar_t": f'#include <wchar.h>\nconst wchar_t *diagnostic = L"{PRIVATE}";',
            "UTF-16LE": PRIVATE.encode("utf-16le"),
            "UTF-16BE": PRIVATE.encode("utf-16be"),
            "UTF-32LE": PRIVATE.encode("utf-32le"),
            "UTF-32BE": PRIVATE.encode("utf-32be"),
        }
        for label, diagnostic in fixtures.items():
            with self.subTest(label=label):
                if isinstance(diagnostic, bytes):
                    data = ",".join(map(str, diagnostic))
                    diagnostic = f"const unsigned char diagnostic[] = {{{data}}};"
                self.source.write_text(SOURCE + diagnostic, encoding="ascii")
                self.build()
                self.assertEqual(self.split(PRIVATE)["findings"], [
                    {"code": "private_name_in_public", "name": PRIVATE}])
                self.assert_no_outputs()

    def test_private_name_requires_a_collection(self):
        self.build()
        with self.assertRaises(GuardError):
            split_elf_debug(self.app, self.public, self.private, PRIVATE)
        self.assert_no_outputs()

    def test_cli_returns_distinct_findings_and_error_codes(self):
        self.build("-rdynamic")
        cmd = [sys.executable, "-m", "releaseguard", "split-elf-debug", str(self.app),
               "--public", str(self.public), "--private", str(self.private), "--private-name"]
        found = subprocess.run([*cmd, "public_quote"], capture_output=True, timeout=20)
        self.assertEqual(found.returncode, 3, found.stderr)
        self.assertEqual(json.loads(found.stdout)["findings"][0]["code"], "private_name_in_public")
        self.assert_no_outputs()
        missing = subprocess.run([*cmd, "unknown_private_symbol"], capture_output=True, timeout=20)
        self.assertEqual(missing.returncode, 2, missing.stdout)
        self.assertIn("error", json.loads(missing.stderr))
        self.assert_no_outputs()

    def test_unknown_marker_fails_without_output(self):
        self.build()
        with self.assertRaisesRegex(GuardError, "absent from separate"):
            self.split("this_private_symbol_was_not_in_the_input")
        self.assert_no_outputs()

    def test_appended_data_and_already_stripped_input_fail(self):
        self.build()
        with self.app.open("ab") as stream:
            stream.write(b"app-specific appended payload")
        with self.assertRaisesRegex(GuardError, "appended"):
            self.split()
        self.assert_no_outputs()
        self.build("-s")
        with self.assertRaisesRegex(GuardError, "static symbols"):
            self.split()
        self.assert_no_outputs()

    def test_invalid_nonlinked_and_privileged_inputs(self):
        self.app.write_bytes(b"not an executable file")
        with self.assertRaises(ValueError):
            self.split()
        subprocess.run(["cc", "-c", self.source, "-o", self.app], check=True)
        with self.assertRaises(ValueError):
            self.split()
        self.app.chmod(0o4755)
        with self.assertRaisesRegex(GuardError, "privileges"):
            self.split()
        self.assert_no_outputs()

    def test_existing_and_alias_destinations_are_never_reused(self):
        self.build()
        self.public.mkdir()
        (self.public / "keep").write_text("existing")
        with self.assertRaises(ValueError):
            self.split()
        self.assertEqual((self.public / "keep").read_text(), "existing")
        self.assertFalse(self.private.exists())
        (self.public / "keep").unlink()
        self.public.rmdir()
        with self.assertRaisesRegex(GuardError, "distinct"):
            split_elf_debug(self.app, self.public, self.public)
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            split_elf_debug(self.app, alias / "public", self.private)
        self.private.symlink_to(self.root / "absent")
        with self.assertRaises(ValueError):
            self.split()
        self.assertTrue(self.private.is_symlink())
        self.assertFalse(self.public.exists())

    def test_input_symlink_and_subprocess_failure(self):
        self.build()
        actual = self.app.rename(self.root / "actual")
        self.app.symlink_to(actual)
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.split()
        self.app.unlink()
        actual.rename(self.app)
        with patch("releaseguard.split_elf.subprocess.run", side_effect=subprocess.TimeoutExpired("objcopy", 120)):
            with self.assertRaisesRegex(ValueError, "timed out"):
                self.split()
        self.assert_no_outputs()

    def test_rollback_after_private_file_is_created(self):
        self.build()
        with patch.object(Path, "chmod", side_effect=OSError("cannot set mode")):
            with self.assertRaisesRegex(OSError, "cannot set mode"):
                self.split()
        self.assert_no_outputs()

    def test_reject_changes_to_program_headers_and_loaded_data(self):
        self.build()
        original = self.app.read_bytes()
        # The tool only accepts linked host ELFs. This test fixture uses the host ABI.
        is64, endian = original[4] == 2, "<" if original[5] == 1 else ">"
        fmt = endian + ("Q" if is64 else "I")
        phoff = struct.unpack_from(fmt, original, 32 if is64 else 28)[0]
        mutated = bytearray(original)
        mutated[phoff] ^= 1
        with self.assertRaisesRegex(GuardError, "program headers"):
            _check_load_image(original, bytes(mutated))
        needle = b"%d\n\0"
        pos = original.index(needle)
        mutated = bytearray(original)
        mutated[pos] ^= 1
        with self.assertRaisesRegex(GuardError, "loadable segment"):
            _check_load_image(original, bytes(mutated))
