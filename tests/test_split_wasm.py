"""Private Wasm metadata separation with exact bytes and owned engine controls."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from releaseguard.core import GuardError
from releaseguard import split_wasm as module
from tests.test_wasm import HEADER, PRIVATE_FUNCTION, PRIVATE_LOCAL, PRIVATE_MODULE, custom, owned_core, owned_module


class SplitWasmTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned wasm split ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "original.wasm"
        self.source.write_bytes(owned_module())
        self.public = self.root / "public" / "module.wasm"
        self.private = self.root / "private" / "original.wasm"
        self.public.parent.mkdir()
        self.private.parent.mkdir()

    def split(self):
        return module.split_wasm(self.source, self.public, self.private)

    def assert_no_outputs(self):
        self.assertFalse(self.public.exists())
        self.assertFalse(self.private.exists())

    def test_exact_original_and_every_retained_byte_are_preserved(self):
        original, stamp = self.source.read_bytes(), self.source.stat().st_mtime_ns
        result = self.split()
        expected_public = owned_core() + custom("public_notice", b"Copyright: owned fixture")
        self.assertTrue(result["ok"])
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(self.source.stat().st_mtime_ns, stamp)
        self.assertEqual(self.private.read_bytes(), original)
        self.assertEqual(self.public.read_bytes(), expected_public)
        self.assertEqual(result["private_original"], str(self.private))
        self.assertEqual(result["public_wasm"], str(self.public))
        self.assertEqual(result["original"], {"bytes": len(original), "sha256": hashlib.sha256(original).hexdigest()})
        self.assertEqual(result["public"], {"bytes": len(expected_public), "sha256": hashlib.sha256(expected_public).hexdigest()})
        self.assertEqual(sum(item["bytes"] for item in result["removed_sections"]), len(original) - len(expected_public))
        self.assertEqual(result["retained_bytes_sha256"], hashlib.sha256(expected_public).hexdigest())
        self.assertEqual(result["core_sections_sha256"], hashlib.sha256(owned_core()).hexdigest())
        self.assertEqual(result["retained_sections"], 5)
        self.assertFalse(result["checks"]["full_module_validation_performed"])
        for secret in (PRIVATE_FUNCTION, PRIVATE_MODULE, PRIVATE_LOCAL, "owned-private-source.c"):
            self.assertNotIn(secret, json.dumps(result))
            self.assertNotIn(secret.encode(), self.public.read_bytes())
            self.assertIn(secret.encode(), self.private.read_bytes())

    @unittest.skipUnless(os.name == "posix", "POSIX file mode control")
    def test_private_file_has_restricted_permissions_and_public_keeps_mode(self):
        self.source.chmod(0o440)
        self.split()
        self.assertEqual(stat.S_IMODE(self.private.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.public.stat().st_mode), 0o440)

    def test_unknown_runtime_customs_are_kept_byte_for_byte(self):
        suffix = b"".join(custom(name, b"owned payload") for name in (
            "dylink.0", "producers", "target_features", "build_id", "other"))
        self.source.write_bytes(owned_module() + suffix)
        self.split()
        self.assertTrue(self.public.read_bytes().endswith(suffix))

    def test_linker_metadata_requires_final_link_before_any_output(self):
        for name in ("linking", "reloc.Code", "reloc.CODE", "reloc.DATA"):
            with self.subTest(name=name):
                self.source.write_bytes(owned_module() + custom(name, b"owned linker payload"))
                before = self.source.read_bytes()
                with self.assertRaisesRegex(GuardError, "final linked module"):
                    self.split()
                self.assertEqual(self.source.read_bytes(), before)
                self.assert_no_outputs()

    def test_existing_outputs_and_inputs_are_never_overwritten(self):
        for destination in (self.public, self.private):
            with self.subTest(destination=destination):
                destination.write_bytes(b"do not overwrite")
                with self.assertRaises(GuardError):
                    self.split()
                self.assertEqual(destination.read_bytes(), b"do not overwrite")
                self.assertFalse((self.private if destination == self.public else self.public).exists())
                destination.unlink()
        for public, private in ((self.source, self.private), (self.public, self.source)):
            with self.subTest(public=public), self.assertRaises(GuardError):
                module.split_wasm(self.source, public, private)
        self.assert_no_outputs()

    def test_same_or_nested_public_private_trees_are_rejected(self):
        nested = self.public.parent / "private"
        nested.mkdir()
        for public, private in ((self.public, self.public.parent / "original.wasm"),
                                (self.public, nested / "original.wasm"),
                                (nested / "module.wasm", self.public)):
            with self.subTest(public=public, private=private), self.assertRaises(GuardError):
                module.split_wasm(self.source, public, private)
            self.assertFalse(public.exists())
            self.assertFalse(private.exists())

    def test_original_must_stay_outside_public_tree(self):
        with self.assertRaises(GuardError):
            module.split_wasm(self.source, self.root / "published.wasm", self.private)
        self.assert_no_outputs()

    def test_invalid_component_unknown_section_and_no_metadata_leave_nothing(self):
        for data in (b"not wasm", b"\0asm\x0d\0\1\0", HEADER + b"\x0f\1\0", owned_core(),
                     owned_module() + b"\0\x80", owned_module() + custom("name")):
            with self.subTest(data=data[:12]):
                self.source.write_bytes(data)
                with self.assertRaises(GuardError):
                    self.split()
                self.assert_no_outputs()

    def test_links_and_output_parent_aliases_are_rejected(self):
        link = self.root / "input-link.wasm"
        parent_link = self.root / "public-link"
        try:
            link.symlink_to(self.source)
            parent_link.symlink_to(self.public.parent, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable")
        with self.assertRaises(GuardError):
            module.split_wasm(link, self.public, self.private)
        with self.assertRaises(GuardError):
            module.split_wasm(self.source, parent_link / "module.wasm", self.private)
        self.assert_no_outputs()

    def test_oversized_input_and_missing_parents_leave_no_output(self):
        with self.source.open("wb") as stream:
            stream.truncate((64 << 20) + 1)
        with self.assertRaises(GuardError):
            self.split()
        self.assert_no_outputs()
        self.source.write_bytes(owned_module())
        with self.assertRaises(OSError):
            module.split_wasm(self.source, self.root / "missing" / "module.wasm", self.private)
        self.assert_no_outputs()

    def test_write_failure_rolls_back_the_private_original(self):
        real_write = module.write_new

        def fail_public(path, content, **options):
            if path == self.public:
                raise OSError("owned failure control")
            return real_write(path, content, **options)

        with patch.object(module, "write_new", side_effect=fail_public), self.assertRaises(OSError):
            self.split()
        self.assert_no_outputs()

    def test_written_bytes_are_verified_before_success(self):
        real_write = module.write_new
        for damaged in (self.public, self.private):
            def alter(path, content, **options):
                return real_write(path, content + (b"changed" if path == damaged else b""), **options)
            with self.subTest(damaged=damaged), patch.object(module, "write_new", side_effect=alter):
                with self.assertRaisesRegex(GuardError, "outputs differ"):
                    self.split()
                self.assert_no_outputs()

    def test_input_change_after_public_creation_rolls_back_both_files(self):
        real_write = module.write_new

        def alter_source(path, content, **options):
            real_write(path, content, **options)
            if path == self.public:
                self.source.write_bytes(owned_module() + custom("change"))

        with patch.object(module, "write_new", side_effect=alter_source), self.assertRaises(GuardError):
            self.split()
        self.assert_no_outputs()

    def test_private_change_during_public_readback_rolls_back_both_files(self):
        real_read = module._read

        def alter_private(path, maximum):
            result = real_read(path, maximum)
            if path == self.public:
                self.private.write_bytes(owned_module() + custom("changed-private"))
            return result

        with patch.object(module, "_read", side_effect=alter_private), self.assertRaises(GuardError):
            self.split()
        self.assert_no_outputs()

    def test_public_change_during_final_source_check_rolls_back_both_files(self):
        real_assert = module._assert_scanned_identity
        source_checks = 0

        def alter_public(path, identity, label):
            nonlocal source_checks
            real_assert(path, identity, label)
            if path == self.source:
                source_checks += 1
                if source_checks == 2:
                    self.public.write_bytes(owned_core() + custom("changed-public"))

        with patch.object(module, "_assert_scanned_identity", side_effect=alter_public), self.assertRaises(GuardError):
            self.split()
        self.assertEqual(source_checks, 2)
        self.assert_no_outputs()

    @unittest.skipUnless(shutil.which("node"), "Requires Node.js for the owned WebAssembly engine control")
    def test_real_engine_keeps_outputs_exports_and_restore_control(self):
        self.split()
        # Only this test's own fixed arithmetic fixture is instantiated. The
        # production splitter does not invoke Node or execute target modules.
        script = """const fs=require('node:fs'); const crypto=require('node:crypto');
const rows=process.argv.slice(1).map(path=>{
 const bytes=fs.readFileSync(path); const m=new WebAssembly.Module(bytes);
 const i=new WebAssembly.Instance(m); const names=WebAssembly.Module.customSections(m,'name');
 return {valid:WebAssembly.validate(bytes), exports:WebAssembly.Module.exports(m),
 values:[-2,0,1,11,2147483647,-2147483648].map(x=>i.exports.quote(x)),
 names:names.map(v=>Buffer.from(v).toString('hex')),
 notices:WebAssembly.Module.customSections(m,'public_notice').map(v=>Buffer.from(v).toString('hex'))};
});process.stdout.write(JSON.stringify(rows));"""
        run = subprocess.run([shutil.which("node"), "-e", script, str(self.source), str(self.public), str(self.private)],
                             check=True, capture_output=True, text=True, timeout=20)
        before, public, restored = json.loads(run.stdout)
        self.assertEqual(before, restored)
        self.assertTrue(all(row["valid"] for row in (before, public, restored)))
        self.assertEqual(before["exports"], [{"name": "quote", "kind": "function"}])
        self.assertEqual(before["exports"], public["exports"])
        self.assertEqual(before["values"], [-11, 3, 10, 80, 2147483644, -2147483645])
        self.assertEqual(before["values"], public["values"])
        self.assertEqual(before["notices"], public["notices"])
        self.assertEqual(len(before["names"]), 1)
        self.assertEqual(public["names"], [])


if __name__ == "__main__":
    unittest.main()
