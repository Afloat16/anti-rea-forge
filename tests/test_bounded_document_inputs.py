"""Legacy manifest/license/key readers share a bounded regular-file boundary."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from releaseguard import core
from releaseguard.core import GuardError, read_document, read_limited


class BoundedDocumentInputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned bounded documents ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.path = self.work / "document.json"
        self.path.write_bytes(b'{"owned":"document"}')

    def test_normal_document_empty_and_exact_limit_remain_supported(self):
        raw = self.path.read_bytes()
        self.assertEqual(read_document(self.path), {"owned": "document"})
        self.assertEqual(read_limited(self.path, len(raw)), raw)
        self.assertEqual(self.path.read_bytes(), raw)
        self.path.write_bytes(b"")
        self.assertEqual(read_limited(self.path, 0), b"")

    def test_negative_boolean_noninteger_and_unbounded_limits_fail_before_open(self):
        for limit in (-2, -1, True, 1.0, "1", core.MAX_DOCUMENT_BYTES + 1):
            with self.subTest(limit=limit), patch.object(Path, "open", side_effect=AssertionError(
                    "An invalid limit must fail before opening the file")), patch.object(
                    core.os, "open", side_effect=AssertionError("Invalid limit reached os.open")):
                with self.assertRaisesRegex(GuardError, "limit"):
                    read_limited(self.path, limit)

    def test_oversized_regular_file_fails_before_open(self):
        with patch.object(Path, "open", side_effect=AssertionError("Oversized input must not be opened")), \
                patch.object(core.os, "open", side_effect=AssertionError("Oversized input reached os.open")):
            with self.assertRaisesRegex(GuardError, "limit"):
                read_limited(self.path, 1)

    def test_leaf_symlink_cannot_select_another_document(self):
        link = self.work / "linked.json"
        try:
            link.symlink_to(self.path)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable")
        with self.assertRaises(GuardError):
            read_document(link)
        self.assertEqual(read_document(self.path), {"owned": "document"})

    def test_directory_is_not_a_document(self):
        with self.assertRaises(GuardError):
            read_limited(self.work)

    @unittest.skipUnless(os.name == "posix", "POSIX FIFO boundary")
    def test_fifo_without_writer_is_rejected_without_blocking(self):
        fifo = self.work / "pipe.json"
        os.mkfifo(fifo)
        program = (
            "import sys\nfrom releaseguard.core import GuardError, read_document\n"
            "try:\n read_document(sys.argv[1])\n"
            "except GuardError:\n sys.exit(0)\n"
            "sys.exit(1)\n"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(Path(core.__file__).resolve().parents[1])
        try:
            result = subprocess.run([sys.executable, "-c", program, str(fifo)], cwd=self.work,
                                    env=environment, capture_output=True, timeout=3)
        except subprocess.TimeoutExpired:
            self.fail("A no-writer FIFO blocked document loading")
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))

    def test_changed_or_replaced_regular_file_is_not_returned(self):
        original = b'{"owned":"document"}'
        real_fdopen = os.fdopen
        real_path_open = Path.open
        for mutation in ("contents", "replacement"):
            self.path.write_bytes(original)
            target = self.path

            class ChangingReader:
                def __init__(self, handle):
                    self.handle = handle

                def __enter__(self):
                    self.handle.__enter__()
                    return self

                def __exit__(self, *args):
                    result = self.handle.__exit__(*args)
                    if mutation == "replacement":
                        replacement = target.with_name("replacement.json")
                        replacement.write_bytes(original)
                        os.replace(replacement, target)
                    return result

                def fileno(self):
                    return self.handle.fileno()

                def read(self, size):
                    value = self.handle.read(size)
                    if mutation == "contents":
                        stamp = target.stat()
                        target.write_bytes(b'{"owned":"modified"}')
                        os.utime(target, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 1_000_000_000))
                    return value

            def changing_path_open(path, mode="r", *args, **kwargs):
                handle = real_path_open(path, mode, *args, **kwargs)
                return ChangingReader(handle) if mode == "rb" and path == target else handle

            with self.subTest(mutation=mutation), patch.object(
                    core.os, "fdopen", side_effect=lambda *args, **kwargs: ChangingReader(
                        real_fdopen(*args, **kwargs))), patch.object(Path, "open", new=changing_path_open):
                with self.assertRaisesRegex(GuardError, "changed"):
                    read_limited(target)


if __name__ == "__main__":
    unittest.main()
