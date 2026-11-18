"""Exact private-byte containment, bounded work, and archive integration."""

from dataclasses import replace
import io
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from releaseguard.core import GuardError
from releaseguard.private_inputs import (
    MAX_PRIVATE_CONTENT_CANDIDATES, MAX_PRIVATE_CONTENT_VERIFY_BYTES,
    PrivateContentBudgetError, PrivateContentScanner,
    assert_private_inputs_unchanged, snapshot_private_inputs,
)


class PrivateContentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="private content ")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "public"
        self.root.mkdir()
        self.private = self.base / "private.mjs"
        self.data = (b"// Owned server-only implementation: private_quote_37_19.\n"
                     b"export function quote(quantity) { return quantity * 37 + 19; }\n")
        self.private.write_bytes(self.data)

    def snapshot(self, data=None):
        if data is not None:
            self.private.write_bytes(data)
        return snapshot_private_inputs([self.private], root=self.root)[0]

    def matcher(self, data=None):
        return PrivateContentScanner([self.snapshot(data)])

    def test_snapshot_retains_only_bounded_private_prefix(self):
        item = self.snapshot(self.data * 10000)
        self.assertEqual(item.anchor, self.data[:64])
        self.assertEqual(len(item.anchor), 64)
        self.assertNotIn(item.anchor.decode(), repr(item))
        self.assertNotIn(item.sha256, repr(item))
        self.assertNotIn(str(self.private), repr(item))

    def test_prefix_suffix_bundle_and_multiple_occurrences_match_once(self):
        for payload in (b"prefix\n" + self.data, self.data + b"\nsuffix",
                        b"prefix\n" + self.data + b"\nsuffix", self.data * 3):
            with self.subTest(size=len(payload)):
                matcher = self.matcher()
                stream = io.BytesIO(payload)
                stream.seek(3)
                self.assertEqual(matcher.scan(stream, len(payload)), (0,))
                self.assertEqual(stream.tell(), 3)
                self.assertEqual(matcher.candidates_checked, 1)
                self.assertEqual(matcher.verification_bytes, len(self.data))

    def test_short_including_zero_byte_references_are_never_silently_skipped(self):
        for data in (b"\0", b"x", b"secret", b"s" * 63, b"s" * 64):
            with self.subTest(size=len(data), zero=data == b"\0"):
                matcher = self.matcher(data)
                payload = b"prefix" + data + b"suffix"
                self.assertEqual(matcher.scan(io.BytesIO(payload), len(payload)), (0,))
                self.assertEqual(matcher.verification_bytes, 0)
                self.assertEqual(matcher.candidates_checked, 1)
        self.private.write_bytes(b"")
        with self.assertRaises(GuardError):
            snapshot_private_inputs([self.private], root=self.root)

    def test_same_prefix_without_complete_reference_does_not_match(self):
        data = b"a" * 64 + b"private"
        matcher = self.matcher(data)
        payload = b"public" + b"a" * 64 + b"visible"
        self.assertEqual(matcher.scan(io.BytesIO(payload), len(payload)), ())
        self.assertEqual(matcher.candidates_checked, 1)

    def test_changed_encoded_split_and_same_name_public_content_are_boundaries(self):
        import base64
        for data in (self.data.replace(b"37", b"38"), base64.b64encode(self.data),
                     self.data[:70] + b"\0" + self.data[70:], b"export const publicVersion = 1;\n"):
            with self.subTest(size=len(data)):
                self.assertEqual(self.matcher().scan(io.BytesIO(data), len(data)), ())

    def test_anchor_and_complete_content_cross_scan_chunks(self):
        chunk = 128 * 1024
        data = self.data + b"x" * (chunk + 103)
        for start in (chunk - 64, chunk - 63, chunk - 1, chunk, 2 * chunk - 17):
            with self.subTest(start=start):
                payload = b"p" * start + data + b"tail"
                matcher = self.matcher(data)
                self.assertEqual(matcher.scan(io.BytesIO(payload), len(payload)), (0,))
                self.assertEqual(matcher.candidates_checked, 1)

    def test_overlapping_candidates_do_not_skip_later_true_match(self):
        matcher = self.matcher(b"a" * 64 + b"b")
        payload = b"a" * 120 + b"b"
        self.assertEqual(matcher.scan(io.BytesIO(payload), len(payload)), (0,))
        self.assertEqual(matcher.candidates_checked, 57)

    def test_duplicate_references_share_work_and_preserve_all_rule_indexes(self):
        first = self.snapshot()
        second = self.snapshot(self.data[:-2] + b"different\n")
        matcher = PrivateContentScanner([first, first, second])
        payload = b"prefix" + self.data + b"tail" * 10
        self.assertEqual(matcher.scan(io.BytesIO(payload), len(payload)), (0, 1))
        self.assertEqual(matcher.candidates_checked, 2)
        self.assertEqual(matcher.verification_bytes, first.size + second.size)

    def test_already_matched_whole_payload_is_not_duplicated_or_charged(self):
        item = self.snapshot()
        matcher = PrivateContentScanner([item, item])
        stream = io.BytesIO(self.data)
        stream.seek(7)
        self.assertEqual(matcher.scan(stream, len(self.data), matched_indices=[0, 1]), ())
        self.assertEqual(stream.tell(), 7)
        self.assertEqual(matcher.candidates_checked, 0)
        self.assertEqual(matcher.verification_bytes, 0)
        self.assertEqual(matcher.scan(io.BytesIO(self.data), len(self.data), matched_indices=[0]), (1,))
        self.assertEqual(matcher.candidates_checked, 1)

    def test_64_distinct_references_return_correct_indexes(self):
        snapshots = [self.snapshot(bytes([index]) * 64 + b"private") for index in range(64)]
        matcher = PrivateContentScanner(snapshots)
        payload = b"public" + bytes([31]) * 64 + b"private" + bytes([63]) * 64 + b"private"
        self.assertEqual(matcher.scan(io.BytesIO(payload), len(payload)), (31, 63))

    def test_small_chunk_search_matches_independent_full_bytes_oracle(self):
        generator = random.Random(14000)
        for _ in range(50):
            originals = [generator.randbytes(generator.randrange(1, 150)) for _ in range(6)]
            snapshots = [self.snapshot(data) for data in originals]
            data = generator.randbytes(71) + originals[1] + generator.randbytes(89) + originals[4]
            expected = tuple(index for index, source in enumerate(originals) if source in data)
            with patch("releaseguard.private_inputs._CHUNK_BYTES", 73):
                self.assertEqual(PrivateContentScanner(snapshots).scan(io.BytesIO(data), len(data)), expected)

    def test_candidate_budget_is_global_exhaustion_is_latched_and_position_restored(self):
        matcher = self.matcher(b"a" * 64 + b"private")
        data = b"a" * 64 + b"visible"
        with patch("releaseguard.private_inputs.MAX_PRIVATE_CONTENT_CANDIDATES", 2):
            for _ in range(2):
                self.assertEqual(matcher.scan(io.BytesIO(data), len(data)), ())
            stream = io.BytesIO(data)
            stream.seek(5)
            with self.assertRaises(PrivateContentBudgetError) as caught:
                matcher.scan(stream, len(data))
            self.assertEqual(caught.exception.reason, "private_content_candidate_limit")
            self.assertEqual(stream.tell(), 5)
            self.assertEqual(matcher.candidates_checked, 2)
            with self.assertRaises(PrivateContentBudgetError):
                matcher.scan(io.BytesIO(b"clean"), 5)

    def test_actual_candidate_ceiling_bounds_dense_adversarial_anchors(self):
        matcher = self.matcher(b"a" * 64 + b"b")
        data = b"a" * (MAX_PRIVATE_CONTENT_CANDIDATES + 128)
        with self.assertRaises(PrivateContentBudgetError) as caught:
            matcher.scan(io.BytesIO(data), len(data))
        self.assertEqual(caught.exception.reason, "private_content_candidate_limit")
        self.assertEqual(matcher.candidates_checked, MAX_PRIVATE_CONTENT_CANDIDATES)
        self.assertEqual(matcher.verification_bytes, 65 * MAX_PRIVATE_CONTENT_CANDIDATES)

    def test_verification_budget_reserves_full_span_before_reading(self):
        data = b"a" * 64 + b"visible"
        matcher = self.matcher(b"a" * 64 + b"private")
        with patch("releaseguard.private_inputs.MAX_PRIVATE_CONTENT_VERIFY_BYTES", 2 * len(data)):
            for _ in range(2):
                self.assertEqual(matcher.scan(io.BytesIO(data), len(data)), ())
            with self.assertRaises(PrivateContentBudgetError) as caught:
                matcher.scan(io.BytesIO(data), len(data))
        self.assertEqual(caught.exception.reason, "private_content_verification_limit")
        self.assertEqual(matcher.verification_bytes, 2 * len(data))
        self.assertEqual(matcher.candidates_checked, 3)
        self.assertEqual(MAX_PRIVATE_CONTENT_VERIFY_BYTES, 512 * 1024 * 1024)

    def test_near_end_impossible_candidates_are_not_verified(self):
        data = b"a" * 1000000
        matcher = self.matcher(data[:-1] + b"b")
        self.assertEqual(matcher.scan(io.BytesIO(data), len(data)), ())
        self.assertEqual(matcher.candidates_checked, 1)

    def test_truncated_grown_and_io_error_streams_fail_closed_without_details(self):
        class Failed(io.BytesIO):
            def read(self, size=-1):
                raise OSError("sensitive external path must not escape")
        for stream, size in ((io.BytesIO(self.data), len(self.data) + 1),
                             (io.BytesIO(self.data), len(self.data) - 1),
                             (Failed(self.data), len(self.data))):
            with self.subTest(size=size):
                with self.assertRaises(GuardError) as caught:
                    self.matcher().scan(stream, size)
                self.assertNotIn("sensitive", str(caught.exception))

    def test_stream_shrinking_during_candidate_verification_is_rejected(self):
        class Shrinking(io.BytesIO):
            zero_seeks = 0
            def seek(self, offset, whence=0):
                if offset == 0 and whence == 0:
                    self.zero_seeks += 1
                    if self.zero_seeks == 2:
                        self.truncate(20)
                return super().seek(offset, whence)
        stream = Shrinking(self.data + b"tail")
        stream.seek(9)
        with self.assertRaisesRegex(GuardError, "changed"):
            self.matcher().scan(stream, len(self.data) + 4)
        self.assertEqual(stream.tell(), 9)

    def test_reference_change_is_rejected_by_publication_recheck(self):
        snapshot = self.snapshot()
        self.private.write_bytes(self.data + b"changed")
        matcher = PrivateContentScanner([snapshot])
        self.assertEqual(matcher.scan(io.BytesIO(self.data), len(self.data)), (0,))
        with self.assertRaises(GuardError):
            assert_private_inputs_unchanged([snapshot])

    def test_invalid_empty_anchors_and_unbounded_direct_arguments_are_rejected(self):
        item = self.snapshot()
        for invalid in (replace(item, anchor=b""), replace(item, size=0), replace(item, sha256="x" * 64)):
            with self.assertRaises(GuardError):
                PrivateContentScanner([invalid])
        matcher = PrivateContentScanner([item])
        for size, indices in ((True, ()), (-1, ()), (513 * 1024 * 1024, ()),
                              (len(self.data), (1,)), (len(self.data), (False,))):
            with self.assertRaises(GuardError):
                matcher.scan(io.BytesIO(self.data), size, matched_indices=indices)

    def test_scanner_never_executes_declared_source_or_public_payload(self):
        marker = self.base / "must-not-execute"
        source = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n".encode()
        payload = b"# wrapper\n" + source
        self.assertEqual(self.matcher(source).scan(io.BytesIO(payload), len(payload)), (0,))
        self.assertFalse(marker.exists())
