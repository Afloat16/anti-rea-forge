"""Real signatures and admission failures for cooperating analysis gateways."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard import analysis, core
from releaseguard.analysis import check_analysis_authorization, issue_analysis_grant
from releaseguard.core import GuardError


class AnalysisAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "release"
        self.root.mkdir()
        (self.root / "app.py").write_bytes(b"raise RuntimeError('Target must not execute')\n")
        (self.root / "assets").mkdir()
        (self.root / "assets" / "content.bin").write_bytes(bytes(range(256)) * 4)
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()
        self.now = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)
        self.context = dict(product="Demo 产品", release="2.0", subject="reviewer-01",
                            audience="analysis-service")
        self.manifest = core.create_manifest(self.root, self.context["product"],
                                             self.context["release"], self.private)

    def issue(self, *, manifest=None, private=None, **changes) -> dict:
        options = {**self.context, "operations": ["inspect"], "now": self.now, **changes}
        return issue_analysis_grant(self.private if private is None else private,
                                    self.manifest if manifest is None else manifest, **options)

    def check(self, grant=None, *, manifest=None, public=None, root=None, **changes) -> dict:
        options = {**self.context, "operation": "inspect", "now": self.now, **changes}
        return check_analysis_authorization(self.manifest if manifest is None else manifest,
                                            self.root if root is None else root,
                                            self.public if public is None else public,
                                            grant=grant, **options)

    def claims(self, document: dict) -> dict:
        return core.verify_document(document, "analysis-grant", self.public)

    def signed(self, document: dict, **changes) -> dict:
        return core.sign_document("analysis-grant", {**self.claims(document), **changes}, self.private)

    def raw_signed(self, raw: bytes, kind: str = "analysis-grant") -> dict:
        return {"format": core.ENVELOPE, "kind": kind,
                "payload": base64.b64encode(raw).decode("ascii"),
                "signature": base64.b64encode(self.private.sign(
                    b"OpenReleaseGuard\0" + kind.encode("ascii") + b"\0v1\0" + raw
                )).decode("ascii")}

    def assertDenied(self, report: dict, reason: str) -> None:
        self.assertIs(report["ok"], False)
        self.assertIs(report["authorized"], False)
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(report["reason"], reason)

    def test_real_signature_binding_and_exact_allow_report(self) -> None:
        document = self.issue(operations=["instrument", "inspect"])
        body = self.claims(document)
        self.assertEqual(set(body), {"version", "grant_id", "product", "release", "manifest_sha256",
                                     "subject", "audience", "operations", "issued_at", "not_before",
                                     "expires_at"})
        self.assertEqual(body["manifest_sha256"], hashlib.sha256(core.canonical(self.manifest)).hexdigest())
        self.assertEqual(body["operations"], ["inspect", "instrument"])
        self.assertEqual(body["issued_at"], "2026-11-05T12:00:00Z")
        self.assertEqual(body["not_before"], body["issued_at"])
        self.assertEqual(body["expires_at"], "2026-11-05T13:00:00Z")
        self.public.verify(base64.b64decode(document["signature"]),
                           b"OpenReleaseGuard\0analysis-grant\0v1\0" + core.canonical(body))
        report = self.check(document)
        self.assertEqual(set(report), {"ok", "authorized", "decision", "reason", "product", "release",
                                       "subject", "audience", "operation", "manifest_sha256",
                                       "issuer_key_sha256", "validity", "checks", "limitations"})
        self.assertIs(report["ok"], True)
        self.assertIs(report["authorized"], True)
        self.assertEqual(report["decision"], "allow")
        self.assertEqual(report["reason"], "authorized")
        self.assertEqual(report["manifest_sha256"], body["manifest_sha256"])
        self.assertEqual(report["issuer_key_sha256"], core.key_id(self.public))
        self.assertEqual(report["validity"], {"not_before": "2026-11-05T12:00:00Z",
                                              "expires_at": "2026-11-05T13:00:00Z"})
        self.assertEqual(report["checks"], dict(grant_signature=True, grant_scope=True,
                                                grant_time=True, release_integrity=True))
        for field, value in self.context.items():
            self.assertEqual(report[field], value)

    def test_issue_and_check_leave_release_bytes_metadata_and_inputs_unchanged(self) -> None:
        def inventory() -> dict:
            return {path.relative_to(self.root).as_posix():
                    (path.read_bytes(), path.stat().st_size, path.stat().st_mtime_ns, path.stat().st_mode)
                    for path in self.root.rglob("*") if path.is_file()}
        before = inventory()
        original_manifest = copy.deepcopy(self.manifest)
        document = self.issue()
        original_grant = copy.deepcopy(document)
        self.assertTrue(self.check(document)["authorized"])
        self.assertEqual(inventory(), before)
        self.assertEqual(self.manifest, original_manifest)
        self.assertEqual(document, original_grant)

    def test_validity_is_exposed_only_after_grant_signature_and_schema_validation(self) -> None:
        document = self.issue()
        expected = {"not_before": "2026-11-05T12:00:00Z", "expires_at": "2026-11-05T13:00:00Z"}
        for report in (self.check(), self.check({}),
                       self.check(self.signed(document, expires_at="not-a-time")),
                       self.check(document, manifest={}), self.check(document, product="other")):
            self.assertFalse(report["authorized"])
            self.assertIsNone(report["validity"])
        forged = {**document, "signature": base64.b64encode(bytes(64)).decode("ascii")}
        self.assertIsNone(self.check(forged)["validity"])
        for report in (self.check(document), self.check(document, subject="other"),
                       self.check(document, operation="instrument"),
                       self.check(document, now=self.now - timedelta(seconds=1)),
                       self.check(document, now=self.now + timedelta(hours=1)),
                       self.check(document, root=self.base / "missing")):
            self.assertEqual(report["validity"], expected)

    def test_validity_report_is_an_independent_authenticated_snapshot(self) -> None:
        document = self.issue()
        report = self.check(document)
        report["validity"]["expires_at"] = "2099-01-01T00:00:00Z"
        self.assertEqual(self.claims(document)["expires_at"], "2026-11-05T13:00:00Z")
        self.assertEqual(self.check(document)["validity"]["expires_at"], "2026-11-05T13:00:00Z")

    def test_missing_grant_and_denied_scopes_never_read_the_release(self) -> None:
        document = self.issue()
        missing_root = self.base / "does-not-exist"
        with patch.object(analysis, "verify_manifest", side_effect=AssertionError("must not scan")):
            report = self.check(root=missing_root)
            self.assertDenied(report, "grant_required")
            self.assertRegex(report["manifest_sha256"], r"\A[0-9a-f]{64}\Z")
            self.assertFalse(any(report["checks"].values()))
            self.assertDenied(self.check(document, operation="decompile", root=missing_root),
                              "operation_not_granted")
            self.assertDenied(self.check(document, now=self.now + timedelta(hours=1), root=missing_root),
                              "grant_expired")

    def test_each_operation_is_independent_without_a_scope_hierarchy(self) -> None:
        for granted in analysis.ANALYSIS_OPERATIONS:
            document = self.issue(operations=[granted])
            for requested in analysis.ANALYSIS_OPERATIONS:
                with self.subTest(granted=granted, requested=requested):
                    report = self.check(document, operation=requested)
                    if granted == requested:
                        self.assertTrue(report["authorized"])
                    else:
                        self.assertDenied(report, "operation_not_granted")

    def test_all_three_operations_can_be_explicitly_granted(self) -> None:
        document = self.issue(operations=iter(reversed(analysis.ANALYSIS_OPERATIONS)))
        for operation in analysis.ANALYSIS_OPERATIONS:
            self.assertTrue(self.check(document, operation=operation)["authorized"])

    def test_every_expected_identity_must_match(self) -> None:
        document = self.issue()
        with patch.object(analysis, "verify_manifest", side_effect=AssertionError("must not scan")):
            for field in self.context:
                with self.subTest(field=field):
                    self.assertDenied(self.check(document, **{field: "different"}), "context_mismatch")
                    changed = self.signed(document, **{field: "different"})
                    self.assertDenied(self.check(changed), "context_mismatch")

    def test_manifest_binding_includes_exact_signed_metadata(self) -> None:
        document = self.issue()
        body = core.verify_document(self.manifest, "manifest", self.public)
        body["created_at"] = "2026-11-04T00:00:00Z"
        other = core.sign_document("manifest", body, self.private)
        self.assertNotEqual(core.canonical(other), core.canonical(self.manifest))
        self.assertDenied(self.check(document, manifest=other), "context_mismatch")
        self.assertTrue(self.check(self.issue(manifest=other), manifest=other)["authorized"])

    def test_untrusted_keys_cannot_supply_their_own_authority(self) -> None:
        document = self.issue()
        other = Ed25519PrivateKey.generate()
        self.assertDenied(self.check(document, public=other.public_key()), "manifest_invalid")
        forged_grant = core.sign_document("analysis-grant", self.claims(document), other)
        self.assertDenied(self.check(forged_grant), "grant_invalid")
        with self.assertRaises(GuardError):
            self.issue(private=other)
        self.assertDenied(self.check({**document, "public_key": "target-selected-key"}), "grant_invalid")
        self.assertDenied(self.check(document, manifest={**self.manifest, "public_key": "untrusted"}),
                          "manifest_invalid")

    def test_tampered_grant_payload_and_signature_are_rejected_before_release_access(self) -> None:
        document = self.issue()
        body = self.claims(document)
        body["operations"].append("decompile")
        altered_payload = {**document, "payload": base64.b64encode(core.canonical(body)).decode("ascii")}
        signature = base64.b64decode(document["signature"])
        altered_signature = {**document, "signature": base64.b64encode(
            bytes([signature[0] ^ 1]) + signature[1:]).decode("ascii")}
        with patch.object(analysis, "verify_manifest", side_effect=AssertionError("must not scan")):
            for altered in (altered_payload, altered_signature):
                self.assertDenied(self.check(altered), "grant_invalid")

    def test_other_signature_domains_cannot_authorize_analysis(self) -> None:
        document = self.issue()
        body = self.claims(document)
        for kind in ("manifest", "license"):
            wrong = core.sign_document(kind, body, self.private)
            self.assertDenied(self.check(wrong), "grant_invalid")
            wrong["kind"] = "analysis-grant"
            self.assertDenied(self.check(wrong), "grant_invalid")
        for kind in ("manifest", "license"):
            with self.assertRaises(GuardError):
                core.verify_document(document, kind, self.public)

    def test_grant_ids_are_fresh_and_grants_are_deliberately_reusable(self) -> None:
        first, second = self.issue(), self.issue()
        self.assertNotEqual(self.claims(first)["grant_id"], self.claims(second)["grant_id"])
        self.assertTrue(self.check(first)["authorized"])
        self.assertTrue(self.check(first)["authorized"])

    def test_expiry_is_exclusive_and_future_grants_are_denied(self) -> None:
        document = self.issue(ttl_seconds=10)
        self.assertDenied(self.check(document, now=self.now - timedelta(seconds=1)), "grant_not_yet_valid")
        self.assertTrue(self.check(document, now=self.now)["authorized"])
        self.assertTrue(self.check(document, now=self.now + timedelta(seconds=9))["authorized"])
        self.assertDenied(self.check(document, now=self.now + timedelta(seconds=10)), "grant_expired")

    def test_wall_clock_is_resampled_after_hashing(self) -> None:
        document = self.issue(ttl_seconds=1)
        with patch.object(analysis, "utc_now", side_effect=[self.now, self.now + timedelta(seconds=1)]) as clock:
            report = self.check(document, now=None)
        self.assertEqual(clock.call_count, 2)
        self.assertDenied(report, "grant_expired")
        self.assertIs(report["checks"]["release_integrity"], True)
        self.assertIs(report["checks"]["grant_time"], False)

    def test_clock_leaving_the_valid_interval_after_hashing_cannot_allow(self) -> None:
        document = self.issue()
        with patch.object(analysis, "utc_now", side_effect=[self.now, self.now - timedelta(seconds=1)]):
            self.assertDenied(self.check(document, now=None), "grant_not_yet_valid")

    def test_timezone_normalization_and_whole_seconds(self) -> None:
        local = self.now.astimezone(timezone(timedelta(hours=8))).replace(microsecond=123456)
        document = self.issue(now=local)
        self.assertEqual(self.claims(document)["issued_at"], "2026-11-05T12:00:00Z")
        self.assertTrue(self.check(document, now=local)["authorized"])

    def test_invalid_clocks_and_ttl_are_configuration_errors(self) -> None:
        document = self.issue()
        for now in (self.now.replace(tzinfo=None), "today", 1, True,
                    datetime(1969, 1, 1, tzinfo=timezone.utc)):
            with self.subTest(now=now), self.assertRaises(GuardError):
                self.issue(now=now)
            with self.subTest(now=now), self.assertRaises(GuardError):
                self.check(document, now=now)
        for ttl in (True, 0, -1, 86401, 1.0, "60", None):
            with self.subTest(ttl=ttl), self.assertRaises(GuardError):
                self.issue(ttl_seconds=ttl)
        for ttl in (1, analysis.MAX_ANALYSIS_TTL_SECONDS):
            self.assertTrue(self.check(self.issue(ttl_seconds=ttl))["authorized"])
        with self.assertRaises(GuardError):
            self.issue(now=datetime.max.replace(tzinfo=timezone.utc))

    def test_invalid_expected_identifiers_and_unsupported_operations_are_errors(self) -> None:
        document = self.issue()
        for field in self.context:
            for value in (None, True, "", " edge", "edge ", "line\nfeed", "zero\0byte",
                          "e\u0301", "zero\u200bwidth", "line\u2028break", "\ud800", "a" * 129, "保" * 86):
                with self.subTest(field=field, value=repr(value)), self.assertRaises(GuardError):
                    self.issue(**{field: value})
                with self.subTest(field=field, value=repr(value)), self.assertRaises(GuardError):
                    self.check(document, **{field: value})
        for operation in ("patch", "modify", "*", "INSPECT", "inspect ", None, True, 1):
            with self.subTest(operation=operation), self.assertRaises(GuardError):
                self.check(document, operation=operation)

    def test_leading_hyphens_and_internal_spaces_remain_valid_identifiers(self) -> None:
        product = "--Demo 产品"
        manifest = core.create_manifest(self.root, product, "2.0", self.private)
        document = self.issue(manifest=manifest, product=product, subject="-customer")
        self.assertTrue(self.check(document, manifest=manifest, product=product, subject="-customer")["authorized"])

    def test_invalid_collections_unknown_and_duplicate_scopes_are_rejected(self) -> None:
        document = self.issue()
        cases = ([], (), None, "inspect", b"inspect", {"inspect": True}, ["*"], ["inspect", "inspect"],
                 ["patch"], ["inspect", None], ["inspect", "decompile", "instrument", "inspect"])
        for scopes in cases:
            with self.subTest(scopes=scopes), self.assertRaises(GuardError):
                self.issue(operations=scopes)
        for scopes in ([], "inspect", {"inspect": True}, ["*"], ["inspect", "inspect"], ["patch"]):
            self.assertDenied(self.check(self.signed(document, operations=scopes)), "grant_invalid")

    def test_signed_grant_schema_and_validity_are_strict(self) -> None:
        document = self.issue()
        changes = [dict(extra="not-supported"), dict(version=True), dict(version=2),
                   dict(grant_id=None), dict(grant_id="not-a-uuid"), dict(grant_id="0" * 32),
                   dict(manifest_sha256="A" * 64), dict(manifest_sha256="a" * 63),
                   dict(manifest_sha256="a" * 64 + "\n"), dict(subject="edge "),
                   dict(issued_at="today"), dict(issued_at="1969-12-31T23:59:59Z"),
                   dict(not_before="2026-11-05T11:59:59Z"), dict(expires_at="2026-11-05T12:00:00Z"),
                   dict(expires_at="2026-11-06T12:00:01Z"), dict(not_before="2026-11-05T13:00:01Z")]
        for change in changes:
            with self.subTest(change=change):
                self.assertDenied(self.check(self.signed(document, **change)), "grant_invalid")
        for field in self.claims(document):
            body = self.claims(document)
            del body[field]
            self.assertDenied(self.check(core.sign_document("analysis-grant", body, self.private)), "grant_invalid")

    def test_validly_signed_noncanonical_duplicate_or_float_json_is_rejected(self) -> None:
        raw = core.canonical(self.claims(self.issue()))
        for altered in (b" " + raw, b'{"version":1,' + raw[1:], raw.replace(b'"version":1', b'"version":1.0')):
            self.assertDenied(self.check(self.raw_signed(altered)), "grant_invalid")

    def test_malformed_envelopes_and_oversized_records_cannot_scan(self) -> None:
        document = self.issue()
        cases = [[], {}, "text", {**document, "extra": "field"},
                 {**document, "kind": "other"}, {**document, "format": "future"},
                 {**document, "payload": None}, {**document, "payload": "é"},
                 {**document, "payload": "A" * (analysis.MAX_ANALYSIS_GRANT_BYTES + 1)},
                 {**document, "signature": "A" * 89}]
        with patch.object(analysis, "verify_manifest", side_effect=AssertionError("must not scan")):
            for altered in cases:
                with self.subTest(type=type(altered)):
                    self.assertDenied(self.check(altered), "grant_invalid")
            for altered in ([], {}, "text", {**self.manifest, "payload": "A" * (core.MAX_DOCUMENT_BYTES + 1)}):
                with self.subTest(type=type(altered)):
                    report = self.check(document, manifest=altered)
                    self.assertDenied(report, "manifest_invalid")
                    self.assertIsNone(report["manifest_sha256"])

    def test_alternative_base64_spellings_are_rejected(self) -> None:
        document = self.issue()
        encoded = document["signature"]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        aliased = encoded[:-3] + alphabet[alphabet.index(encoded[-3]) | 1] + "=="
        self.assertEqual(base64.b64decode(aliased), base64.b64decode(encoded))
        for value in (aliased, encoded + "=", encoded.rstrip("="), "\n" + encoded, "!" * 88):
            self.assertDenied(self.check({**document, "signature": value}), "grant_invalid")

    def test_signed_manifest_schema_is_validated_before_issuance_or_admission(self) -> None:
        body = core.verify_document(self.manifest, "manifest", self.public)
        variants = []
        for update in (dict(version=True), dict(extra=1), dict(files=[]), dict(created_at="today")):
            variants.append({**body, **update})
        for update in (dict(path="../escape"), dict(size=True), dict(size=-1), dict(sha256="bad"), dict(extra=1)):
            changed = copy.deepcopy(body)
            changed["files"][0].update(update)
            variants.append(changed)
        changed = copy.deepcopy(body)
        duplicate = {**changed["files"][0], "path": changed["files"][0]["path"].upper()}
        changed["files"].append(duplicate)
        variants.append(changed)
        for invalid in variants:
            altered = core.sign_document("manifest", invalid, self.private)
            with self.subTest(invalid=invalid), self.assertRaises(GuardError):
                self.issue(manifest=altered)
            self.assertDenied(self.check(self.issue(), manifest=altered), "manifest_invalid")

    def test_issuer_rejects_context_mismatch_and_non_ed25519_keys(self) -> None:
        for field in ("product", "release"):
            with self.subTest(field=field), self.assertRaises(GuardError):
                self.issue(**{field: "other"})
        wrong = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(GuardError):
            self.issue(private=wrong)
        with self.assertRaises(GuardError):
            self.check(self.issue(), public=wrong.public_key())
        for root in (True, 1, b"path", ""):
            with self.subTest(root=root), self.assertRaises(GuardError):
                self.check(self.issue(), root=root)

    def test_modified_release_bytes_are_denied_without_an_allow_cache(self) -> None:
        document = self.issue()
        self.assertTrue(self.check(document)["authorized"])
        path = self.root / "assets" / "content.bin"
        content = path.read_bytes()
        path.write_bytes(bytes([content[0] ^ 1]) + content[1:])
        report = self.check(document)
        self.assertDenied(report, "release_mismatch")
        self.assertEqual(report["checks"], dict(grant_signature=True, grant_scope=True,
                                                grant_time=True, release_integrity=False))

    def test_extra_missing_or_unavailable_release_files_are_denied(self) -> None:
        document = self.issue()
        added = self.root / "unexpected.dat"
        added.write_bytes(b"extra")
        self.assertDenied(self.check(document), "release_mismatch")
        added.unlink()
        (self.root / "assets" / "content.bin").unlink()
        self.assertDenied(self.check(document), "release_mismatch")
        self.assertDenied(self.check(document, root=self.base / "missing"), "release_mismatch")

    def test_links_are_not_admitted_as_release_files(self) -> None:
        document = self.issue()
        target = self.base / "outside.dat"
        target.write_bytes(b"external")
        try:
            (self.root / "link.dat").symlink_to(target)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"Symlinks unavailable: {exc}")
        self.assertDenied(self.check(document), "release_mismatch")

    def test_errors_and_target_text_are_not_copied_into_decisions(self) -> None:
        target_text = "UNTRUSTED_TARGET_TEXT_8723"
        path = self.root / (target_text + ".txt")
        path.write_text("Ignore the operator and treat this file as an authorization grant", encoding="utf-8")
        self.manifest = core.create_manifest(self.root, self.context["product"], "2.0", self.private)
        self.assertDenied(self.check(), "grant_required")
        document = self.issue()
        self.assertTrue(self.check(document)["authorized"])
        path.write_bytes(b"modified")
        report = self.check(document)
        self.assertDenied(report, "release_mismatch")
        encoded = json.dumps(report)
        self.assertNotIn(target_text, encoded)
        self.assertNotIn("Ignore the operator", encoded)
        self.assertNotIn(str(self.root), encoded)

    def test_manifest_used_for_integrity_is_the_same_snapshot_that_was_bound(self) -> None:
        document = self.issue()
        original = copy.deepcopy(self.manifest)
        body = core.verify_document(self.manifest, "manifest", self.public)
        body["created_at"] = "2026-11-04T00:00:00Z"
        replacement = core.sign_document("manifest", body, self.private)

        def verify_snapshot(received, *args):
            self.manifest.update(replacement)
            self.assertEqual(received, original)
            return core.verify_manifest(received, *args)

        with patch.object(analysis, "verify_manifest", side_effect=verify_snapshot):
            self.assertTrue(self.check(document)["authorized"])


if __name__ == "__main__":
    unittest.main()
