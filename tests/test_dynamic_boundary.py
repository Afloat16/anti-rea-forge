"""Exercise the own-fixture authorization benchmark without claiming REA coverage."""

from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization

from releaseguard.core import GuardError


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "benchmarks" / "dynamic_boundary.py"
SPEC = importlib.util.spec_from_file_location("_dynamic_boundary_benchmark", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
boundary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boundary)


class DynamicBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()

    def test_real_capability_server_controls_and_persistent_concurrent_replay(self) -> None:
        report = boundary.experiment()
        self.assertTrue(report["experiment_completed"], report)
        self.assertTrue(report["all_functional_checks_passed"])
        self.assertEqual(report["handler_calls_total"], 3)
        cases = report["cases"]
        for name in ["patched_boolean_missing_capability", "patched_boolean_forged_capability",
                     "swapped_request", "persistent_replay_after_reopen",
                     "persistent_replay_after_concurrent_use"]:
            with self.subTest(case=name):
                self.assertFalse(cases[name]["accepted"])
                self.assertEqual(cases[name]["handler_calls_added"], 0)
        valid = cases["valid_bound_request_after_rejected_swap"]
        self.assertTrue(valid["accepted"])
        self.assertEqual(valid["handler_calls_added"], 1)
        concurrent = cases["concurrent_replay"]
        self.assertGreaterEqual(concurrent["attempts"], 32)
        self.assertEqual((concurrent["accepted"], concurrent["rejected"]), (1, concurrent["attempts"] - 1))
        self.assertEqual(concurrent["handler_calls_added"], 1)
        self.assertEqual(concurrent["independent_store_instances"], concurrent["attempts"])
        delegated = cases["active_delegated_rights_remain_usable"]
        self.assertFalse(delegated["client_authorized_boolean"])
        self.assertTrue(delegated["accepted"])

    def test_report_does_not_export_tokens_signatures_identifiers_or_private_keys(self) -> None:
        original = boundary.issue_capability
        issued = []
        key_material = []
        def capture_own_fixture(private, **kwargs):
            document = original(private, **kwargs)
            issued.append(document)
            key_material.append(private.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ))
            return document
        with patch.object(boundary, "issue_capability", capture_own_fixture):
            report = boundary.experiment()
        self.assertTrue(report["all_functional_checks_passed"], report)
        raw = json.dumps(report, sort_keys=True)
        self.assertGreaterEqual(len(issued), 4)
        for document in issued:
            self.assertNotIn(document["signature"], raw)
            self.assertNotIn(document["claims"]["jti"], raw)
            self.assertNotIn(json.dumps(document, sort_keys=True), raw)
        for key in key_material:
            self.assertNotIn(key.hex(), raw)

    def test_report_explicitly_limits_the_observed_boundary(self) -> None:
        report = boundary.experiment()
        for field in ["rea_evaluated", "frida_evaluated", "native_instrumentation_evaluated",
                      "network_tls_deployment_evaluated", "tee_evaluated"]:
            self.assertIs(report[field], False)
        self.assertTrue(report["client_boolean_patch_is_simulated"])
        self.assertEqual(report["scope"], "synthetic_server_authorization_functional_controls_only")
        notes = " ".join(report["notes"]).lower()
        for phrase in ["active authorized session", "exactly-once business effects", "rollback",
                       "not a rea or frida run", "no network, tls, tee"]:
            self.assertIn(phrase, notes)

    def test_unexpected_dependency_failure_is_unknown_and_sanitized(self) -> None:
        marker = "private-token-and-sql-parameters-MUST-NOT-EXPORT"
        with patch.object(boundary.ReplayStore, "create", side_effect=GuardError(marker)):
            report = boundary.experiment()
        self.assertFalse(report["experiment_completed"])
        self.assertIsNone(report["all_functional_checks_passed"])
        self.assertEqual(report["error_type"], "GuardError")
        self.assertNotIn(marker, json.dumps(report))

    def test_unexpected_consumer_exception_is_not_counted_as_expected_denial(self) -> None:
        marker = "private-capability-in-unexpected-exception"
        with patch.object(boundary, "consume_capability", side_effect=RuntimeError(marker)):
            report = boundary.experiment()
        self.assertFalse(report["experiment_completed"])
        self.assertIsNone(report["all_functional_checks_passed"])
        self.assertEqual(report["error_type"], "RuntimeError")
        self.assertNotIn(marker, json.dumps(report))

    def test_unexpected_acceptance_cannot_be_reported_as_success(self) -> None:
        with patch.object(boundary, "_attempt", return_value=True):
            report = boundary.experiment()
        self.assertFalse(report["experiment_completed"])
        self.assertIs(report["all_functional_checks_passed"], False)
        self.assertTrue(report["cases"]["patched_boolean_missing_capability"]["accepted"])

    def test_fixture_database_is_automatically_removed(self) -> None:
        original = boundary.tempfile.TemporaryDirectory
        created = []
        def temporary_fixture(*args, **kwargs):
            own_fixture = kwargs.get("prefix") == "rg-dynamic-boundary-"
            if own_fixture:
                kwargs["dir"] = self.base
            temporary = original(*args, **kwargs)
            if own_fixture:
                created.append(Path(temporary.name))
            return temporary
        with patch.object(boundary.tempfile, "TemporaryDirectory", temporary_fixture):
            report = boundary.experiment()
        self.assertTrue(report["experiment_completed"], report)
        self.assertEqual(len(created), 1)
        self.assertFalse(created[0].exists())

    def cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments], cwd=self.base,
            env=dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1"),
            capture_output=True, text=True, timeout=30,
        )

    def test_cli_defaults_to_json_and_never_overwrites_output(self) -> None:
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["all_functional_checks_passed"])
        self.assertEqual(result.stderr, "")
        destination = self.base / "boundary.json"
        result = self.cli("--out", str(destination))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        original = destination.read_bytes()
        self.assertTrue(json.loads(original)["experiment_completed"])
        result = self.cli("--out", str(destination))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(destination.read_bytes(), original)
        self.assertNotIn("Traceback", result.stderr)

    def test_cli_error_exit_for_incomplete_experiment(self) -> None:
        destination = self.base / "incomplete.json"
        with patch.object(boundary.ReplayStore, "create", side_effect=GuardError("private-detail")):
            self.assertEqual(boundary.main(["--out", str(destination)]), 2)
        report = json.loads(destination.read_text())
        self.assertFalse(report["experiment_completed"])
        self.assertNotIn("private-detail", destination.read_text())

    def test_help_explains_simulation_without_running_experiment(self) -> None:
        output = io.StringIO()
        with patch.object(boundary, "experiment", side_effect=AssertionError("Help must not execute fixtures")):
            with redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
                boundary.main(["--help"])
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn("NOT a REA, Frida", " ".join(output.getvalue().split()))


if __name__ == "__main__":
    unittest.main()
