"""Human reports preserve decisions, boundaries and terminal-safe locations."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from releaseguard import cli
from releaseguard.core import GuardError
from releaseguard.distribution import scan_release
from releaseguard.reporting import render_text_error, render_text_report


class ReportingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="human report ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.root = self.work / "public"
        self.root.mkdir()
        (self.root / "client.js").write_bytes(b"export {};\n")
        self.policy = self.work / "policy.json"
        self.policy.write_text('{"version":1}', encoding="utf-8")

    def scan(self):
        return scan_release(self.root, self.policy)

    def test_unknown_code_is_visible_and_arbitrary_extra_fields_are_not_rendered(self):
        report = self.scan()
        report["ok"] = False
        report["findings"] = [{"code": "future_finding", "path": "payload.bin",
                               "private_path": "/private/source.py", "matched_bytes": "PRIVATE-MATERIAL"}]
        text = render_text_report("check", report)
        self.assertIn("BLOCKED (exit 3)", text)
        self.assertIn('"future_finding"', text)
        self.assertIn("Keep publication blocked", text)
        self.assertNotIn("/private/source.py", text)
        self.assertNotIn("PRIVATE-MATERIAL", text)

    def test_all_dynamic_locations_and_details_escape_terminal_and_bidi_controls(self):
        marker = "\x1b[2J\r\n\u202e\u2066"
        report = self.scan()
        report["ok"] = False
        report["root"] += marker
        report["findings"] = [{"code": "unknown" + marker, "path": "payload" + marker,
                               "archive_members": ["outer" + marker, "inner" + marker],
                               "reason": "reason" + marker, "rule_index": 0}]
        text = render_text_report("prepare", {"ok": False, "prepared": False, "scan": report,
                                              "outputs": {"manifest.json": "output" + marker}})
        for control in ("\x1b", "\r", "\u202e", "\u2066"):
            self.assertNotIn(control, text)
        for escaped in ("\\u001b", "\\r", "\\n", "\\u202e", "\\u2066"):
            self.assertIn(escaped, text)
        self.assertIn("rule_index=0", text)

    def test_disabled_checks_and_incomplete_private_inputs_are_distinct(self):
        self.policy.write_text(json.dumps({"version": 1, "check_source_maps": False,
                                          "check_private_keys": False, "check_native_metadata": False}),
                               encoding="utf-8")
        report = self.scan()
        report["ok"] = False
        report["checks"].update(private_inputs_checked=1, private_input_scan_completed=False,
                                 private_input_profile="exact-content/v1")
        report["findings"] = [{"code": "private_input_unverifiable", "path": "payload.bin",
                               "reason": "candidate_budget_exceeded"}]
        text = render_text_report("check", report)
        self.assertIn("Private inputs: INCOMPLETE", text)
        self.assertIn("Source maps: disabled by policy", text)
        self.assertIn("Native metadata: disabled by policy", text)
        self.assertIn("Structured secrets: disabled by policy", text)
        self.assertIn("Asset keys: 0 (not configured)", text)
        self.assertIn("PYC asset keys: not configured", text)
        self.assertIn("every required reference before publishing", text)

    def test_errors_escape_details_and_do_not_reflect_os_private_paths(self):
        detail = "private input \x1b[2J\n\u202e"
        text = render_text_error("check", GuardError(detail))
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)
        self.assertIn("relative to project.json", text)
        text = render_text_error("prepare", FileNotFoundError(2, "missing", "/private/issuer-key.pem"))
        self.assertNotIn("issuer-key", text)
        self.assertIn("ERROR (exit 2)", text)

    def test_cancelled_cli_retains_stdout_stderr_and_exit_contract_in_both_formats(self):
        for output_format in ("json", "text"):
            for exception in (KeyboardInterrupt, EOFError):
                with self.subTest(format=output_format, exception=exception.__name__):
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with patch("releaseguard.cli._run", side_effect=exception), redirect_stdout(stdout), redirect_stderr(stderr):
                        code = cli.main(["check", "--format", output_format])
                    self.assertEqual(code, 130)
                    self.assertEqual(stdout.getvalue(), "")
                    if output_format == "json":
                        self.assertEqual(json.loads(stderr.getvalue()), {"ok": False, "error": "Operation cancelled"})
                    else:
                        self.assertIn("CANCELLED (exit 130)", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
