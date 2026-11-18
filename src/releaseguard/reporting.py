"""Optional, terminal-safe explanations for the existing portable scan reports.

The scanner owns all decisions. These renderers neither inspect files nor alter
the JSON protocol, findings or exit codes. Only allowlisted public report fields
are displayed; private reference objects and arbitrary finding fields are never
rendered. Dynamic strings use ASCII JSON quoting, including control/Bidi text.
"""

from __future__ import annotations

import json
import os
from typing import Any


# Titles and next steps are fixed text. Do not insert matched values, private
# reference paths or policy literals into these explanations.
_DIAGNOSTICS: dict[str, tuple[str, str]] = {
    "private_input_exposure": (
        "Declared private input is present in the public release",
        "Remove the private implementation or data from the public build and its packages; "
        "keep it in the private service or build environment, then rerun the check.",
    ),
    "private_input_unverifiable": (
        "Private-input inspection did not complete",
        "Review the reported budget reason and the documented private-input limits. "
        "Reduce unnecessary public payloads or use a supported release layout, then rerun "
        "every required reference before publishing.",
    ),
    "asset_key_exposure": (
        "A declared external asset key is present in the release",
        "Remove the key and its encoded or derived storage from the public build; obtain it "
        "through the trusted external key flow. Rotate a key that has already been distributed.",
    ),
    "private_key_marker": (
        "Private-key material may be present",
        "Inspect the flagged public file locally, remove private keys from the build and "
        "rebuild. Rotate any private key that has already been distributed.",
    ),
    "private_key_structure": (
        "A supported private-key structure is present",
        "Keep signing and decryption keys outside the release; distribute only the required "
        "public material, rebuild, and rotate any private key already distributed.",
    ),
    "native_token_exposure": (
        "A native bearer-token pattern is present",
        "Keep usable unlock tokens outside the public build and obtain them through the "
        "trusted token flow; replace any token that has already been distributed.",
    ),
    "structured_secret_unverifiable": (
        "Structured secret inspection did not complete",
        "Review the reason and format in the JSON report, then fix malformed, unsupported "
        "or over-budget input using the documented JSON, DER or PYC profile and rerun.",
    ),
    "source_map_marker": (
        "A source-map reference or embedded source marker is present",
        "Keep debug maps outside the public build. Use split-source-maps for supported "
        "external maps; rebuild without inline maps or public sourceMappingURL directives.",
    ),
    "source_map_structure": (
        "A source-map structure is present",
        "Move supported external maps into private debug storage with split-source-maps; "
        "rebuild inline or bundled maps out of the public artifact, then rerun.",
    ),
    "source_map_unverifiable": (
        "Source-map inspection did not complete",
        "Fix the malformed or over-budget map-like input and keep debug maps privately. "
        "Rerun until the configured inspection completes.",
    ),
    "native_debug_metadata": (
        "Native debug metadata is present",
        "Separate debug information before packaging. Use split-elf-debug or split-wasm-debug "
        "for supported inputs, or your platform's build tools, then scan the public output.",
    ),
    "native_symbol_table": (
        "A private or static native symbol table is present",
        "Produce a public artifact without private/static symbols using the supported "
        "debug-splitting workflow or platform build tools; retain required runtime exports.",
    ),
    "native_compiler_metadata": (
        "Embedded compiler metadata is present",
        "Disable embedded IR or compiler records in the public build and retain those "
        "artifacts privately; rebuild the final machine-code artifact and rerun.",
    ),
    "native_metadata_unverifiable": (
        "Native metadata inspection did not complete",
        "Review the reason and format, separate standalone debug/compiler files into "
        "private storage, and rebuild a supported inspectable public artifact before rerunning.",
    ),
    "forbidden_extension": (
        "A file extension is forbidden by the release policy",
        "Move private build/debug files outside the release and fix the packaging inputs. "
        "Review intentional public files against your trusted release policy.",
    ),
    "forbidden_path_component": (
        "A path component is forbidden by the release policy",
        "Exclude repository metadata, environment files and other private directories from "
        "the build/package inputs, then rebuild and rerun.",
    ),
    "forbidden_literal": (
        "A configured private literal is present",
        "Review the indexed forbid_literals rule in the private policy and remove its "
        "value from the public build, including supported encoded copies, then rerun.",
    ),
    "forbidden_file_digest": (
        "An explicitly forbidden file copy is present",
        "Review the indexed forbid_file_sha256 rule and exclude the matching file from "
        "the public build and packages, then rerun.",
    ),
    "unexpected_release_file": (
        "A public file is outside the configured allowlist",
        "Remove unintended packaging inputs. If the file is intentionally public, review "
        "and update allowed_release_files in the trusted policy before rerunning.",
    ),
    "missing_release_file": (
        "A required allowlisted file is missing",
        "Restore the required build output or review the trusted allowed_release_files "
        "list, then scan the complete release again.",
    ),
    "unsupported_archive": (
        "A detected archive format cannot be inspected",
        "Use a supported inspected release layout or a separately validated packaging "
        "workflow. Inspect the trusted unpacked staging tree and verify its relation to "
        "the final package before publication.",
    ),
    "archive_not_scanned": (
        "A detected archive was not inspected",
        "Enable the matching ZIP/ASAR inspection in the trusted policy when supported, "
        "or use a supported inspected release layout, then rerun.",
    ),
}
_UNKNOWN_DIAGNOSTIC = (
    "A release finding requires review",
    "Keep publication blocked. Review this code in the full JSON report and the matching "
    "version's documentation; resolve it and rerun the configured check.",
)
_DETAIL_FIELDS = ("rule_index", "format", "reason", "representation", "encoding", "kind")


def _quote(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True)


def _count(checks: dict[str, Any], field: str) -> str:
    value = checks.get(field)
    return str(value) if type(value) is int and value >= 0 else "unknown"


def _status(enabled: bool, completed: bool, *, absent: str = "disabled by policy") -> str:
    if not enabled:
        return absent + ("; INCOMPLETE" if not completed else "")
    return "complete" if completed else "INCOMPLETE"


def render_text_report(command: str, result: dict[str, Any]) -> str:
    """Render a scan/check/prepare result without serializing private data."""
    scan = result["scan"] if command == "prepare" else result
    checks = scan["checks"]
    findings = scan["findings"]
    passed = result["ok"]
    lines = [
        "Release Guard: " + ("PASS (exit 0)" if passed else "BLOCKED (exit 3)"),
        "Release root: " + _quote(scan["root"]),
        "Scanned: " + _count(checks, "files_scanned") + " files; "
        + _count(checks, "bytes_scanned") + " bytes; "
        + _count(checks, "archives_scanned") + " archives / "
        + _count(checks, "archive_entries") + " members",
    ]
    for label, field in (("Private inputs", "private_inputs_checked"), ("Asset keys", "asset_keys_checked")):
        lines.append(label + ": " + _count(checks, field)
                     + (" (not configured)" if checks.get(field) == 0 else ""))
    if checks.get("private_inputs_checked") == 0 or checks.get("asset_keys_checked") == 0:
        lines.append("Reference setup: use --private-input-file / --asset-key-file; "
                     "project-init can save these references for later checks.")
    lines.extend([
        "Inspection status:",
        "  Release scan: " + _status(True, checks["scan_completed"]),
        "  Private inputs: " + _status(bool(checks.get("private_inputs_checked")),
                                       checks.get("private_input_scan_completed", checks["scan_completed"]),
                                       absent="not configured"),
        "  Archives: " + _status(bool(checks["archive_formats"]), checks["archive_scan_completed"]),
        "  Source maps: " + _status(checks["source_map_structures_checked"], checks["source_map_scan_completed"]),
        "  Structured secrets: " + _status(checks["structured_secrets_checked"],
                                           checks["structured_secret_scan_completed"]),
        "  PYC asset keys: " + _status(checks["pyc_asset_keys_checked"], checks["pyc_asset_key_scan_completed"],
                                      absent="not configured"),
        "  Native metadata: " + _status(checks["native_metadata_checked"], checks["native_metadata_scan_completed"])
        + "; " + _count(checks, "native_files_checked") + " native payloads",
        "  Private-key markers / DER: " + ("enabled" if checks["private_key_markers_checked"] else "disabled by policy"),
        "  Native bearer tokens: " + ("enabled" if checks["native_token_format_checked"] else "disabled by policy"),
        "  Release allowlist: " + ("configured" if checks["release_allowlist_applied"] else "not configured"),
        "Findings: " + str(len(findings)),
    ])
    for index, finding in enumerate(findings, start=1):
        code = finding["code"]
        title, action = _DIAGNOSTICS.get(code, _UNKNOWN_DIAGNOSTIC)
        lines.append("  " + str(index) + ". " + _quote(code) + ": " + title)
        lines.append("     File: " + _quote(finding["path"]))
        if finding.get("archive_members"):
            lines.append("     Archive members: " + _quote(finding["archive_members"]))
        details = [field + "=" + _quote(finding[field]) for field in _DETAIL_FIELDS
                   if field in finding and type(finding[field]) in (str, int)]
        if details:
            lines.append("     Details: " + "; ".join(details))
        lines.append("     Next: " + action)
    if command == "prepare":
        lines.append("Prepared: " + ("yes" if result["prepared"] else "no; publication sidecars were not created"))
        for name in ("manifest.json", "ANALYSIS_NOTICE.md", "release-report.json"):
            if name in result["outputs"]:
                lines.append("  " + name + ": " + _quote(result["outputs"][name]))
    lines.append("Scope: configured static exposure checks; passing does not prove resistance to reverse engineering.")
    lines.append("Use --format json for the full inventory and machine-readable evidence.")
    return "\n".join(lines)


def render_text_error(command: str, error: BaseException | None = None, *, cancelled: bool = False) -> str:
    """Explain a CLI failure on stderr, escaping text and omitting OS paths."""
    if cancelled:
        return ("Release Guard: CANCELLED (exit 130)\n"
                "The operation did not complete. Rerun against the unchanged staging tree before publishing.")
    if isinstance(error, OSError):
        # In particular, prepare may receive an issuer-private-key path here.
        # OS diagnostics can reveal it; use only the platform's fixed errno text.
        detail = os.strerror(error.errno) if type(error.errno) is int else "Cannot access a required file or directory"
    else:
        detail = str(error) if error is not None else "The operation could not complete"
    lowered = detail.lower()
    if "private" in lowered and "input" in lowered:
        action = ("Check every private_input_files entry and --private-input-file argument. "
                  "Saved paths resolve relative to project.json; command-line paths resolve from the working directory. "
                  "References must be existing, unchanged regular files outside the release and within documented limits.")
    elif "asset" in lowered and "key" in lowered:
        action = ("Check every asset_key_files entry and --asset-key-file argument. "
                  "Saved paths resolve relative to project.json; command-line paths resolve from the working directory. "
                  "Use unchanged external regular files containing exactly 32 raw bytes.")
    elif command in {"check", "prepare"}:
        action = ("Confirm --config points to the intended project.json and its paths resolve from that file's directory. "
                  "Use project-init for a new configuration, build a nonempty release, and rerun after fixing the error.")
    else:
        action = ("Check --root and --policy, build a nonempty release, and keep the trusted policy outside it. "
                  "Resolve the reported input or resource-limit error, then rerun before publishing.")
    return "\n".join(("Release Guard: ERROR (exit 2)", "Detail: " + _quote(detail), "Next: " + action))
