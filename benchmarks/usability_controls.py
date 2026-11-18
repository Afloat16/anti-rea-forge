"""Reproduce v1.4 setup, relocation and readable-report controls against v1.3.

Only an owned synthetic private implementation and key are used. The real CLI
and Node SDK are exercised; no REA process or model is invoked. Text-size figures
describe one identical exact-copy finding, not general throughput or usability.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

from llvm_metadata_recovery import installed_identity


ROOT = Path(__file__).resolve().parents[1]
BASELINE_SHA256 = "1bb79222ca7aa1224f3815b2cacf235985e9c9f08bf7330ce0a80099df7bc3a6"
PRIVATE_INPUT = b"def owned_private_quote(units):\n    return units * 117 + 23\n"
ASSET_KEY = bytes(range(96, 128))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sdk_identity(root):
    """Hash every published SDK file, including package metadata and guides."""
    package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    paths = {root / "package.json"}
    for name in package["files"]:
        path = root / name
        require(path.resolve().is_relative_to(root.resolve()), "SDK package path is outside its root")
        if path.is_dir():
            paths.update(item for item in path.rglob("*") if item.is_file())
        else:
            require(path.is_file(), "Required SDK package file is missing")
            paths.add(path)
    inventory = hashlib.sha256()
    for path in sorted(paths, key=lambda value: value.relative_to(root).as_posix()):
        name = path.relative_to(root).as_posix()
        inventory.update((name + " " + hashlib.sha256(path.read_bytes()).hexdigest() + "\n").encode())
    return {"name": package["name"], "version": package["version"], "package_files": len(paths),
            "package_inventory_sha256": inventory.hexdigest()}


def cli(python, *arguments, cwd, expected=0):
    result = subprocess.run([str(python), "-I", "-m", "releaseguard", *map(str, arguments)],
                            cwd=cwd, capture_output=True, text=True, timeout=60)
    require(result.returncode == expected, "CLI control returned an unexpected exit status")
    require((result.stderr == "") if expected in (0, 3) else (result.stdout == ""),
            "CLI control violated the stdout/stderr contract")
    return result


def json_report(process):
    report = json.loads(process.stdout)
    require(type(report.get("ok")) is bool and process.returncode == (0 if report["ok"] else 3),
            "CLI JSON decision differs from its exit status")
    return report


def text_size(text):
    return {"lines": len(text.splitlines()), "characters": len(text), "utf8_bytes": len(text.encode("utf-8"))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-python", type=Path, required=True)
    parser.add_argument("--baseline-wheel", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--node", default=shutil.which("node"))
    parser.add_argument("--sdk-root", type=Path, default=ROOT / "packages/releaseguard")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(bool(args.node), "Real Node is required for the SDK relocation control")
    wheel = args.baseline_wheel.resolve(strict=True)
    require(hashlib.sha256(wheel.read_bytes()).hexdigest() == BASELINE_SHA256,
            "Expected the verified official v1.3.0 wheel")
    # Preserve virtual-environment executable symlinks: resolve() would select
    # the base interpreter when the subsequent command changes its cwd.
    baseline_python, candidate_python = args.baseline_python.absolute(), args.python.absolute()
    sdk = args.sdk_root.resolve(strict=True)
    baseline_before = installed_identity(baseline_python, wheel)
    candidate_before = installed_identity(candidate_python)
    sdk_before = sdk_identity(sdk)
    require(baseline_before["version"] == "1.3.0", "Expected the official v1.3 installed baseline")
    require(candidate_before["version"] == sdk_before["version"], "Candidate Python and SDK versions differ")
    node_version = subprocess.check_output([args.node, "--version"], text=True, timeout=15).strip()

    program = r"""const {createReleaseGuard}=await import(process.argv[1]);
const guard=createReleaseGuard({python:process.argv[2]});
const report=await guard.checkProject({config:process.argv[3]});
console.log(JSON.stringify({ok:report.ok,exitCode:report.exitCode,
 private_inputs_checked:report.checks.private_inputs_checked,
 asset_keys_checked:report.checks.asset_keys_checked,
 codes:report.findings.map(finding=>finding.code)}));"""
    with tempfile.TemporaryDirectory(prefix="owned-usability-") as temporary:
        work = Path(temporary)
        project = work / "owned project"
        project.mkdir()
        public = project / "public"
        public.mkdir()
        (public / "client.js").write_bytes(b"export const operation = 'quote';\n")
        private_dir = project / "private inputs"
        private_dir.mkdir()
        reference = private_dir / "owned private implementation.py"
        reference.write_bytes(PRIVATE_INPUT)
        key = private_dir / "owned external.key"
        key.write_bytes(ASSET_KEY)
        setup_flags = ("--root", "public", "--product", "owned-usability",
                       "--private-input-file", "private inputs/owned private implementation.py",
                       "--asset-key-file", "private inputs/owned external.key")
        cli(baseline_python, "project-init", *setup_flags, "--out", "unsupported-setup",
            cwd=project, expected=2)
        require(not (project / "unsupported-setup").exists(), "Failed baseline setup created a configuration")
        setup = json_report(cli(candidate_python, "project-init", *setup_flags, "--out", "guard", cwd=project))
        config = project / "guard/project.json"
        document = json.loads(config.read_text(encoding="utf-8"))
        require(document["root"] == "../public"
                and document["private_input_files"] == ["../private inputs/owned private implementation.py"]
                and document["asset_key_files"] == ["../private inputs/owned external.key"],
                "Initialization did not save correct config-relative input paths")
        require(reference.name not in json.dumps(setup) and key.name not in json.dumps(setup),
                "Initialization report disclosed private reference names")

        moved = work / "moved project"
        project.rename(moved)
        public, config = moved / "public", moved / "guard/project.json"
        operator = work / "unrelated working directory"
        operator.mkdir()
        clean = json_report(cli(candidate_python, "check", "--config", config, cwd=operator))
        require(clean["checks"]["private_inputs_checked"] == 1 and clean["checks"]["asset_keys_checked"] == 1,
                "Relocation lost configured protection inputs")

        def sdk_check():
            process = subprocess.run([args.node, "--input-type=module", "-e", program,
                                      (sdk / "src/index.js").as_uri(), str(candidate_python), str(config)],
                                     cwd=operator, capture_output=True, text=True, timeout=60)
            require(process.returncode == 0 and process.stderr == "", "Real Node SDK control did not complete")
            return json.loads(process.stdout)

        clean_sdk = sdk_check()
        require(clean_sdk["ok"] and clean_sdk["exitCode"] == 0
                and clean_sdk["private_inputs_checked"] == clean_sdk["asset_keys_checked"] == 1,
                "SDK lost initialized references after project relocation")
        (public / "client.js").unlink()
        copy = public / "renamed.bin"
        copy.write_bytes(PRIVATE_INPUT)
        baseline = cli(baseline_python, "check", "--config", config, cwd=operator, expected=3)
        candidate_json = cli(candidate_python, "check", "--config", config, cwd=operator, expected=3)
        explicit_json = cli(candidate_python, "check", "--config", config, "--format", "json",
                            cwd=operator, expected=3)
        require(candidate_json.stdout == explicit_json.stdout, "Explicit JSON differs from the default protocol")
        baseline_report, candidate_report = json_report(baseline), json_report(candidate_json)
        require(len(baseline_report["findings"]) == len(candidate_report["findings"]) == 1
                and baseline_report["findings"][0]["code"] == candidate_report["findings"][0]["code"]
                == "private_input_exposure", "The paired size fixture must have the same single exact-copy finding")
        readable = cli(candidate_python, "check", "--config", config, "--format", "text",
                       cwd=operator, expected=3)
        require('File: "renamed.bin"' in readable.stdout and "rule_index=0" in readable.stdout
                and "Remove the private implementation" in readable.stdout,
                "Human report is missing the public location, rule or remediation")
        for hidden in (reference.name, key.name, PRIVATE_INPUT.decode(), ASSET_KEY.hex(),
                       hashlib.sha256(PRIVATE_INPUT).hexdigest()):
            require(hidden not in readable.stdout, "Human report disclosed private reference material")
        baseline_size, candidate_size = text_size(baseline.stdout), text_size(readable.stdout)

        copy.write_bytes(b"owned package header\n" + PRIVATE_INPUT + b"\nowned package trailer\n")
        before_contained = json_report(cli(baseline_python, "check", "--config", config, cwd=operator))
        after_contained = json_report(cli(candidate_python, "check", "--config", config,
                                          cwd=operator, expected=3))
        require(before_contained["ok"] and after_contained["checks"]["private_input_scan_completed"],
                "Containment control did not reproduce the expected completed inspection")
        require(any(f["code"] == "private_input_exposure" and f.get("representation") == "contained-bytes"
                    for f in after_contained["findings"]), "Candidate did not refuse the contained private input")
        contained_sdk = sdk_check()
        require(not contained_sdk["ok"] and contained_sdk["exitCode"] == 3
                and "private_input_exposure" in contained_sdk["codes"],
                "SDK allowed the contained private input after relocation")

        cli(candidate_python, "project-init", "--root", public, "--product", "owned-defaults",
            "--out", moved / "unconfigured", cwd=operator)
        unconfigured = cli(candidate_python, "check", "--config", moved / "unconfigured/project.json",
                           "--format", "text", cwd=operator)
        require("Private inputs: 0 (not configured)" in unconfigured.stdout
                and "Asset keys: 0 (not configured)" in unconfigured.stdout,
                "Human report did not identify omitted protection references")
        (moved / "private inputs" / reference.name).unlink()
        missing = cli(candidate_python, "check", "--config", config, "--format", "text", cwd=operator, expected=2)
        require("Saved paths resolve relative to project.json" in missing.stderr
                and reference.name not in missing.stderr,
                "Missing-reference error lacks safe configuration-path guidance")

    baseline_after = installed_identity(baseline_python, wheel)
    candidate_after = installed_identity(candidate_python)
    sdk_after = sdk_identity(sdk)
    require(baseline_before == baseline_after and candidate_before == candidate_after and sdk_before == sdk_after,
            "Python or SDK package identity changed during the control")
    output = {
        "schema": "open-release-guard/usability-controls/v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "benchmark_files_sha256": {"driver": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "identity_helper": hashlib.sha256(Path(__file__).with_name("llvm_metadata_recovery.py").read_bytes()).hexdigest()},
        "environment": {"python": platform.python_version(), "node": node_version, "platform": platform.platform()},
        "baseline_wheel_sha256": BASELINE_SHA256,
        "baseline_identity_before": baseline_before, "baseline_identity_after": baseline_after,
        "candidate_identity_before": candidate_before, "candidate_identity_after": candidate_after,
        "sdk_identity_before": sdk_before, "sdk_identity_after": sdk_after,
        "initialization": {"baseline_accepts_reference_flags": False, "candidate_accepts_reference_flags": True,
                           "cwd_relative_arguments_saved_as_config_relative": True,
                           "private_reference_count": 1, "asset_key_count": 1,
                           "manual_configuration_edits_required": 0},
        "relocation": {"caller_cwd_differs_from_config_directory": True,
                       "clean_cli_allowed": True, "clean_sdk": clean_sdk,
                       "baseline_contained_copy_allowed": True, "candidate_contained_copy_refused": True,
                       "contained_sdk": contained_sdk, "extra_reference_arguments_required": 0},
        "single_finding_report": {"fixture": "one renamed, byte-identical private-file copy",
                                  "finding_count": 1, "baseline_default_json": baseline_size,
                                  "candidate_text": candidate_size,
                                  "line_reduction_percent": round(100 * (1 - candidate_size["lines"] / baseline_size["lines"]), 2),
                                  "character_reduction_percent": round(100 * (1 - candidate_size["characters"] / baseline_size["characters"]), 2),
                                  "default_and_explicit_json_identical": True,
                                  "location_rule_and_remediation_visible": True,
                                  "private_reference_material_displayed": False},
        "diagnostics": {"zero_reference_configuration_visible": True,
                        "missing_reference_stderr_exit_2": True, "config_relative_path_guidance_visible": True},
        "summary": {"reference_initialization_passed": True, "relocation_cli_and_sdk_passed": True,
                    "readable_failure_passed": True, "unconfigured_and_missing_reference_guidance_passed": True},
        "limitations": ["Owned synthetic files only; no REA or model was invoked.",
                        "Line and character counts describe one identical exact-copy finding; paths and other findings change report size.",
                        "A shorter human report is not a scan-speed or general usability benchmark; JSON retains the full evidence.",
                        "Initialization saves only explicitly declared references; omitted private inputs remain unknown.",
                        "Contained-byte detection does not identify rewritten, compiled, fragmented or encrypted implementations."],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(output, indent=2) + "\n")
    print(json.dumps({"summary": output["summary"], "single_finding_report": output["single_finding_report"]}, sort_keys=True))


if __name__ == "__main__":
    main()
