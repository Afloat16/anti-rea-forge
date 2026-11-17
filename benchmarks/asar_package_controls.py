"""Check real caller-supplied @electron/asar packages against releaseguard.

Every input is a temporary, project-owned fixture. The official CLI packs,
lists and extracts its files; releaseguard independently inspects the package.
The report retains identities and observations, never generated key contents.
No Electron application, REA process, model or arbitrary target is executed.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import sys
import tempfile

from releaseguard import __version__
from releaseguard.core import GuardError, write_new
from releaseguard.distribution import scan_release


ROOT = Path(__file__).resolve().parents[1]
CLEAN_FILES = {
    "package.json": b'{"name":"owned-asar-control","version":"1.0.0","main":"index.js"}',
    "index.js": b"export const publicValue = 7;\n",
    "assets/message.txt": b"Public synthetic ASAR resource.\n",
    "assets/empty.bin": b"",
}
ESCAPED_MAP = (b'{"ver\\u0073ion":3,"sour\\u0063es":["owned.ts"],"names":[],"mappings":"AAAA",'
               b'"sourcesCont\\u0065nt":["export const owned = 1;"]}')


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def command(arguments, *, cwd: Path | None = None) -> bytes:
    result = subprocess.run(list(map(str, arguments)), cwd=cwd, capture_output=True,
                            timeout=120, env={**os.environ, "LC_ALL": "C"}, check=False)
    if result.returncode:
        # A tool's diagnostics may contain fixture material. Retain only status.
        raise RuntimeError(f"{Path(arguments[0]).name} exited with status {result.returncode}")
    return result.stdout


def resolve_cli(selected: str | None) -> Path:
    found = shutil.which(selected or "asar")
    if not found:
        raise RuntimeError("A caller-supplied @electron/asar CLI is required; use --asar-cli or PATH")
    return Path(found).resolve(strict=True)


def tool_identity(cli: Path) -> dict:
    version = command([cli, "--version"]).decode("utf-8").strip()
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node.js is required for the @electron/asar CLI")
    result = {"version_output": version, "cli_sha256": sha(cli.read_bytes()),
              "node_version": command([node, "--version"]).decode("ascii").strip()}
    # npm's supported CLI lives in @electron/asar/bin/asar.mjs. Package metadata
    # and hashes identify the observed installation; they do not authenticate it.
    package_root = cli.parent.parent
    metadata_path = package_root / "package.json"
    if metadata_path.is_file():
        metadata = json.loads(metadata_path.read_bytes())
        if metadata.get("name") == "@electron/asar":
            if version != "v" + metadata["version"]:
                raise RuntimeError("ASAR CLI version and adjacent package metadata disagree")
            result.update({"package_name": metadata["name"], "package_version": metadata["version"],
                           "package_source_sha256": {"package.json": sha(metadata_path.read_bytes())}})
            for path in sorted((package_root / "lib").glob("*.js")):
                result["package_source_sha256"][str(path.relative_to(package_root))] = sha(path.read_bytes())
            if package_root.parent.name == "@electron" and package_root.parent.parent.name == "node_modules":
                lock = package_root.parent.parent.parent / "package-lock.json"
                if lock.is_file():
                    raw_lock = lock.read_bytes()
                    entry = json.loads(raw_lock).get("packages", {}).get("node_modules/@electron/asar", {})
                    if entry.get("version") == metadata["version"]:
                        result["npm_lock"] = {"sha256": sha(raw_lock), "resolved": entry.get("resolved"),
                                              "integrity": entry.get("integrity")}
    return result


def inventory(files: dict[str, bytes]) -> dict:
    return {name: {"bytes": len(data), "sha256": sha(data)} for name, data in sorted(files.items())}


def verify_with_upstream(cli: Path, archive: Path, files: dict[str, bytes], destination: Path) -> dict:
    """Require the real upstream inventory and every extracted file to match."""
    expected = set(files)
    for name in files:
        expected.update(str(parent) for parent in Path(name).parents if str(parent) != ".")
    listed = command([cli, "list", archive]).decode("utf-8").splitlines()
    names = [name.replace("\\", "/").lstrip("/") for name in listed]
    if len(names) != len(set(names)) or set(names) != expected:
        raise RuntimeError("The upstream ASAR inventory does not match the owned fixture")
    for index, (name, data) in enumerate(sorted(files.items())):
        output_dir = destination / str(index)
        output_dir.mkdir(parents=True)
        command([cli, "extract-file", archive, name], cwd=output_dir)
        if (output_dir / Path(name).name).read_bytes() != data:
            raise RuntimeError("The upstream ASAR extraction does not match the owned fixture")
    return {"listed_entries": len(names), "listed_inventory_matches": True,
            "extracted_files": len(files), "all_extracted_bytes_match": True}


def scanner_observation(folder: Path, policy: Path, key_file: Path) -> dict:
    try:
        report = scan_release(folder, policy, asset_key_files=[key_file])
    except GuardError as exc:
        return {"status": "rejected_input", "ok": False, "reason": str(exc)}
    return {"status": "completed", "ok": report["ok"],
            "finding_codes": sorted({item["code"] for item in report["findings"]}),
            "member_findings": [{"code": item["code"], "archive_members": item["archive_members"]}
                                for item in report["findings"] if item.get("archive_members")],
            "archives_scanned": report["checks"]["archives_scanned"],
            "archive_scan_completed": report["checks"]["archive_scan_completed"],
            "asset_keys_checked": report["checks"]["asset_keys_checked"]}


def run_controls(cli: Path) -> dict:
    tool = tool_identity(cli)
    checks, cases = {}, {}
    with tempfile.TemporaryDirectory(prefix="rg-official-asar-") as temporary:
        work = Path(temporary).resolve()
        private = work / "issuer"
        private.mkdir(mode=0o700)
        key = secrets.token_bytes(32)
        key_file = private / "external.key"
        write_new(key_file, key, secret=True)
        policy = private / "policy.json"
        policy.write_text('{"version":1}', encoding="ascii")
        definitions = {
            "clean": (dict(CLEAN_FILES), ()),
            "escaped_source_map": ({**CLEAN_FILES, "assets/resource.dat": ESCAPED_MAP}, ()),
            "hidden_env": ({**CLEAN_FILES, ".env": b"OWNED_FIXTURE_SETTING=public-test-value\n"}, ()),
            "bundled_key": ({**CLEAN_FILES, "assets/key.bin": key}, ()),
            "unpacked_sidecar": ({**CLEAN_FILES, "addons/owned.node": b"owned non-executable sidecar\n"}, ("--unpack", "*.node")),
        }
        archives = {}
        for name, (files, options) in definitions.items():
            source, release = work / (name + "-source"), work / (name + "-release")
            source.mkdir()
            release.mkdir()
            for relative, data in files.items():
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            archive = release / "application.asar"
            command([cli, "pack", source, archive, *options])
            upstream = verify_with_upstream(cli, archive, files, work / (name + "-extracted"))
            archives[name] = archive
            cases[name] = {"archive_sha256": sha(archive.read_bytes()), "archive_bytes": archive.stat().st_size,
                           "fixture_files": inventory(files), "pack_options": list(options),
                           "upstream": upstream, "scan": scanner_observation(release, policy, key_file)}
            if name == "unpacked_sidecar":
                sidecar = release / "application.asar.unpacked/addons/owned.node"
                cases[name]["upstream_created_sidecar"] = sidecar.is_file() and sidecar.read_bytes() == files["addons/owned.node"]

        # Renaming preserves the exact upstream-produced bytes. Both the tool and
        # scanner must still interpret the archive without an .asar extension.
        for original_name, renamed_name in (("clean", "renamed_clean"), ("bundled_key", "renamed_bundled_key")):
            release = work / (renamed_name + "-release")
            release.mkdir()
            archive = release / "resource.bin"
            shutil.copyfile(archives[original_name], archive)
            files = definitions[original_name][0]
            cases[renamed_name] = {"archive_sha256": sha(archive.read_bytes()), "archive_bytes": archive.stat().st_size,
                                   "fixture_files": inventory(files), "copied_from": original_name,
                                   "upstream": verify_with_upstream(cli, archive, files, work / (renamed_name + "-extracted")),
                                   "scan": scanner_observation(release, policy, key_file)}
            checks[renamed_name + "_bytes_unchanged"] = cases[renamed_name]["archive_sha256"] == cases[original_name]["archive_sha256"]

        for name in ("clean", "renamed_clean"):
            observed = cases[name]["scan"]
            checks[name + "_accepted_and_expanded"] = (observed["status"] == "completed" and observed["ok"]
                and observed["archives_scanned"] == 1 and observed["archive_scan_completed"] and observed["asset_keys_checked"] == 1)
        for name, code, member in (("escaped_source_map", "source_map_structure", "assets/resource.dat"),
                                   ("hidden_env", "forbidden_path_component", ".env"),
                                   ("bundled_key", "asset_key_exposure", "assets/key.bin"),
                                   ("renamed_bundled_key", "asset_key_exposure", "assets/key.bin")):
            observed = cases[name]["scan"]
            checks[name + "_blocked_at_actual_member"] = (observed["status"] == "completed" and not observed["ok"]
                and {"code": code, "archive_members": [member]} in observed["member_findings"])
        sidecar = cases["unpacked_sidecar"]
        checks["upstream_unpacked_sidecar_exists_and_extracts"] = sidecar["upstream_created_sidecar"] and sidecar["upstream"]["all_extracted_bytes_match"]
        checks["unsupported_unpacked_layout_rejected"] = (sidecar["scan"]["status"] == "rejected_input"
            and "ASAR unpacked sidecars" in sidecar["scan"]["reason"])
        checks["all_upstream_lists_and_extractions_match"] = all(case["upstream"]["listed_inventory_matches"]
            and case["upstream"]["all_extracted_bytes_match"] for case in cases.values())

    sources = [Path(__file__), ROOT / "src/releaseguard/asar.py", ROOT / "src/releaseguard/distribution.py",
               ROOT / "src/releaseguard/core.py"]
    return {"schema": "releaseguard-official-asar-controls/v1", "ok": all(checks.values()),
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "core_version": __version__, "tool": tool,
            "environment": {"platform": platform.platform(), "python": platform.python_version()},
            "source_sha256": {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in sources},
            "cases": cases, "checks": checks,
            "scope": {"owned_fixtures_only": True, "real_asar_cli_executed": True,
                      "real_pack_list_extract_file_executed": True, "target_application_executed": False,
                      "rea_executed": False, "decompilation_resistance": "not_evaluated",
                      "notes": ["The caller supplies the CLI. Observed version, package metadata and hashes identify it, not authenticate its provenance.",
                                "An unpacked layout is valid to the upstream tool but intentionally rejected by this bounded scanner.",
                                "All extracted bytes are compared with the original owned fixture; no original key or content bytes are retained in the report.",
                                "These controls establish compatibility and configured disclosure checks for the recorded package layouts, not complete Electron or REA resistance."]}}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asar-cli", help="Caller-supplied asar executable; otherwise find asar on PATH")
    parser.add_argument("--out", type=Path, help="New JSON report path; an existing path is never overwritten")
    args = parser.parse_args(argv)
    try:
        if args.out is not None and os.path.lexists(args.out):
            raise FileExistsError("Report path already exists")
        report = run_controls(resolve_cli(args.asar_cli))
        data = (json.dumps(report, indent=2) + "\n").encode("utf-8")
        if args.out is not None:
            write_new(args.out, data)
        print(data.decode("utf-8"), end="")
        return 0 if report["ok"] else 1
    except (GuardError, OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ok": False, "status": "execution_error", "error": str(exc),
                          "compatibility_outcome": "not_measured"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
