"""Check real caller-supplied @electron/asar packages against releaseguard.

Every input is a temporary, project-owned fixture. The official CLI packs,
lists and extracts each valid package before releaseguard independently scans it.
Copies with deliberate sidecar mutations are tested separately; upstream success
is never claimed for a mutated input. The report retains hashes and observations,
never raw generated key contents or captured fixture/tool output.
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
import zipfile

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
        expected.update(parent.as_posix() for parent in Path(name).parents if parent.as_posix() != ".")
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


def release_bytes(folder: Path) -> dict[str, bytes]:
    """Inventory only our generated package files, including external sidecars."""
    return {path.relative_to(folder).as_posix(): path.read_bytes()
            for path in sorted(folder.rglob("*")) if path.is_file()}


def verify_sidecars(archive: Path, files: dict[str, bytes], unpacked: tuple[str, ...]) -> dict:
    expected = {name: files[name] for name in unpacked}
    sidecar_root = Path(str(archive) + ".unpacked")
    observed = release_bytes(sidecar_root) if sidecar_root.is_dir() else {}
    if observed != expected:
        raise RuntimeError("The upstream sidecar tree does not match the declared owned fixture")
    return {"unpacked_files": len(observed), "unpacked_inventory_matches": True,
            "all_unpacked_bytes_match": True}


def scanner_observation(folder: Path, policy: Path, key_file: Path) -> dict:
    try:
        report = scan_release(folder, policy, asset_key_files=[key_file])
    except GuardError as exc:
        # GuardError is the scanner's rejection outcome. Missing tools, tool
        # failures and unrelated I/O exceptions must still abort the experiment.
        return {"status": "rejected_input", "ok": False, "reason": str(exc)}
    return {"status": "completed", "ok": report["ok"],
            "finding_codes": sorted({item["code"] for item in report["findings"]}),
            "findings": [{"code": item["code"], "path": item["path"],
                          "archive_members": item.get("archive_members", [])}
                         for item in report["findings"]],
            "files_scanned": report["checks"]["files_scanned"],
            "bytes_scanned": report["checks"]["bytes_scanned"],
            "archives_scanned": report["checks"]["archives_scanned"],
            "archive_scan_completed": report["checks"]["archive_scan_completed"],
            "asar_unpacked_members_checked": report["checks"]["asar_unpacked_members_checked"],
            "asset_keys_checked": report["checks"]["asset_keys_checked"]}


def run_controls(cli: Path) -> dict:
    tool = tool_identity(cli)
    checks, cases, mutations = {}, {}, {}
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
            "clean": {
                "files": dict(CLEAN_FILES), "options": (), "unpacked": (),
            },
            "escaped_source_map": {
                "files": {**CLEAN_FILES, "assets/resource.dat": ESCAPED_MAP},
                "options": (), "unpacked": (),
                "finding": ("source_map_structure", "assets/resource.dat"),
            },
            "hidden_env": {
                "files": {**CLEAN_FILES, ".env": b"OWNED_FIXTURE_SETTING=public-test-value\n"},
                "options": (), "unpacked": (),
                "finding": ("forbidden_path_component", ".env"),
            },
            "bundled_key": {
                "files": {**CLEAN_FILES, "assets/key.bin": key},
                "options": (), "unpacked": (),
                "finding": ("asset_key_exposure", "assets/key.bin"),
            },
            "unpacked_sidecar": {
                "files": {**CLEAN_FILES, "addons/owned.node": b"owned non-executable sidecar\n"},
                "options": ("--unpack", "*.node"), "unpacked": ("addons/owned.node",),
            },
            "unpacked_escaped_source_map": {
                "files": {**CLEAN_FILES, "assets/resource.dat": ESCAPED_MAP},
                "options": ("--unpack", "*.dat"), "unpacked": ("assets/resource.dat",),
                "finding": ("source_map_structure", "assets/resource.dat"),
            },
            "unpacked_bundled_key": {
                "files": {**CLEAN_FILES, "assets/key.bin": key},
                "options": ("--unpack", "*key.bin"), "unpacked": ("assets/key.bin",),
                "finding": ("asset_key_exposure", "assets/key.bin"),
            },
            "unpacked_directory": {
                "files": {**CLEAN_FILES,
                          "addons/owned.node": b"owned non-executable directory sidecar\n",
                          "addons/empty.bin": b"",
                          "addons/nested/note.txt": b"Owned nested unpacked resource.\n"},
                "options": ("--unpack-dir", "addons"),
                "unpacked": ("addons/owned.node", "addons/empty.bin", "addons/nested/note.txt"),
            },
        }
        archives = {}

        def record_valid_case(name, release, archive, definition, upstream, *,
                              copied_from=None, wrapper=None):
            files = definition["files"]
            unpacked = definition["unpacked"]
            physical = release_bytes(release)
            observed = scanner_observation(release, policy, key_file)
            archive_name = archive.name
            expected_archives = 2 if wrapper is not None else 1
            # Physical package bytes plus packed member expansion. Unpacked
            # bytes have already been counted as actual sibling payloads.
            expected_bytes = archive.stat().st_size + sum(map(len, files.values()))
            if wrapper is not None:
                expected_bytes += wrapper.stat().st_size
            expected_finding = None
            if "finding" in definition:
                code, member = definition["finding"]
                if wrapper is not None:
                    actual = ("payload/" + archive_name + ".unpacked/" + member
                              if member in unpacked else "payload/" + archive_name)
                    members = [actual] if member in unpacked else [actual, member]
                    expected_finding = {"code": code, "path": wrapper.name,
                                        "archive_members": members}
                elif member in unpacked:
                    expected_finding = {"code": code, "path": archive_name + ".unpacked/" + member,
                                        "archive_members": []}
                else:
                    expected_finding = {"code": code, "path": archive_name,
                                        "archive_members": [member]}
            case = {"archive_sha256": sha(archive.read_bytes()),
                    "archive_bytes": archive.stat().st_size,
                    "fixture_files": inventory(files), "release_files": inventory(physical),
                    "pack_options": list(definition["options"]),
                    "upstream": upstream, "scan": observed,
                    "expected_scan": {"files_scanned": len(physical),
                                      "bytes_scanned": expected_bytes,
                                      "archives_scanned": expected_archives,
                                      "asar_unpacked_members_checked": len(unpacked),
                                      "finding": expected_finding}}
            if copied_from is not None:
                case["copied_from"] = copied_from
            if wrapper is not None:
                case["wrapper"] = {"format": "zip-deflate",
                                   "sha256": sha(wrapper.read_bytes()),
                                   "bytes": wrapper.stat().st_size}
            cases[name] = case
            checks[name + "_scanner_accounting_matches"] = (
                observed["status"] == "completed"
                and observed["files_scanned"] == len(physical)
                and observed["bytes_scanned"] == expected_bytes
                and observed["archives_scanned"] == expected_archives
                and observed["archive_scan_completed"]
                and observed["asar_unpacked_members_checked"] == len(unpacked)
                and observed["asset_keys_checked"] == 1
            )
            checks[name + "_release_gate_matches"] = (
                observed["status"] == "completed"
                and ((observed["ok"] and not observed["findings"]) if expected_finding is None
                     else (not observed["ok"] and expected_finding in observed["findings"]))
            )

        for name, definition in definitions.items():
            files, options = definition["files"], definition["options"]
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
            upstream.update(verify_sidecars(archive, files, definition["unpacked"]))
            archives[name] = archive
            record_valid_case(name, release, archive, definition, upstream)

        # Rename a valid archive together with its exact matching sidecar tree.
        # The upstream reader uses <current archive path>.unpacked for its files.
        for original_name, renamed_name in (
            ("clean", "renamed_clean"),
            ("bundled_key", "renamed_bundled_key"),
            ("unpacked_sidecar", "renamed_unpacked_sidecar"),
        ):
            release = work / (renamed_name + "-release")
            release.mkdir()
            archive = release / "resource.bin"
            original = archives[original_name]
            shutil.copyfile(original, archive)
            definition = definitions[original_name]
            if definition["unpacked"]:
                shutil.copytree(Path(str(original) + ".unpacked"), Path(str(archive) + ".unpacked"))
            upstream = verify_with_upstream(
                cli, archive, definition["files"], work / (renamed_name + "-extracted"),
            )
            upstream.update(verify_sidecars(archive, definition["files"], definition["unpacked"]))
            record_valid_case(renamed_name, release, archive, definition, upstream,
                              copied_from=original_name)
            checks[renamed_name + "_archive_bytes_unchanged"] = (
                cases[renamed_name]["archive_sha256"] == cases[original_name]["archive_sha256"]
            )
            if definition["unpacked"]:
                checks[renamed_name + "_sidecar_bytes_unchanged"] = (
                    release_bytes(Path(str(original) + ".unpacked"))
                    == release_bytes(Path(str(archive) + ".unpacked"))
                )

        # Deliberately write ZIP members in reverse name order. Each external
        # sidecar is stored before the ASAR that refers to it. Extraction below
        # uses only our fixed member names and compares every wrapper payload.
        for original_name, zipped_name in (
            ("unpacked_sidecar", "zip_unpacked_clean"),
            ("unpacked_escaped_source_map", "zip_unpacked_escaped_source_map"),
            ("unpacked_bundled_key", "zip_unpacked_bundled_key"),
        ):
            definition = definitions[original_name]
            original = archives[original_name]
            payloads = {"payload/" + name: data
                        for name, data in release_bytes(original.parent).items()}
            member_order = sorted(payloads, reverse=True)
            release = work / (zipped_name + "-release")
            release.mkdir()
            wrapper = release / "bundle.zip"
            with zipfile.ZipFile(wrapper, "x") as container:
                for name in member_order:
                    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = 0o100644 << 16
                    container.writestr(info, payloads[name])
            unwrapped = work / (zipped_name + "-unwrapped")
            unwrapped.mkdir()
            with zipfile.ZipFile(wrapper) as container:
                if container.namelist() != member_order:
                    raise RuntimeError("The ZIP wrapper did not preserve the requested member order")
                for name, expected in payloads.items():
                    data = container.read(name)
                    if data != expected:
                        raise RuntimeError("The ZIP wrapper changed an upstream package payload")
                    target = unwrapped / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
            archive = unwrapped / "payload" / original.name
            upstream = verify_with_upstream(
                cli, archive, definition["files"], work / (zipped_name + "-extracted"),
            )
            upstream.update(verify_sidecars(archive, definition["files"], definition["unpacked"]))
            upstream["zip_payloads_compared_with_valid_source"] = True
            record_valid_case(zipped_name, release, archive, definition, upstream,
                              copied_from=original_name, wrapper=wrapper)
            cases[zipped_name]["wrapper"]["member_order"] = member_order
            archive_member = "payload/" + original.name
            sidecar_members = [archive_member + ".unpacked/" + name for name in definition["unpacked"]]
            checks[zipped_name + "_sidecars_precede_archive_without_changing_payloads"] = (
                all(member_order.index(name) < member_order.index(archive_member)
                    for name in sidecar_members)
                and cases[zipped_name]["archive_sha256"] == cases[original_name]["archive_sha256"]
                and upstream["zip_payloads_compared_with_valid_source"]
            )

        # Upstream extraction was verified on the clean source above. These
        # independent copies are modified afterwards, with no claim that the
        # upstream reader rejects or correctly verifies the corrupted content.
        negative_definitions = {
            "missing_sidecar": "ASAR unpacked sidecar is missing from its sibling namespace",
            "sidecar_size_changed": "ASAR unpacked sidecar size differs from its index",
            "sidecar_same_size_tampered": "ASAR member digest mismatch",
            "unindexed_sidecar_file": "ASAR unpacked sidecar tree contains unindexed files",
        }
        original = archives["unpacked_sidecar"]
        target_name = "application.asar.unpacked/addons/owned.node"
        for name, expected_error in negative_definitions.items():
            release = work / (name + "-release")
            shutil.copytree(original.parent, release)
            target = release / target_name
            mutation_path = target_name
            if name == "missing_sidecar":
                target.unlink()
            elif name == "sidecar_size_changed":
                target.write_bytes(target.read_bytes() + b"!")
            elif name == "sidecar_same_size_tampered":
                data = target.read_bytes()
                if not data:
                    raise RuntimeError("The same-size mutation fixture must be nonempty")
                target.write_bytes(bytes([data[0] ^ 1]) + data[1:])
            elif name == "unindexed_sidecar_file":
                mutation_path = "application.asar.unpacked/addons/unindexed.bin"
                (release / mutation_path).write_bytes(b"unindexed owned resource\n")
            else:
                raise RuntimeError("Unknown sidecar mutation control")
            observed = scanner_observation(release, policy, key_file)
            unchanged_archive = (release / original.name).read_bytes() == original.read_bytes()
            mutations[name] = {
                "copied_from_valid_case": "unpacked_sidecar",
                "mutation_path": mutation_path,
                "upstream_executed_on_mutated_input": False,
                "original_archive_bytes_unchanged": unchanged_archive,
                "release_files": inventory(release_bytes(release)),
                "expected_guard_error": expected_error,
                "scan": observed,
            }
            checks[name + "_rejected_with_exact_guard_error"] = (
                unchanged_archive and observed["status"] == "rejected_input"
                and not observed["ok"] and observed["reason"] == expected_error
            )

        checks["all_valid_upstream_lists_extractions_and_sidecars_match"] = all(
            case["upstream"]["listed_inventory_matches"]
            and case["upstream"]["all_extracted_bytes_match"]
            and case["upstream"]["unpacked_inventory_matches"]
            and case["upstream"]["all_unpacked_bytes_match"]
            for case in cases.values()
        )

    sources = [Path(__file__), ROOT / "src/releaseguard/asar.py", ROOT / "src/releaseguard/distribution.py",
               ROOT / "src/releaseguard/core.py", ROOT / "src/releaseguard/sealed.py"]
    return {"schema": "releaseguard-official-asar-controls/v2", "ok": all(checks.values()),
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "core_version": __version__, "tool": tool,
            "environment": {"platform": platform.platform(), "python": platform.python_version()},
            "source_sha256": {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in sources},
            "cases": cases, "mutation_cases": mutations, "checks": checks,
            "case_counts": {"upstream_verified": len(cases), "mutated": len(mutations),
                            "total": len(cases) + len(mutations)},
            "scope": {"owned_fixtures_only": True, "real_asar_cli_executed": True,
                      "real_pack_list_extract_file_executed": True, "target_application_executed": False,
                      "upstream_verified_mutated_inputs": False,
                      "rea_executed": False, "decompilation_resistance": "not_evaluated",
                      "notes": [
                          "The caller supplies the CLI. Version, package metadata and hashes identify the installation; they do not authenticate its provenance.",
                          "Valid packed and unpacked packages are listed and every file is extracted by the upstream CLI. Renamed archives retain their matching sidecar trees.",
                          "ZIP wrappers store sidecars before the referring ASAR. Wrapper bytes are compared with the valid source before upstream extraction; scanner findings use actual sibling paths.",
                          "The missing, resized, same-size-tampered and extra-file controls are independent mutations of a verified clean package. No upstream success or rejection is asserted for those mutated inputs.",
                          "Unpacked bytes are checked through their actual physical or ZIP sibling payload once, with index size and upstream-generated integrity checks. These fixtures do not test archives without integrity metadata.",
                          "No raw key, captured tool output or extracted file contents are retained in the report. Hashes describe synthetic test artifacts and the executed source.",
                          "These controls measure the recorded package layouts and configured disclosure gates. They do not establish complete Electron coverage, decompilation resistance or resistance to REA.",
                      ]}}


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
