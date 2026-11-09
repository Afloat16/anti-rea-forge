"""Run the unmodified Craft Anything v0.5.0 CLI on one fixed, synthetic JS fixture.

Inputs come from the source-map benchmark's --work directory. The user supplies
the official Linux archive; this experiment does not download or install tools.
The upstream CLI runs in Deep mode and never executes the target JavaScript.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path


VERSION = "0.5.0"
COMMIT = "622d023cdfdb91c00df8b9a37c486a2a18fb0917"
ASSET = "craft-anything-0.5.0-linux-x86_64.tar.gz"
MEMBER = "craft-anything-0.5.0-linux-x86_64/bin/craft-anything-cli"
ARCHIVE_BYTES = 68_980_627
ARCHIVE_SHA = "d18c54ef05e5c7ef50f8c4959fee8983c0a4a1f141edc488d11f7029973c885b"
CLI_BYTES = 34_280_824
CLI_SHA = "61beefb5fc3f3a102649a9daed94f45f2e302c3f415ea5830fbf2cc317a1f901"
FIXTURE = {
    "app.js": "79a5c99baec4a8a063db6d51dc9f521f7776ace46d4f8bb1cc68c4702ca7a1e8",
    "package.json": "0d0723506b0a29cb81b1ff5a4dcfcb005b39a661b5c7d15f306ee9c570e6b93c",
    "app.js.map": "0b84e1698955dbdde34d8017e362aa1bca5e726e036353bdba1fd3987d20b979",
}
ORIGINAL_SHA = "950aba3d70fb67f10427f86534c8dac4b17fb1d8450522f3bffdb02849664cb5"
CANARY = b"releaseguard_source_only_canary_4bd216a5531e"


def require(condition, message):
    # Keep acceptance checks active under python -O.
    if not condition:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as reader:
        for block in iter(lambda: reader.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def inventory(directory, expected):
    require(directory.is_dir() and not directory.is_symlink(), "Fixture directory missing or linked")
    require({p.name for p in directory.iterdir()} == set(expected), "Unexpected fixture inventory")
    for name in expected:
        p = directory / name
        st = p.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_size <= 16_384, "Fixture is not a small regular file")
        require(digest(p) == FIXTURE[name], f"Unexpected synthetic fixture digest: {name}")


def get_cli(archive, scratch):
    st = archive.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_size == ARCHIVE_BYTES, "Wrong official archive size/type")
    cli = scratch / "craft-anything-cli"
    # Hash and extract through the same opened archive handle; never extractall.
    with archive.open("rb") as file:
        sha = hashlib.sha256()
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            sha.update(chunk)
        require(sha.hexdigest() == ARCHIVE_SHA, "Official release archive digest mismatch")
        file.seek(0)
        with tarfile.open(fileobj=file, mode="r:gz") as package:
            member = package.getmember(MEMBER)
            require(member.isfile() and member.size == CLI_BYTES, "Wrong CLI member type or size")
            source = package.extractfile(member)
            require(source is not None, "CLI member unreadable")
            with source, cli.open("xb") as dest:
                shutil.copyfileobj(source, dest)
    require(digest(cli) == CLI_SHA, "CLI digest mismatch")
    cli.chmod(0o700)
    return cli


def run_case(cli, scratch, name, app, expected_original_count):
    work = scratch / name
    work.mkdir()
    out = work / "recovered"
    proc = subprocess.run(
        [str(cli), "--deep", "--project", str(work / "session.cany"), "js-sources-restore",
         "--path", str(app), "--output-directory", str(out), "--output-format", "json"],
        cwd=work, capture_output=True, timeout=45, check=True,
        env={"PATH": os.defpath, "LANG": "C", "XDG_CONFIG_HOME": str(work / "config"),
             "XDG_DATA_HOME": str(work / "data"), "XDG_CACHE_HOME": str(work / "cache")},
    )
    evidence = json.loads(proc.stdout)
    env = evidence["environment"]
    require(env["clean_room"] is False and env["engine"] == "builtin" and env["engine_version"] == VERSION,
            "CLI did not use the expected Deep mode / engine")
    require(evidence["operation"] == "js_sources_restore" and evidence["coverage"]["status"] == "complete",
            "Missing successful restore coverage")
    result = evidence["result"]
    require(len(result["inputs"]) == 1 and result["inputs"][0]["sha256"] == FIXTURE["app.js"],
            "Restore examined the wrong bundle")
    outputs = result["outputs"]
    require(result["outputs_total"] == len(outputs) and not result["notes"],
            "Restore results are incomplete or include errors/limitations in notes")
    originals = [o for o in outputs if o["kind"] == "original-source"]
    pretty = [o for o in outputs if o["kind"] == "pretty"]
    require(len(pretty) == 1 and len(originals) == expected_original_count, "Unexpected recovery result")
    contents = {}
    for row in outputs:
        candidate = (out / row["path"]).resolve(strict=True)
        require(candidate.is_relative_to(out) and candidate.is_file() and candidate.stat().st_size <= 16_384,
                "Unexpected recovery output path or size")
        contents[row["path"]] = candidate.read_bytes()
    recovered = [hashlib.sha256(contents[o["path"]]).hexdigest() for o in originals]
    require(recovered == [ORIGINAL_SHA] * expected_original_count, "Original file digest mismatch")
    marker_found = any(CANARY in data for data in contents.values())
    require(marker_found == bool(expected_original_count), "Canary recovery differs from expected control")
    return {"exit_code": proc.returncode, "deep_mode": True, "coverage": "complete",
            "analyzed_js_sha256": result["inputs"][0]["sha256"],
            "pretty_files": len(pretty), "pretty_sha256": hashlib.sha256(contents[pretty[0]["path"]]).hexdigest(),
            "original_source_files": len(originals), "recovered_original_sha256": recovered,
            "canary_in_emitted_files": marker_found}


def observe(archive, baseline, public, private):
    require(platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64"),
            "The pinned release artifact targets Linux x86-64")
    inventory(baseline, FIXTURE)
    inventory(public, ("app.js", "package.json"))
    inventory(private, ("app.js.map",))
    require(b"sourceMappingURL" not in (baseline / "app.js").read_bytes(), "Expected an unlinked sibling map")
    with tempfile.TemporaryDirectory(prefix="releaseguard-craft-") as tmp:
        scratch = Path(tmp).resolve()
        cli = get_cli(archive, scratch)
        # The tool receives one isolated directory per case. Reassociation is
        # an explicit authorized debug control, not access granted to public users.
        cases = {}
        for name, directory, extra_private, expected in (
            ("baseline", baseline, False, 1), ("public", public, False, 0),
            ("public_plus_private_map", public, True, 1),
        ):
            inputs = scratch / (name + "-input")
            shutil.copytree(directory, inputs)
            if extra_private:
                shutil.copyfile(private / "app.js.map", inputs / "app.js.map")
            cases[name] = run_case(cli, scratch, name, inputs / "app.js", expected)
        require(len({v["pretty_sha256"] for v in cases.values()}) == 1,
                "Pretty-printed program changed across cases")
    return {"schema": "releaseguard-craft-source-map-observation/v1", "passed": True,
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "tool": {"repo": "storytold/craft-anything", "release": "v" + VERSION, "commit": COMMIT,
                     "asset": ASSET, "archive_sha256": ARCHIVE_SHA, "cli_sha256": CLI_SHA,
                     "operation": "js_sources_restore", "mode": "Deep"},
            "host": {"platform": platform.system(), "architecture": platform.machine(),
                     "python": platform.python_version()},
            "fixture_sha256": FIXTURE, "expected_original_sha256": ORIGINAL_SHA, "observations": cases,
            "scope": "Exact source restoration via an external sibling map on this one synthetic bundle. "
                     "Pretty-printing still works. Does not measure behavioral reconstruction or other targets."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "baseline", "public", "private", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    report = observe(args.archive, args.baseline, args.public, args.private)
    with args.output.open("x", encoding="utf-8", newline="\n") as dest:
        json.dump(report, dest, indent=2, ensure_ascii=False)
        dest.write("\n")
    print(f"Craft Anything {VERSION}: baseline/public/debug originals 1/0/1; all three restores completed.")


if __name__ == "__main__":
    main()
