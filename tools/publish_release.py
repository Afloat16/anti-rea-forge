#!/usr/bin/env python3
"""Publish only the exact installation-tested artifacts of a successful main CI.

GitHub Actions supplies the short-lived token. No third-party PR artifact is used,
existing tags/releases are never replaced, and incomplete uploads remain drafts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

REPOSITORY = "Afloat16/anti-rea-forge"
ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_ci(run: dict, jobs: list[dict], expected_sha: str,
                required_jobs: list[str]) -> None:
    require(bool(re.fullmatch(r"[0-9a-f]{40}", expected_sha)), "Invalid commit")
    require(run.get("head_sha") == expected_sha, "CI did not validate current main")
    require(run.get("event") == "push" and run.get("head_branch") == "main",
            "Release requires a main push run")
    require(run.get("repository", {}).get("full_name") == REPOSITORY and
            run.get("head_repository", {}).get("full_name") == REPOSITORY,
            "CI must originate in this repository")
    require(run.get("path") == ".github/workflows/ci.yml", "Unexpected CI workflow")
    require(run.get("status") == "completed" and run.get("conclusion") == "success",
            "CI is not complete and successful")
    require(len(required_jobs) == len(set(required_jobs)) and bool(required_jobs),
            "Invalid required-job inventory")
    require(len(jobs) == len(required_jobs) and
            {job.get("name") for job in jobs} == set(required_jobs),
            "CI job inventory differs from release policy")
    require(all(job.get("status") == "completed" and job.get("conclusion") == "success"
                for job in jobs), "A required job did not succeed")


def validate_artifacts(directory: Path, report: dict, version: str, sha: str) -> list[Path]:
    require(bool(re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", version)), "Invalid stable version")
    require(report.get("schema") == "anti-rea-forge.installation.v1" and
            report.get("ok") is True and report.get("source_commit") == sha and
            report.get("source_dirty") is False and
            report.get("version") == version and report.get("platform") == "Linux",
            "Installation report does not bind the release")
    installations = report.get("python_installations")
    require(type(installations) is list and len(installations) == 2,
            "Both wheel and source installations are required")
    for item in installations:
        require(item.get("version") == version and
                all(item.get(name) is True for name in (
                    "isolated_import", "clean_release_accepted", "renamed_source_map_blocked",
                    "leaked_key_blocked", "structured_key_blocked", "wasm_split_verified"))
                and item.get("native_resources_present") == 5 and
                item.get("asset_roundtrip_bytes") == 4096,
                "Installed Python controls are incomplete")
    javascript = report.get("javascript_installation", {})
    require(all(javascript.get(name) is True for name in (
        "installed_sdk", "clean_release_accepted", "source_map_blocked")),
        "Installed SDK controls are incomplete")
    expected = {f"open_release_guard-{version}-py3-none-any.whl",
                f"open_release_guard-{version}.tar.gz",
                f"anti-rea-forge-releaseguard-{version}.tgz"}
    records = report.get("artifacts")
    require(type(records) is list and len(records) == 3 and
            {record.get("name") for record in records} == expected,
            "Unexpected release archive inventory")
    require({item.get("artifact") for item in installations} ==
            {name for name in expected if not name.endswith(".tgz")},
            "Python installation evidence names different archives")
    paths = []
    for record in records:
        path = directory / record["name"]
        require(path.is_file() and not path.is_symlink(), "Archive missing or linked")
        require(type(record.get("bytes")) is int and record["bytes"] == path.stat().st_size,
                "Archive size changed")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == record.get("sha256"),
                "Archive digest changed")
        paths.append(path)
    return sorted(paths)


def api(path: str, *, missing_ok: bool = False, payload: dict | None = None):
    token = os.environ["GH_TOKEN"]
    request = urllib.request.Request("https://api.github.com/" + path,
                                    data=json.dumps(payload).encode() if payload is not None else None,
                                    headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "anti-rea-forge-release"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if missing_ok and error.code == 404:
            return {}
        raise RuntimeError(f"GitHub API request failed with HTTP {error.code}") from None


def gh(*args: str) -> None:
    subprocess.run(["gh", *args, "--repo", REPOSITORY], check=True, timeout=300)


def release_by_tag(prefix: str, tag: str) -> dict:
    # The /releases/tags endpoint only returns published releases. Authenticated
    # collection reads also expose drafts; use their numeric ID for later reads.
    found = []
    for page in range(1, 101):
        releases = api(prefix + f"releases?per_page=100&page={page}")
        found.extend(item for item in releases if item.get("tag_name") == tag)
        if len(releases) < 100:
            require(len(found) <= 1, "Ambiguous existing release tag")
            return found[0] if found else {}
    raise ValueError("Release inventory exceeds the inspection budget")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    policy = json.loads((ROOT / "release-policy.json").read_text(encoding="utf-8"))
    version = policy["version"]
    require(policy.get("publish") is True, "Release publication is not enabled")
    require(re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", version) is not None, "Invalid version")
    tag = "v" + version
    notes = ROOT / "docs/releases" / (tag + ".md")
    require(notes.is_file(), "Release notes are required")
    prefix = f"repos/{REPOSITORY}/"
    existing = release_by_tag(prefix, tag)
    if existing:
        require(existing.get("draft") is False, "An existing draft needs review; it will not be overwritten")
        print(json.dumps({"already_published": True, "url": existing["html_url"]}))
        return 0
    sha = api(prefix + "git/ref/heads/main")["object"]["sha"]
    run = api(prefix + f"actions/runs/{args.run_id}")
    job_data = api(prefix + f"actions/runs/{args.run_id}/jobs?filter=latest&per_page=100")
    jobs = job_data["jobs"]
    require(job_data["total_count"] == len(jobs), "Uncollected CI jobs")
    validate_ci(run, jobs, sha, policy["required_jobs"])
    require(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                    text=True).strip() == sha, "Checkout differs from validated main")
    report_path = args.artifacts / "installation-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    archives = validate_artifacts(args.artifacts, report, version, sha)
    require(not api(prefix + "git/ref/tags/" + tag, missing_ok=True),
            "An existing tag will not be reused or moved")
    evidence = {"schema": "anti-rea-forge.release.v1", "version": version,
                "source_commit": sha, "ci_run": run["html_url"], "ci_run_id": args.run_id,
                "jobs": [{"name": job["name"], "conclusion": job["conclusion"],
                          "url": job["html_url"]} for job in jobs],
                "installation": report,
                "scope": "CI and installed-artifact evidence; no universal reverse-engineering guarantee."}
    evidence_path = args.artifacts / "release-evidence.json"
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    assets = archives + [report_path, evidence_path]
    checksums = args.artifacts / "SHA256SUMS"
    checksums.write_text("".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                                 for path in assets), encoding="utf-8")
    assets.append(checksums)
    # GitHub does not materialize a new draft's pending tag. Create the absent
    # lightweight ref explicitly; POST never moves an existing tag.
    api(prefix + "git/refs", payload={"ref": "refs/tags/" + tag, "sha": sha})
    gh("release", "create", tag, *(str(path) for path in assets), "--draft", "--verify-tag", "--target", sha,
       "--title", f"Anti-REA Forge {tag}", "--notes-file", str(notes))
    draft = release_by_tag(prefix, tag)
    require(bool(draft), "Uploaded draft is missing")
    uploaded = api(prefix + f"releases/{draft['id']}")
    require(uploaded.get("draft") is True, "Release must remain a draft until verified")
    require(uploaded.get("tag_name") == tag and uploaded.get("prerelease") is False,
            "Draft release identity differs")
    remote = {asset["name"]: asset for asset in uploaded["assets"]}
    require(set(remote) == {path.name for path in assets}, "Uploaded asset inventory differs")
    for path in assets:
        item = remote[path.name]
        require(item["size"] == path.stat().st_size, "Uploaded asset size differs")
        require(item.get("digest") == "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
                "Uploaded asset digest differs")
    require(api(prefix + "git/ref/heads/main")["object"]["sha"] == sha,
            "Main changed; the release remains a draft")
    require(api(prefix + "git/ref/tags/" + tag)["object"]["sha"] == sha,
            "Release tag does not identify the validated commit")
    gh("release", "edit", tag, "--draft=false", "--latest")
    final = api(prefix + f"releases/{draft['id']}")
    require(final.get("tag_name") == tag and final.get("draft") is False and final.get("prerelease") is False,
            "Final publication did not complete")
    print(json.dumps({"published": True, "tag": tag, "commit": sha, "url": final["html_url"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
