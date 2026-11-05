"""Reproduce build-only costs and authorization controls on synthetic files.

No external target, model, REA process or application workload is executed.
Timings describe this host and this synthetic input, not runtime performance.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import platform
import statistics
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard.analysis import check_analysis_authorization, issue_analysis_grant
from releaseguard.core import read_document, write_new
from releaseguard.project import check_project, init_project, prepare_release


def snapshot(root: Path) -> dict:
    return {
        path.relative_to(root).as_posix(): {
            "size": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mtime_ns": path.stat().st_mtime_ns,
            "mode": path.stat().st_mode,
        }
        for path in sorted(root.rglob("*")) if path.is_file()
    }


def timed(call):
    start = time.perf_counter()
    result = call()
    return result, (time.perf_counter() - start) * 1000


def summary(values: list[float]) -> dict:
    return {"min_ms": min(values), "median_ms": statistics.median(values), "max_ms": max(values)}


def run(size_mib: int, repeats: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="analysis boundary ") as temporary:
        work = Path(temporary)
        root = work / "dist"
        root.mkdir()
        marker = work / "target-executed"
        (root / "app.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('unexpected target execution')\n",
            encoding="utf-8",
        )
        block = b"PUBLIC-SYNTHETIC-BENCHMARK-DATA:" + bytes(range(32, 127))
        amount = size_mib * 1024 * 1024
        payload = (block * (amount // len(block) + 1))[:amount]
        (root / "data.bin").write_bytes(payload)
        before = snapshot(root)
        private = Ed25519PrivateKey.generate()
        config = work / "guard/project.json"
        _, setup_ms = timed(lambda: init_project(root, "synthetic-demo", config.parent))
        _, scan_ms = timed(lambda: check_project(config))
        prepared, prepare_ms = timed(lambda: prepare_release(config, private, "1", work / "evidence"))
        manifest = read_document(work / "evidence/manifest.json")
        context = {"product": "synthetic-demo", "release": "1", "subject": "synthetic-analyst",
                   "audience": "synthetic-gateway"}
        grant = issue_analysis_grant(private, manifest, **context, operations=["inspect"])

        def check(grant_value=grant, **overrides):
            expected = {**context, "operation": "inspect", **overrides}
            return check_analysis_authorization(manifest, root, private.public_key(),
                                                **expected, grant=grant_value)

        allow_times, deny_times = [], []
        allowed, denied = {}, {}
        for _ in range(repeats):
            allowed, elapsed = timed(check)
            allow_times.append(elapsed)
            denied, elapsed = timed(lambda: check(None))
            deny_times.append(elapsed)
        unchanged = before == snapshot(root)
        no_execution = not marker.exists()
        other_scope = check(operation="instrument")
        other_subject = check(subject="another-analyst")
        past = datetime.now(timezone.utc) - timedelta(hours=2)
        expired_grant = issue_analysis_grant(private, manifest, **context, operations=["inspect"],
                                            ttl_seconds=1, now=past)
        expired = check(expired_grant)
        # Only the synthetic fixture is deliberately changed for this negative control.
        (root / "data.bin").write_bytes(b"changed synthetic bytes")
        changed = check()
        controls = {
            "matching_grant_allowed": allowed.get("authorized") is True,
            "missing_grant_denied": denied.get("reason") == "grant_required",
            "missing_grant_skips_release_hash": denied["checks"]["release_integrity"] is False,
            "independent_scope_denied": other_scope.get("reason") == "operation_not_granted",
            "wrong_subject_denied": other_subject.get("reason") == "context_mismatch",
            "expired_grant_denied": expired.get("reason") == "grant_expired",
            "changed_release_denied": changed.get("reason") == "release_mismatch",
            "target_bytes_size_mtime_mode_unchanged_by_readonly_workflow": unchanged,
            "target_execution_marker_absent": no_execution,
            "sidecars_outside_release": prepared["prepared"] and not (root / "manifest.json").exists(),
        }
        return {
            "ok": all(controls.values()),
            "schema": "analysis-boundary-observation/v1",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "environment": {"python": platform.python_version(), "platform": platform.platform()},
            "sample": {"files": len(before), "bytes": sum(item["size"] for item in before.values()),
                       "payload_mib": size_mib, "repeats": repeats},
            "controls": controls,
            "timings": {"project_init_ms": setup_ms, "check_ms": scan_ms,
                        "prepare_including_scan_and_sign_ms": prepare_ms,
                        "authorized_preflight": summary(allow_times),
                        "missing_grant_preflight": summary(deny_times)},
            "limitations": [
                "Synthetic functional controls, not a REA/model refusal or cracking-resistance evaluation.",
                "Timings are observations on this host; no application workload or overhead ratio was measured.",
                "The workflow does not rewrite target files or add application startup/runtime hooks.",
                "Build and analysis checks still consume CPU and I/O; run them outside the application workload.",
                "The SDK handler boundary is tested separately; direct tool calls and check-to-use replacement remain outside it.",
            ],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="New JSON report path")
    parser.add_argument("--size-mib", type=int, default=4)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.size_mib <= 32 or not 1 <= args.repeats <= 10:
        parser.error("size-mib must be 1..32 and repeats must be 1..10")
    report = run(args.size_mib, args.repeats)
    write_new(args.out, json.dumps(report, indent=2, ensure_ascii=True).encode("ascii") + b"\n")
    print(json.dumps(report, indent=2, ensure_ascii=True))
    return 0 if report["ok"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
