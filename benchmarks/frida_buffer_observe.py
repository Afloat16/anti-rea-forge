#!/usr/bin/env python3
"""Observe only our compiled secure_buffer fixture through real Frida 17.23.2.

No external executable, PID, script or target is accepted. The fixture uses a
public synthetic byte pattern, not a credential. Frida reads the same owned
allocation at two exported checkpoints: during use and after explicit clear(),
before destruction. Only metadata and boolean observations leave the process.

Exit 0 means the two expected boundary observations were made, including that
live plaintext WAS READABLE. It does not mean protection against Frida passed.
Exit 2 means environment/setup failure or an incomplete/contradictory result.
This is not a REA CLI/provider/agent/model experiment or a whole-process dump.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
INCLUDE = ROOT / "src" / "releaseguard" / "data" / "include"
HEADER = INCLUDE / "releaseguard" / "secure_buffer.hpp"
FRIDA_VERSION = "17.23.2"
SIZE = 32

FIXTURE = r'''#include <releaseguard/secure_buffer.hpp>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <thread>

#if defined(_WIN32)
#define RG_EXPORT __declspec(dllexport) __declspec(noinline)
#else
#define RG_EXPORT __attribute__((visibility("default"), noinline, used))
#endif

unsigned char* volatile checkpoint_pointer = nullptr;
volatile std::size_t checkpoint_size = 0;
volatile int checkpoint_phase = 0;
volatile int checkpoint_status = 0;

extern "C" RG_EXPORT void rg_buffer_checkpoint(unsigned char* bytes,
    std::size_t size, int phase, int status) {
    // Observable writes keep these checkpoints in optimized builds. Their
    // explicit exports are observation aids, not a production target design.
    checkpoint_pointer = bytes;
    checkpoint_size = size;
    checkpoint_phase = phase;
    checkpoint_status = status;
}

int main() {
    try {
        // Both lanes wait for our parent to finish installing the observer.
        if (std::getchar() != '\n') return 2;
        // Optional lock avoids assuming host resource permissions. The header
        // still attempts lock/dump exclusion and reports the actual outcome.
        releaseguard::secure_buffer buffer(32, {false, false});
        const auto status = buffer.protection_status();
        const int flags = (status.locked ? 1 : 0) |
                          (status.dump_excluded ? 2 : 0) |
                          (status.guard_pages ? 4 : 0);
        for (std::size_t i = 0; i < buffer.size(); ++i)
            buffer.data()[i] = static_cast<unsigned char>((i * 29 + 17) % 251 + 1);
        rg_buffer_checkpoint(buffer.data(), buffer.size(), 1, flags);
        buffer.clear();
        rg_buffer_checkpoint(buffer.data(), buffer.size(), 2, flags);
        for (std::size_t i = 0; i < buffer.size(); ++i)
            if (buffer.data()[i] != 0) return 3;
        // Keep the allocation owned long enough for observation delivery.
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        return 0;
    } catch (...) {
        return 4;
    }
}
'''

SCRIPT = r'''"use strict";
const point = Process.mainModule.getExportByName("rg_buffer_checkpoint");
Interceptor.attach(point, {
  onEnter(args) {
    const size = args[1].toUInt32();
    const phase = args[2].toInt32();
    const flags = args[3].toInt32();
    if (size !== 32 || (phase !== 1 && phase !== 2)) {
      send({kind: "invalid_checkpoint"});
      return;
    }
    const bytes = new Uint8Array(args[0].readByteArray(size));
    let matches = true;
    let zero = true;
    for (let i = 0; i < size; ++i) {
      matches = matches && bytes[i] === ((i * 29 + 17) % 251 + 1);
      zero = zero && bytes[i] === 0;
    }
    send({kind: "checkpoint", phase: phase, byte_count: size,
      public_pattern_matches: matches, all_zero: zero,
      locked: (flags & 1) !== 0, dump_excluded: (flags & 2) !== 0,
      guard_pages: (flags & 4) !== 0});
  }
});
send({kind: "ready"});
'''


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _failure(stage: str, exc: Exception) -> dict[str, str]:
    # These operations handle only our public fixture. Do not include target
    # output, message data buffers, script sources or arbitrary payloads.
    return {"stage": stage, "type": type(exc).__name__, "message": str(exc)[:2000]}


def observations_match(rows: list[dict[str, Any]]) -> bool:
    if len(rows) != 2 or [row.get("phase") for row in rows] != [1, 2]:
        return False
    required = {"kind", "phase", "byte_count", "public_pattern_matches", "all_zero",
                "locked", "dump_excluded", "guard_pages"}
    for row in rows:
        if set(row) != required or row["kind"] != "checkpoint" or row["byte_count"] != SIZE:
            return False
        if type(row["phase"]) is not int or type(row["byte_count"]) is not int:
            return False
        if not all(type(row[name]) is bool for name in (
            "public_pattern_matches", "all_zero", "locked", "dump_excluded", "guard_pages"
        )):
            return False
    return (rows[0]["public_pattern_matches"] and not rows[0]["all_zero"]
            and not rows[1]["public_pattern_matches"] and rows[1]["all_zero"]
            and all(rows[0][field] == rows[1][field] for field in (
                "locked", "dump_excluded", "guard_pages")))


def _observe(frida: Any, binary: Path, mode: str) -> dict[str, Any]:
    if mode not in {"spawn", "attach"}:
        raise ValueError("Only the two owned-fixture launch modes are supported")
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    ready, detached = threading.Event(), threading.Event()
    detached_reason: list[str] = []
    mutex = threading.Lock()
    device = session = script = None
    pid = None
    owned_process = None
    owned_process_exit_code = None
    owned_process_alive_before_attach = None
    stage = "local_device"
    cleanup: dict[str, Any] = {"errors": []}

    def bounded(call, seconds: float = 5):
        cancellation = frida.Cancellable()
        timer = threading.Timer(seconds, cancellation.cancel)
        timer.daemon = True
        timer.start()
        try:
            with cancellation:
                return call()
        finally:
            timer.cancel()

    def message(value: dict[str, Any], data: bytes | None) -> None:
        del data  # Never export any target-supplied binary data.
        payload = value.get("payload")
        with mutex:
            if value.get("type") == "error":
                errors.append({"stage": "script", "type": "FridaScriptError",
                               "message": str(value.get("description", "script error"))[:2000]})
            elif value.get("type") == "send" and payload == {"kind": "ready"}:
                ready.set()
            elif value.get("type") == "send" and isinstance(payload, dict):
                fields = {"kind", "phase", "byte_count", "public_pattern_matches", "all_zero",
                          "locked", "dump_excluded", "guard_pages"}
                if set(payload) == fields and len(rows) < 4:
                    rows.append(dict(payload))
                else:
                    errors.append({"stage": "script", "type": "InvalidObservation",
                                   "message": "Unexpected fixture observation; raw payload omitted"})

    def on_detached(reason: str, crash: Any = None) -> None:
        del crash  # No memory/crash contents are retained.
        detached_reason.append(str(reason))
        detached.set()

    try:
        device = bounded(frida.get_local_device)
        if mode == "spawn":
            stage = "spawn_owned_fixture"
            pid = bounded(lambda: device.spawn([str(binary)], stdio="pipe"))
        else:
            stage = "launch_owned_fixture"
            owned_process = subprocess.Popen(
                [str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, cwd=binary.parent,
            )
            pid = owned_process.pid
            owned_process_alive_before_attach = owned_process.poll() is None
        stage = "attach_owned_fixture"
        session = bounded(lambda: device.attach(pid))
        session.on("detached", on_detached)
        stage = "create_script"
        script = bounded(lambda: session.create_script(SCRIPT, name="releaseguard-owned-buffer-observer"))
        script.on("message", message)
        stage = "load_script"
        bounded(script.load)
        if not ready.wait(2):
            raise TimeoutError("Observer did not report ready before target resume")
        if mode == "spawn":
            stage = "resume_owned_fixture"
            bounded(lambda: device.resume(pid))
            stage = "release_owned_fixture_input"
            bounded(lambda: device.input(pid, b"\n"))
        else:
            stage = "release_owned_fixture_input"
            output, error = owned_process.communicate(input=b"\n", timeout=5)
            owned_process_exit_code = owned_process.returncode
            if output or error or owned_process_exit_code != 0:
                raise RuntimeError("Observed own fixture did not exit 0 without output")
        stage = "observe_owned_fixture"
        if not detached.wait(5):
            raise TimeoutError("Owned fixture did not detach within the observation window")
    except Exception as exc:
        errors.append(_failure(stage, exc))
    finally:
        if owned_process is not None and owned_process.poll() is None:
            cleanup["owned_target_kill_attempted"] = True
            try:
                owned_process.kill()
                owned_process.communicate(timeout=3)
            except Exception as exc:
                cleanup["errors"].append(_failure("kill_owned_fixture", exc))
        elif mode == "spawn" and pid is not None and not detached.is_set():
            cleanup["owned_target_kill_attempted"] = True
            try:
                bounded(lambda: device.kill(pid), 3)
            except Exception as exc:
                cleanup["errors"].append(_failure("kill_owned_fixture", exc))
        if session is not None and not session.is_detached:
            try:
                bounded(session.detach, 3)
            except Exception as exc:
                cleanup["errors"].append(_failure("detach_owned_fixture", exc))
    with mutex:
        captured = list(rows)
    completed = (observations_match(captured) and not errors and not cleanup["errors"]
                 and detached_reason == ["process-terminated"])
    return {"mode": mode, "completed_expected_observations": completed, "observations": captured,
            "errors": errors, "cleanup": cleanup, "detached_reasons": detached_reason,
            "ready_observed": ready.is_set(), "owned_pid_acquired": pid is not None,
            "owned_process_alive_before_attach": owned_process_alive_before_attach,
            "owned_process_exit_code": owned_process_exit_code}


def experiment() -> dict[str, Any]:
    started = time.monotonic()
    report: dict[str, Any] = {
        "format": "open-release-guard-frida-buffer-observe/v1",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "environment_failure", "protection_outcome": "not_evaluated",
        "environment": {"system": platform.system(), "machine": platform.machine(),
                        "python": platform.python_version()},
        "fixture": {"owned_source_only": True, "public_synthetic_pattern": True,
                    "byte_count": SIZE, "source_sha256": _sha(FIXTURE.encode()),
                    "observer_sha256": _sha(SCRIPT.encode()),
                    "requested_lock_required": False, "requested_dump_exclusion_required": False},
        "scope": {"real_frida": False, "rea_cli": False, "rea_provider": False,
                  "rea_agent_model_pipeline": False, "whole_process_dump": False,
                  "third_party_target": False, "freed_memory_read": False,
                  "real_frida_instrumentation_completed": False},
        "limitations": [
            "Checkpoint exports are explicit observation aids in our synthetic fixture.",
            "Live public-pattern visibility is the expected limit, not an anti-Frida protection pass.",
            "After-clear reads cover only 32 bytes of the same still-owned allocation.",
            "No assertion covers copies, registers, whole-process dumps, real secrets or real applications.",
            "Memory-lock/dump-exclusion flags report this run only; they do not prevent in-process reads.",
        ],
    }
    stage = "load_frida"
    try:
        if platform.system() not in {"Linux", "Windows"}:
            raise RuntimeError("Fixture build supports Linux or Windows only")
        frida = importlib.import_module("frida")
        report["environment"]["frida_version"] = frida.__version__
        if frida.__version__ != FRIDA_VERSION:
            raise RuntimeError(f"Expected Frida {FRIDA_VERSION}; installed version differs")
        stage = "select_compiler"
        names = ("cl",) if os.name == "nt" else ("g++", "clang++")
        compiler = next((path for name in names if (path := shutil.which(name))), None)
        if compiler is None:
            raise RuntimeError("C++17 compiler unavailable")
        report["environment"]["compiler"] = Path(compiler).name
        version_args = [compiler] if os.name == "nt" else [compiler, "--version"]
        version = subprocess.run(version_args, capture_output=True, text=True, timeout=5)
        version_text = (version.stdout or version.stderr).splitlines()
        report["environment"]["compiler_version"] = version_text[0] if version_text else "unreported"
        report["fixture"]["header_sha256"] = _sha(HEADER.read_bytes())
        stage = "compile_owned_fixture"
        # Own fixture artifacts live under the workspace and are removed on return.
        with tempfile.TemporaryDirectory(prefix="rg-frida-buffer-", dir=ROOT) as temp:
            work = Path(temp)
            source = work / "fixture.cpp"
            source.write_text(FIXTURE, encoding="utf-8")
            binary = work / ("fixture.exe" if os.name == "nt" else "fixture")
            if os.name == "nt":
                flags = ["/nologo", "/std:c++17", "/EHsc", "/O2", f"/I{INCLUDE}",
                         str(source), f"/Fe:{binary}", f"/Fo:{work / 'fixture.obj'}"]
            else:
                flags = ["-std=c++17", "-O2", "-Wall", "-Wextra", "-pthread", "-rdynamic",
                         "-I", str(INCLUDE), str(source), "-o", str(binary)]
            built = subprocess.run([compiler, *flags], capture_output=True, text=True,
                                   timeout=30, cwd=work)
            report["fixture"]["compiler_exit_code"] = built.returncode
            report["fixture"]["optimization"] = "O2"
            if built.returncode:
                raise RuntimeError((built.stderr or built.stdout)[:2000])
            report["fixture"]["binary_sha256"] = _sha(binary.read_bytes())
            stage = "unobserved_fixture_control"
            control = subprocess.run([str(binary)], input=b"\n", capture_output=True, timeout=5, cwd=work)
            report["fixture"]["unobserved_control_exit_code"] = control.returncode
            report["fixture"]["unobserved_control_no_output"] = not control.stdout and not control.stderr
            if control.returncode or control.stdout or control.stderr:
                raise RuntimeError("Unobserved own fixture did not exit 0 without output")
            stage = "frida_observation"
            report["scope"]["real_frida"] = True
            attempts = [_observe(frida, binary, mode) for mode in ("spawn", "attach")]
            report["frida_attempts"] = attempts
            completed = [attempt for attempt in attempts if attempt["completed_expected_observations"]]
            report["scope"]["real_frida_instrumentation_completed"] = bool(completed)
            if completed:
                report["status"] = "completed_expected_boundary_observations"
                report["protection_outcome"] = "live_owned_plaintext_readable_after_clear_owned_bytes_zero"
            elif any(attempt["errors"] or attempt["cleanup"]["errors"] for attempt in attempts):
                report["status"] = "environment_or_instrumentation_failure"
            else:
                report["status"] = "incomplete_or_contradictory_observations"
    except Exception as exc:
        report["error"] = _failure(stage, exc)
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="Write a new JSON result file; existing files are refused")
    args = parser.parse_args()
    if args.out is not None and (args.out.exists() or args.out.is_symlink()):
        parser.error("--out must name a new result file")
    report = experiment()
    document = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as output:
            output.write(document)
    sys.stdout.write(document)
    return 0 if report["status"] == "completed_expected_boundary_observations" else 2


if __name__ == "__main__":
    raise SystemExit(main())
