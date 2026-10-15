#!/usr/bin/env python3
"""Demonstrate the runtime limit of RG_TEXT on our own temporary Linux/GCC fixture.

Install this checkout, or run with PYTHONPATH=src from the repository root.
Each run creates its own random synthetic secret, C++ source, native header
assets, executable and comparison probe, then automatically removes them.
There is no option to inspect an existing or third-party binary.

Exit 0 means the experiment completed: the runtime secret was recovered and
accepted by the unmodified fixture. That is a FAILED protection goal, not a
protection pass. Incomplete experiments report an unknown protection outcome
and exit 2. This is not a REA or general crack-resistance evaluation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

try:
    from releaseguard import __version__
    from releaseguard.core import GuardError, write_new
    from releaseguard.native import init_native
except ImportError as exc:
    raise SystemExit(
        "releaseguard is unavailable; install this checkout with "
        "'python -m pip install -e .' or run with PYTHONPATH=src."
    ) from exc


SAMPLE_FLAGS = [
    "-std=c++17", "-O2", "-flto", "-fvisibility=hidden",
    "-fvisibility-inlines-hidden", "-fstack-protector-strong", "-fPIE",
    "-pie", "-s", "-Wl,-z,relro,-z,now,-z,noexecstack",
    # Deliberately exercise the dynamically linked strcmp runtime boundary.
    "-fno-builtin-strcmp",
]
PROBE_FLAGS = ["-std=c++17", "-O2", "-shared", "-fPIC", "-fno-builtin"]
ENCODINGS = ("utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")

SAMPLE_SOURCE = r'''#include "releaseguard_build.hpp"
#include "releaseguard/literal.hpp"
#include <cstdio>
#include <cstring>
int main(int argc, char** argv) {
    if (argc != 2) { std::puts("USAGE: sample VALUE"); return 2; }
    auto expected = RG_TEXT("@SECRET@");
    const bool accepted = std::strcmp(argv[1], expected.c_str()) == 0;
    std::puts(accepted ? "ACCEPTED" : "DENIED");
    return accepted ? 0 : 1;
}
'''

PROBE_SOURCE = r'''#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <unistd.h>
#include <cerrno>
#include <cstddef>

using compare_fn = int (*)(const char*, const char*);
static compare_fn real_compare = nullptr;
static thread_local bool resolving = false;
static thread_local bool recording = false;

// Also used during resolver recursion; this preserves strcmp's unsigned-byte
// lexicographic contract instead of forcing either acceptance or rejection.
static int semantic_compare(const char* a, const char* b) {
    while (*a && *a == *b) { ++a; ++b; }
    return static_cast<unsigned char>(*a) - static_cast<unsigned char>(*b);
}
static bool same(const char* a, const char* b) {
    return a && b && semantic_compare(a, b) == 0;
}
static void emit(const char* value) {
    static const char prefix[] = "RG_BOUNDARY_ARG_V1:";
    static const char hex[] = "0123456789abcdef";
    char buffer[sizeof(prefix) + 256 + 1];
    std::size_t used = 0;
    for (std::size_t i = 0; prefix[i]; ++i) buffer[used++] = prefix[i];
    for (std::size_t i = 0; i < 128 && value[i]; ++i) {
        const auto byte = static_cast<unsigned char>(value[i]);
        buffer[used++] = hex[byte >> 4];
        buffer[used++] = hex[byte & 15];
    }
    buffer[used++] = '\n';
    std::size_t sent = 0;
    while (sent < used) {
        const auto count = ::write(STDERR_FILENO, buffer + sent, used - sent);
        if (count > 0) sent += static_cast<std::size_t>(count);
        else if (count < 0 && errno == EINTR) continue;
        else break;
    }
}
extern "C" int strcmp(const char* left, const char* right) {
    if (!real_compare && !resolving) {
        resolving = true;
        real_compare = reinterpret_cast<compare_fn>(dlsym(RTLD_NEXT, "strcmp"));
        resolving = false;
    }
    const int result = real_compare ? real_compare(left, right)
                                    : semantic_compare(left, right);
    // The library is passed only to our new fixture. Additionally restrict
    // records to calls originating in that exact executable, not its libraries.
    if (!recording && !resolving) {
        recording = true;
        Dl_info caller{};
        if (dladdr(__builtin_return_address(0), &caller) &&
            same(caller.dli_fname, @SAMPLE_PATH@)) {
            emit(left);
            emit(right);
        }
        recording = false;
    }
    return result;
}
'''


class ExperimentIncomplete(RuntimeError):
    """The required controlled observations could not all be established."""


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def run(
    command: list[str], *, cwd: Path, env: dict[str, str], label: str,
    timeout: int = 60, require_success: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        process = subprocess.Popen(
            command, cwd=cwd, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True,
        )
    except OSError:
        raise ExperimentIncomplete(f"{label} could not be started") from None
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # GCC can spawn linker/compiler children: stop our entire new session.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            # No controlled fixture/compiler is expected to leave the group.
            # Do not let an inherited pipe make timeout cleanup unbounded.
            assert process.stdout is not None and process.stderr is not None
            process.stdout.close()
            process.stderr.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        # TimeoutExpired includes argv, which can contain the recovered value.
        raise ExperimentIncomplete(f"{label} exceeded its {timeout}-second timeout") from None
    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    if require_success and result.returncode:
        # Compiler diagnostics can quote the generated synthetic secret.
        raise ExperimentIncomplete(f"{label} failed with return code {result.returncode}")
    return result


def experiment() -> dict[str, Any]:
    started = time.monotonic()
    report: dict[str, Any] = {
        "format": "open-release-guard-runtime-boundary/v1",
        "releaseguard_version": __version__,
        "experiment_completed": False,
        "static_plaintext_absent": None,
        "runtime_secret_recovered": None,
        "unmodified_binary_accepts_recovered": None,
        "protection_goal_met": "unknown",
        "rea_evaluated": False,
        "notes": [
            "Exit 0 means experiment completion, not successful protection: recovery fails the protection goal.",
            "Only a newly generated, project-owned Linux/GCC fixture is compiled and executed; no binary input is accepted.",
            "The fixture deliberately uses dynamically linked strcmp; inline comparisons and other toolchains are not evaluated.",
            "RG_TEXT masks static literals reversibly and does not prevent observation of runtime plaintext.",
            "Null observations mean unknown; inability to recover is not evidence of successful protection.",
            "This is a reproducible boundary demonstration, not a REA study or protection probability estimate.",
        ],
    }
    # Child-specific copies only: never modify this process's global environment.
    clean_env = dict(os.environ)
    clean_env.pop("LD_PRELOAD", None)
    clean_env.pop("LD_AUDIT", None)
    try:
        if platform.system() != "Linux":
            raise ExperimentIncomplete("This experiment requires Linux and GCC g++")
        compiler = shutil.which("g++")
        if compiler is None:
            raise ExperimentIncomplete("GCC g++ was not found")
        with tempfile.TemporaryDirectory(prefix="rg-runtime-boundary-") as temporary:
            build = Path(temporary).resolve()
            version = run(
                [compiler, "--version"], cwd=build, env=clean_env,
                label="GCC version check", timeout=10,
            ).stdout.decode("utf-8", errors="replace").strip()
            if "Free Software Foundation" not in version:
                raise ExperimentIncomplete("The discovered g++ does not identify as GCC")
            report["environment"] = {
                "system": platform.system(), "machine": platform.machine(),
                "python": platform.python_version(), "compiler": "g++",
                "compiler_version": version,
            }
            secret = "RG_TEST_" + secrets.token_hex(16)
            report["synthetic_secret_sha256"] = digest(secret.encode("ascii"))
            assets = build / "assets"
            init_native(assets)
            sample_source = build / "sample.cpp"
            sample = build / "sample"
            probe_source = build / "probe.cpp"
            probe = build / "probe.so"
            write_new(sample_source, SAMPLE_SOURCE.replace("@SECRET@", secret).encode("ascii"), secret=True)
            # Bytewise octal escaping also handles non-ASCII or quoted TMPDIRs.
            sample_path_literal = '"' + "".join(
                f"\\{byte:03o}" for byte in os.fsencode(sample)
            ) + '"'
            write_new(probe_source, PROBE_SOURCE.replace(
                "@SAMPLE_PATH@", sample_path_literal,
            ).encode("ascii"))
            run([
                compiler, *SAMPLE_FLAGS, "-I", str(assets), "-I", str(assets / "include"),
                str(sample_source), "-o", str(sample),
            ], cwd=build, env=clean_env, label="Fixture compilation")
            binary = sample.read_bytes()
            report["binary"] = {
                "sha256_before": digest(binary), "size_bytes": len(binary),
                "sample_flags": SAMPLE_FLAGS, "probe_flags": PROBE_FLAGS,
            }
            report["static_plaintext_absent"] = all(
                secret.encode(encoding) not in binary for encoding in ENCODINGS
            )
            report["static_scan_encodings"] = list(ENCODINGS)
            if not report["static_plaintext_absent"]:
                raise ExperimentIncomplete("The generated binary unexpectedly contains the complete plaintext marker")
            run([
                compiler, *PROBE_FLAGS, str(probe_source), "-ldl", "-o", str(probe),
            ], cwd=build, env=clean_env, label="Scoped probe compilation")
            probe_env = dict(clean_env)
            probe_env["LD_PRELOAD"] = str(probe)
            observed = run(
                [str(sample), "WRONG"], cwd=build, env=probe_env,
                label="Fixture comparison observation", timeout=10, require_success=False,
            )
            report["probe"] = {
                "returncode": observed.returncode,
                "comparison_semantics_preserved": observed.returncode == 1 and observed.stdout == b"DENIED\n",
                "scope": "LD_PRELOAD only on the new sample, plus exact caller-executable path filtering",
            }
            candidates = {
                bytes.fromhex(match.decode("ascii"))
                for match in re.findall(rb"^RG_BOUNDARY_ARG_V1:([0-9a-f]+)$", observed.stderr, re.MULTILINE)
                if len(match) % 2 == 0
            }
            candidates = {item for item in candidates if re.fullmatch(rb"RG_TEST_[0-9a-f]{32}", item)}
            if len(candidates) != 1:
                raise ExperimentIncomplete("The scoped probe did not extract exactly one synthetic marker; protection outcome is unknown")
            recovered = candidates.pop()
            if not secrets.compare_digest(recovered, secret.encode("ascii")):
                raise ExperimentIncomplete("The observed marker does not match the independently generated synthetic value")
            report["runtime_secret_recovered"] = True
            report["recovered_secret_sha256"] = digest(recovered)
            if not report["probe"]["comparison_semantics_preserved"]:
                raise ExperimentIncomplete("The observation run did not preserve the expected rejection behavior")
            accepted = run(
                [str(sample), recovered.decode("ascii")], cwd=build, env=clean_env,
                label="Uninstrumented recovered-value verification", timeout=10, require_success=False,
            )
            rejected = run(
                [str(sample), "WRONG"], cwd=build, env=clean_env,
                label="Uninstrumented wrong-value verification", timeout=10, require_success=False,
            )
            accepts = accepted.returncode == 0 and accepted.stdout == b"ACCEPTED\n"
            rejects = rejected.returncode == 1 and rejected.stdout == b"DENIED\n"
            report["unmodified_binary_accepts_recovered"] = accepts
            report["verification"] = {
                "ld_preload_absent": "LD_PRELOAD" not in clean_env,
                "accepted_returncode": accepted.returncode,
                "accepted_stdout_sha256": digest(accepted.stdout),
                "wrong_returncode": rejected.returncode,
                "wrong_stdout_sha256": digest(rejected.stdout),
                "wrong_input_rejected": rejects,
            }
            after = digest(sample.read_bytes())
            report["binary"]["sha256_after"] = after
            report["binary"]["unchanged"] = after == report["binary"]["sha256_before"]
            if not accepts or not rejects or not report["binary"]["unchanged"]:
                raise ExperimentIncomplete("The uninstrumented acceptance/rejection or unchanged-file checks failed")
            report["experiment_completed"] = True
            report["protection_goal_met"] = False
    except (ExperimentIncomplete, GuardError, OSError, UnicodeError) as exc:
        # Internal labels never include source contents, probe output or argv.
        report["error"] = str(exc)
    report["elapsed_seconds"] = round(time.monotonic() - started, 6)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", type=Path,
        help="exclusively create JSON here; existing paths are never overwritten (default: stdout)",
    )
    args = parser.parse_args()
    try:
        if args.out is not None and (args.out.exists() or args.out.is_symlink()):
            raise FileExistsError(f"Output already exists: {args.out}")
        report = experiment()
        content = (json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")
        if args.out is None:
            sys.stdout.buffer.write(content)
        else:
            write_new(args.out, content)
    except (GuardError, OSError) as exc:
        print(f"runtime boundary experiment could not write its report: {exc}", file=sys.stderr)
        return 2
    return 0 if report["experiment_completed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
