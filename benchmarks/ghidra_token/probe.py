"""Run a pinned, real Ghidra static-extraction/replay control on synthetic Linux ELFs.

Normal CI: python probe.py --archive /path/to/ghidra_12.2_PUBLIC_20261016.zip --out new.json
The optional direct Java launcher uses the same official AnalyzeHeadless class and
VM settings from LaunchSupport when the host shell cannot use /dev/fd. It does
not change Ghidra. No third-party input binary or user-chosen token is accepted.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
ARCHIVE = "ghidra_12.2_PUBLIC_20261016.zip"
ARCHIVE_SHA = "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67"
ARCHIVE_BYTES = 569_712_708
ARCHIVE_URL = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/" + ARCHIVE
VERSION = "12.2"
TOKEN = re.compile(r"rg1_[0-9a-f]{64}")
DOMAIN = b"OpenReleaseGuard/native-token/v1\0"
CASES = ("embedded_reference", "verifier_only", "verifier_plus_accidental_plaintext")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(file):
    h = hashlib.sha256()
    with file.open("rb") as stream:
        for data in iter(lambda: stream.read(1 << 20), b""):
            h.update(data)
    return h.hexdigest()


def run(argv, cwd, env, *, data=None, ok=(0,), timeout=180):
    proc = subprocess.run(list(map(str, argv)), cwd=cwd, env=env, input=data,
                          capture_output=True, timeout=timeout, check=False)
    if proc.returncode not in ok:
        diagnostic = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")[-9000:]
        raise RuntimeError(f"{Path(str(argv[0])).name}: exit {proc.returncode}: "
                           + TOKEN.sub("<fixture-token>", diagnostic))
    return proc


def get_ghidra(args, work, env):
    if args.archive is None:
        return args.ghidra_home.resolve(strict=True)
    require(args.archive.is_file() and args.archive.stat().st_size == ARCHIVE_BYTES,
            "Wrong official Ghidra archive size")
    require(sha(args.archive) == ARCHIVE_SHA, "Wrong official Ghidra archive SHA-256")
    # The pinned official archive contains executable launchers and native analyzers.
    # Unzip only after authenticating its complete contents; no installer runs.
    directory = work / "tools"
    directory.mkdir()
    run(["unzip", "-q", args.archive.resolve(), "-d", directory], work, env, timeout=240)
    return directory / "ghidra_12.2_PUBLIC"


def launch_command(args, home, work, env):
    if not args.direct_java:
        return [home / "support/analyzeHeadless"]
    java = Path(env["JAVA_HOME"]) / "bin/java"
    base = [java, "-Duser.home=" + str(work / "home"), "-Djava.io.tmpdir=" + str(work / "tmp")]
    options = run([*base, "-cp", home / "support/LaunchSupport.jar", "LaunchSupport", home, "-vmargs"],
                  work, env).stdout.decode().splitlines()
    require("-Djava.system.class.loader=ghidra.GhidraClassLoader" in options,
            "Missing Ghidra class loader option")
    return [*base, *options, "-Xmx1G", "-XX:ParallelGCThreads=2", "-XX:CICompilerCount=2",
            "-Djava.awt.headless=true", "-cp", home / "Ghidra/Framework/Utility/lib/Utility.jar",
            "ghidra.Ghidra", "ghidra.app.util.headless.AnalyzeHeadless"]


def build_cpp(case_no, work, env, cxx, headers, token, decoy):
    case = work / CASES[case_no]
    source, binary = case / "source", case / "input"
    source.mkdir(parents=True)
    binary.mkdir()
    materials = '#define RG_DECOY "' + decoy + '"\n'
    if case_no != 1:
        materials += '#define RG_LEAKED_REFERENCE "' + token + '"\n'
    (source / "material.hpp").write_text(materials, encoding="ascii")
    target = binary / "sample"
    run([cxx, "-std=c++17", "-O1", "-g0", "-fno-inline", "-fno-builtin-memcmp",
         f"-DRG_CASE={case_no}", "-I", source, "-I", headers, HERE / "fixture.cpp",
         "-o", target, "-lcrypto"], case, env)
    return target


def evaluate(program, candidate, env):
    result = run([program], program.parent, env, data=(candidate + "\n").encode("ascii"), ok=(0, 1))
    require((result.returncode, result.stdout, result.stderr) in
            [(0, b"ACCEPTED\n", b""), (1, b"DENIED\n", b"")], "Unexpected native response")
    return result.returncode == 0


def inspect(case_no, target, launcher, work, env, token, decoy, expected_digest):
    before = sha(target)
    # Independent post-build inventory control; these bytes are never handed to
    # Ghidra as a search key. Ghidra independently enumerates public-format candidates.
    raw_elf = target.read_bytes()
    raw_presence = {encoding: token.encode(encoding) in raw_elf for encoding in
                    ("ascii", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")}
    require(raw_presence["ascii"] == (case_no != 1)
            and (case_no != 1 or not any(raw_presence.values())), "Unexpected raw ELF token exposure")
    case = CASES[case_no]
    projects = work / "projects"
    report = work / (case + "-private-observation.json")
    proc = run([*launcher, projects, case, "-import", target, "-readOnly", "-deleteProject",
                "-analysisTimeoutPerFile", "120", "-max-cpu", "2",
                "-scriptPath", HERE, "-postScript", "InspectTokenGate.java", report,
                "-log", work / (case + "-ghidra.log"), "-scriptlog", work / (case + "-script.log")],
               work, env, timeout=300)
    require(b"RELEASEGUARD_GHIDRA_COMPLETE" in proc.stdout + proc.stderr and report.is_file(),
            "Ghidra did not complete the measurement: " +
            TOKEN.sub("<fixture-token>", (proc.stdout + proc.stderr).decode(errors="replace")[-5200:]))
    result = json.loads(report.read_bytes())
    require(result["ghidra_version"] == VERSION and result["input_sha256"].lower() == before
            and result["analysis_timed_out"] is False and "ELF" in result["format"]
            and result["language"].startswith("x86:LE:64:"), "Wrong analyzer, input, architecture or timeout")
    require(result["nonexternal_functions"] > 0 and result["initialized_loaded_blocks"] > 0
            and result["initialized_loaded_bytes"] > 68, "Empty analysis")
    decompiled = result["decompiled_functions"]
    gate = [f for f in decompiled if f["name"] == "rg_admit"]
    require(len(gate) == 1 and gate[0]["body_addresses"] > 0 and gate[0]["decompiled_c_bytes"] > 32
            and gate[0]["mentions_comparison" if case_no == 0 else "mentions_token_verifier"],
            "Expected admission logic was not decompiled: " + repr(gate))
    memory, pseudo = set(result["memory_candidates"]), set(result["decompiler_candidates"])
    candidates = memory | pseudo
    require(all(TOKEN.fullmatch(s) for s in candidates) and decoy in memory, "Candidate control failed")
    tested = {candidate: evaluate(target, candidate, env) for candidate in candidates}
    accepted = {candidate for candidate, ok in tested.items() if ok}
    require(accepted == (set() if case_no == 1 else {token}), "Native replay did not match the expected control")
    require(evaluate(target, token, env) and not evaluate(target, decoy, env)
            and not evaluate(target, "invalid", env), "Native functional control failed")
    public_digest_observed = False
    digest_replay = None
    if case_no != 0:
        public_digest_observed = any(
            d["bytes_hex"] == expected_digest and d["references"] > 0 for d in result["public_digest_symbols"]
        )
        require(public_digest_observed, "Ghidra did not identify the referenced public digest")
        # Use the bytes actually observed by Ghidra, not the known good token.
        observed = next(d["bytes_hex"] for d in result["public_digest_symbols"]
                        if d["bytes_hex"] == expected_digest and d["references"] > 0)
        digest_replay = evaluate(target, "rg1_" + observed, env)
        require(not digest_replay, "Public digest was accepted as a credential")
    require(sha(target) == before, "Native program changed during the test")
    return {
        "binary_sha256": before, "binary_bytes": target.stat().st_size, "unchanged": True,
        "exact_reference_in_raw_elf": raw_presence,
        "headless_exit": proc.returncode, "analysis_timed_out": result["analysis_timed_out"],
        "java_runtime": result["java_runtime"], "java_vendor": result["java_vendor"],
        "language": result["language"], "nonexternal_functions": result["nonexternal_functions"],
        "initialized_loaded_blocks": result["initialized_loaded_blocks"],
        "initialized_loaded_bytes": result["initialized_loaded_bytes"],
        "decompiled_functions": decompiled, "decompiled_admission_gate": True,
        "public_decoy_found_in_memory": True, "memory_candidates": len(memory),
        "decompiler_candidates": len(pseudo), "distinct_candidates_replayed": len(tested),
        "accepted_extracted_candidates": len(accepted),
        "accepted_candidates_from_memory": len(accepted & memory),
        "accepted_candidates_from_decompiled_c": len(accepted & pseudo),
        "referenced_public_digest_recovered": public_digest_observed if case_no else None,
        "public_digest_as_token_accepted": digest_replay,
        "legitimate_token_accepted": True, "wrong_and_malformed_denied": True,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive", type=Path, help="Official Ghidra 12.2 ZIP; size and hash verified")
    source.add_argument("--ghidra-home", type=Path, help="Preverified, extracted Ghidra 12.2 (archive not rehashed)")
    p.add_argument("--out", type=Path, required=True, help="New redacted JSON report path")
    p.add_argument("--python", default=sys.executable, help="Interpreter with Release Guard installed")
    p.add_argument("--direct-java", action="store_true", help="Use official Java entry point; requires JAVA_HOME")
    args = p.parse_args()
    require(not os.path.lexists(args.out), "Output path already exists")
    require(platform.system() == "Linux" and platform.machine() in {"x86_64", "amd64"},
            "Benchmark fixture targets Linux x86-64")
    python = os.path.abspath(shutil.which(args.python) or args.python)
    cxx = shutil.which("g++")
    require(cxx, "g++ required")
    with tempfile.TemporaryDirectory(prefix="rg-ghidra-") as temp:
        work = Path(temp).resolve()
        for sub in ("projects", "home", "tmp", "issuer", "public"):
            (work / sub).mkdir()
        env = {key: os.environ[key] for key in ("PATH", "JAVA_HOME", "LD_LIBRARY_PATH") if key in os.environ}
        env.update({"HOME": str(work / "home"), "TMPDIR": str(work / "tmp"), "LANG": "C",
                    "GHIDRA_HEADLESS_MAXMEM": "1G",
                    "GHIDRA_JAVA_OPTIONS": f"-Duser.home={work}/home -Djava.io.tmpdir={work}/tmp"})
        home = get_ghidra(args, work, env)
        require((home / "support/analyzeHeadless").is_file(), "Not a Ghidra distribution")
        launcher = launch_command(args, home, work, env)
        headers, secret_file = work / "public" / "include", work / "issuer" / "token"
        run([python, "-I", "-m", "releaseguard", "native-token-issue", "--public-dir", headers,
             "--secret-out", secret_file], work, env)
        private = secret_file.read_bytes()
        require(re.fullmatch(rb"rg1_[0-9a-f]{64}\n", private), "Invalid issuer output")
        token = private[:-1].decode("ascii")
        decoy = "rg1_" + secrets.token_hex(32)
        require(token != decoy, "Fresh control token collided")
        digest = hashlib.sha256(DOMAIN + token.encode("ascii")).hexdigest()
        cases = {}
        for i, name in enumerate(CASES):
            target = build_cpp(i, work, env, cxx, headers, token, decoy)
            cases[name] = inspect(i, target, launcher, work, env, token, decoy, digest)
        result = {
            "schema": "releaseguard-ghidra-native-token/v1", "ok": True,
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "ghidra_version": VERSION, "official_archive_url": ARCHIVE_URL,
            "archive_sha256_verified_in_run": ARCHIVE_SHA if args.archive is not None else None,
            "launcher": "official Java AnalyzeHeadless via LaunchSupport VM options" if args.direct_java
                        else "official support/analyzeHeadless",
            "host": platform.platform(), "python": platform.python_version(),
            "issuer_version": run([python, "-I", "-m", "releaseguard", "--version"], work, env).stdout.decode().strip(),
            "compiler": run([cxx, "--version"], work, env).stdout.decode().splitlines()[0],
            "openssl": run(["openssl", "version"], work, env).stdout.decode().strip(),
            "compiler_profile": ["-std=c++17", "-O1", "-g0", "-fno-inline", "-fno-builtin-memcmp", "-lcrypto"],
            "fixture_cpp_sha256": sha(HERE / "fixture.cpp"),
            "verifier_implementation_sha256": sha(headers / "releaseguard/token_verify.hpp"),
            "script_sha256": sha(HERE / "InspectTokenGate.java"), "cases": cases,
            "scope": "Complete rg1_ token literals in initialized loaded blocks and selected decompiled C, "
                     "replayed against these unchanged native Linux fixtures. Not a general Ghidra block.",
            "limitations": [
                "The ordinary control embeds plaintext; it is not the separate historical RG_TEXT decoder-reconstruction test.",
                "Named fixture functions and verifier data are intentionally retained. The gate remains decompilable and patchable.",
                "No test of arbitrary reconstruction, token capture during use, brute force, an AI agent, or a remote service.",
            ],
        }
    with args.out.open("x", encoding="utf-8") as out:
        json.dump(result, out, indent=2)
        out.write("\n")
    print("Ghidra 12.2 completed and decompiled all three admission gates; accepted extracted candidates: "
          + "/".join(str(c["accepted_extracted_candidates"]) for c in cases.values()))


if __name__ == "__main__":
    main()
