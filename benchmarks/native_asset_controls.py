"""Exercise actual native sealed data with independent initialized-byte extraction."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

from ghidra_token.probe import ARCHIVE_SHA, VERSION, get_ghidra, launch_command
from sealed_native.elf_bytes import verify_loaded_bytes
from releaseguard.core import GuardError
from releaseguard.native_asset import export_native_asset
from releaseguard.sealed import open_asset, seal_asset

HERE = Path(__file__).resolve().parent / "sealed_native"
CASES = ("plaintext", "encrypted", "key_leak")
CONTEXT = dict(product="NativeAssetFixture", release="v1", purpose="reference-data", asset_id="random32")
PATCH = bytes.fromhex("b8 01 00 00 00 c3")
HOOK_MARKER = b"RG_GCM_FINAL_FORCED\n"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def command(args, **kwargs):
    return subprocess.check_output(list(map(str, args)), timeout=180, **kwargs)


def c_array(name, data):
    return f"static const unsigned char {name}[{len(data)}] = {{" + ",".join(str(b) for b in data) + "};\n"


def invoke(binary, key, hook=None):
    env = os.environ.copy()
    env.pop("LD_PRELOAD", None)
    if hook is not None:
        env["LD_PRELOAD"] = str(hook.resolve(strict=True))
    return subprocess.run([str(binary.resolve(strict=True))], input=key, capture_output=True,
                          timeout=15, env=env, check=False)


def prepare(args):
    root = args.corpus.resolve()
    root.mkdir()
    (root / "private").mkdir()
    key, payload, decoy = (secrets.token_bytes(32) for _ in range(3))
    require(len({key, payload, decoy}) == 3, "Random control collision")
    (root / "private/key.bin").write_bytes(key)
    (root / "private/payload.bin").write_bytes(payload)
    envelope = seal_asset(payload, key, **CONTEXT)
    save(root / "asset.json", envelope)
    export_native_asset(envelope, root / "include", **CONTEXT)
    flags = [f"-m{args.bits}", "-std=c++17", "-O0", "-g0", "-fno-inline", "-fno-pie",
             "-fno-builtin-memcmp", "-no-pie", "-Wl,--hash-style=both,--export-dynamic-symbol=rg_asset_gate"]
    inputs = {}
    for index, case in enumerate(CASES):
        folder = root / case
        folder.mkdir()
        material = c_array("expected_key_digest", hashlib.sha256(key).digest()) + c_array("public_decoy", decoy)
        if index == 0:
            material += c_array("ordinary_plaintext", payload)
        if index == 2:
            material += c_array("accidentally_bundled_key", key)
        (folder / "material.hpp").write_text(material, encoding="ascii")
        target = folder / "app"
        command(["g++", *flags, "-I", root / "include", "-I", folder, f"-DRG_CASE={index}",
                 HERE / "fixture.cpp", "-o", target, "-lcrypto"])
        raw = target.read_bytes()
        require((payload in raw) == (index == 0) and (key in raw) == (index == 2) and decoy in raw,
                "Compiler did not emit the planned contiguous controls")
        good, wrong = invoke(target, key), invoke(target, decoy)
        require((good.returncode, good.stdout, good.stderr) == (0, payload, b"") and
                (wrong.returncode, wrong.stdout, wrong.stderr) == (1, b"", b""), "Native functional control failed")
        inputs[case] = digest(raw)
    command(["gcc", f"-m{args.bits}", "-shared", "-fPIC", HERE / "forced_final.c", "-o", root / "forced_final.so"])
    save(root / "fixture.json", {
        "schema": "releaseguard-native-asset-fixture/v1", "bits": args.bits, "inputs": inputs,
        "payload_sha256": digest(payload), "payload_bytes": len(payload), "decoy_hex": decoy.hex(),
        "key_sha256": digest(key), "envelope_sha256": digest((root / "asset.json").read_bytes()),
        "context": CONTEXT, "compiler_flags": flags,
        "compiler": command(["g++", "--version"]).decode().splitlines()[0],
        "openssl": command(["openssl", "version"]).decode().strip(),
        "native_header_sha256": digest((root / "include/releaseguard/sealed_asset.hpp").read_bytes()),
        "fixture_cpp_sha256": digest((HERE / "fixture.cpp").read_bytes()),
        "forced_final_source_sha256": digest((HERE / "forced_final.c").read_bytes()),
        "forced_final_sha256": digest((root / "forced_final.so").read_bytes()),
    })


def contiguous_windows(memory):
    """Join adjacent analyzer blocks before enumerating every 32-byte candidate."""
    regions = []
    previous = -2
    data = bytearray()
    for address, byte in sorted(memory.items()):
        if address != previous + 1 and data:
            regions.append(bytes(data))
            data.clear()
        data.append(byte)
        previous = address
    if data:
        regions.append(bytes(data))
    return {region[i:i + 32] for region in regions for i in range(max(0, len(region) - 31))}


def patch_and_replay(root, case, record, work, fixture):
    source = root / case / "app"
    image = source.read_bytes()
    rows = [r.split() for r in command(["objdump", "-h", source]).decode().splitlines()]
    [text] = [r for r in rows if len(r) >= 7 and r[1] == ".text"]
    size, address, _, offset = (int(n, 16) for n in text[2:6])
    entry = int(record["gate_entry"], 16)
    prefix = bytes.fromhex(record["gate_prefix_hex"])
    require(address <= entry <= address + size - len(PATCH) and record["gate_size"] >= len(PATCH)
            and record["gate_instructions"] > 0 and record["gate_name"] == "rg_asset_gate",
            "Analyzer gate is not a patchable code location")
    offset += entry - address
    require(image[offset:offset + len(prefix)] == prefix, "Analyzer gate bytes differ from input")
    patched = work / (case + "-patched")
    modified = image[:offset] + PATCH + image[offset + len(PATCH):]
    patched.write_bytes(modified)
    patched.chmod(0o700)
    key = (root / "private/key.bin").read_bytes()
    wrong = bytes.fromhex(fixture["decoy_hex"])
    require(digest(key) == fixture["key_sha256"], "Issuer key changed")
    good = invoke(source, key)
    require(good.returncode == 0 and digest(good.stdout) == fixture["payload_sha256"] and not good.stderr,
            "Legitimate input no longer reads the asset")
    original_wrong, patched_wrong = invoke(source, wrong), invoke(patched, wrong)
    require((original_wrong.returncode, original_wrong.stdout, original_wrong.stderr) == (1, b"", b""),
            "Unpatched gate did not reject")
    if case == "plaintext":
        require(patched_wrong.returncode == 0 and digest(patched_wrong.stdout) == fixture["payload_sha256"]
                and not patched_wrong.stderr, "Ordinary plaintext control did not yield the payload after patch")
        forced = None
    else:
        require((patched_wrong.returncode, patched_wrong.stdout, patched_wrong.stderr) == (1, b"", b""),
                "Patched gate released wrong-key data")
        hook = root / "forced_final.so"
        require(digest(hook.read_bytes()) == fixture["forced_final_sha256"], "Forced-final test component changed")
        bypassed = invoke(patched, wrong, hook)
        authorized = invoke(patched, key, hook)
        require((bypassed.returncode, len(bypassed.stdout), bypassed.stderr) == (0, 32, HOOK_MARKER)
                and digest(bypassed.stdout) != fixture["payload_sha256"],
                "Forced authentication response failed the absent-key payload control")
        require(authorized.returncode == 0 and digest(authorized.stdout) == fixture["payload_sha256"]
                and authorized.stderr == HOOK_MARKER, "Forced-final legitimate-key control failed")
        forced = {"returncode": bypassed.returncode, "output_bytes": len(bypassed.stdout),
                  "output_sha256": digest(bypassed.stdout), "exact_payload": False,
                  "hook_calls": 1, "actual_key_exact_payload": True}
    require(source.read_bytes() == image, "Analyzer input was modified")
    return {"gate_file_offset": offset, "gate_entry": hex(entry), "patch_hex": PATCH.hex(),
            "patched_sha256": digest(modified), "legitimate_payload": True,
            "wrong_key_original_exit": original_wrong.returncode,
            "wrong_key_patched_exit": patched_wrong.returncode,
            "wrong_key_patched_bytes": len(patched_wrong.stdout),
            "wrong_key_patched_exact_payload": digest(patched_wrong.stdout) == fixture["payload_sha256"],
            "forced_final": forced}


def analyze(args):
    root = args.corpus.resolve()
    fixture = load(root / "fixture.json")
    envelope = load(root / "asset.json")
    require(digest((root / "asset.json").read_bytes()) == fixture["envelope_sha256"], "Envelope changed")
    tool = args.tool
    env = os.environ.copy()
    rows = {}
    with tempfile.TemporaryDirectory(prefix="rg-asset-probe-") as directory:
        work = Path(directory).resolve()
        if tool == "Ghidra":
            for part in ("home", "tmp", "projects"):
                (work / part).mkdir()
            env.update(HOME=str(work / "home"), TMPDIR=str(work / "tmp"), GHIDRA_HEADLESS_MAXMEM="1G",
                       GHIDRA_JAVA_OPTIONS=f"-Duser.home={work}/home -Djava.io.tmpdir={work}/tmp")
            launcher = launch_command(args, get_ghidra(args, work, env), work, env)
        for case in CASES:
            image = (root / case / "app").read_bytes()
            require(digest(image) == fixture["inputs"][case], "Fixture changed")
            if tool == "Ghidra":
                isolated = work / case
                isolated.mkdir()
                target, raw_report = isolated / "app", isolated / "observed.json"
                target.write_bytes(image)
                cmd = [*launcher, work / "projects", case, "-import", target, "-readOnly", "-deleteProject",
                       "-analysisTimeoutPerFile", "180", "-max-cpu", "2", "-scriptPath", HERE,
                       "-postScript", "ExtractAssetBytes.java", raw_report]
                proc = subprocess.run(list(map(str, cmd)), env=env, timeout=300, capture_output=True, check=False)
                require(proc.returncode == 0 and raw_report.is_file()
                        and b"RELEASEGUARD_ASSET_BYTES_COMPLETE" in proc.stdout + proc.stderr,
                        "Ghidra incomplete: " + (proc.stdout + proc.stderr)[-2200:].decode(errors="replace"))
                record = load(raw_report)
                require(record["version"] == VERSION and record["language"].startswith(f"x86:LE:{fixture['bits']}:")
                        and "ELF" in record["format"], "Unexpected Ghidra engine or input")
            else:
                require(fixture["bits"] == 32, "Pinned IDA experiment requires ELF32")
                record = load(args.observations / (case + ".json"))
                require(record["version"] == "5.0.0.879 Freeware", "Unexpected IDA engine")
            require(record["tool"] == tool and record["input_sha256"].lower() == digest(image),
                    "Analyzer identity/input mismatch")
            memory = verify_loaded_bytes(image, record)
            candidates = contiguous_windows(memory)
            require(bytes.fromhex(fixture["decoy_hex"]) in candidates, "Known public 32-byte control missing")
            raw_payloads = {value for value in candidates if digest(value) == fixture["payload_sha256"]}
            recovered = {}
            started = time.perf_counter()
            for value in candidates:
                try:
                    recovered[value] = open_asset(envelope, value, **fixture["context"])
                except GuardError:
                    continue
            elapsed = time.perf_counter() - started
            require(len(raw_payloads) == (1 if case == "plaintext" else 0) and
                    len(recovered) == (1 if case == "key_leak" else 0), "Unexpected extraction result")
            for value, plaintext in recovered.items():
                replay = invoke(root / case / "app", value)
                require(digest(value) == fixture["key_sha256"] and digest(plaintext) == fixture["payload_sha256"]
                        and replay.returncode == 0 and replay.stdout == plaintext and not replay.stderr,
                        "Recovered candidate did not unlock the actual native asset")
            row = {key: value for key, value in record.items() if key != "blocks"}
            row.update(distinct_32byte_candidates=len(candidates), public_decoy_found=True,
                       direct_payload_recoveries=len(raw_payloads), successful_key_decryptions=len(recovered),
                       exact_payload_recoveries=len(raw_payloads) + len(recovered),
                       all_candidates_tested_with_public_envelope=True, candidate_test_seconds=elapsed,
                       candidate_set_sha256=digest(b"".join(sorted(candidates))),
                       native_recovered_key_replays=len(recovered),
                       patched=patch_and_replay(root, case, record, work, fixture))
            rows[case] = row
    result = {"schema": "releaseguard-native-asset-observation/v1", "tool": tool, "fixture": fixture, "cases": rows}
    if tool == "Ghidra":
        result.update(archive_sha256_verified=ARCHIVE_SHA if args.archive else None,
                      script_sha256=digest((HERE / "ExtractAssetBytes.java").read_bytes()))
    save(args.out, result)


def compare(args):
    ghidra, ida = (load(path) for path in (args.ghidra, args.ida))
    require(ghidra["tool"] == "Ghidra" and ida["tool"] == "IDA" and ghidra["fixture"] == ida["fixture"]
            and ghidra["fixture"]["bits"] == 32, "Both engines must analyze the same actual ELF32 corpus")
    for observation in (ghidra, ida):
        for case, expected in zip(CASES, (1, 0, 1)):
            row = observation["cases"][case]
            require(row["input_sha256"].lower() == observation["fixture"]["inputs"][case]
                    and row["exact_payload_recoveries"] == expected and row["public_decoy_found"]
                    and row["allocated_section_bytes_verified"] > 0 and row["gate_instructions"] > 0,
                    "Incomplete independent extraction evidence")
            patch = row["patched"]
            require(patch["legitimate_payload"] and patch["wrong_key_original_exit"] == 1
                    and patch["patch_hex"] == PATCH.hex()
                    and patch["wrong_key_patched_exact_payload"] is (case == "plaintext")
                    and patch["wrong_key_patched_exit"] == (0 if case == "plaintext" else 1),
                    "Missing actual native patch control")
            if case != "plaintext":
                forced = patch["forced_final"]
                require(forced["returncode"] == 0 and forced["output_bytes"] == 32 and forced["hook_calls"] == 1
                        and forced["actual_key_exact_payload"] and forced["exact_payload"] is False
                        and forced["output_sha256"] != observation["fixture"]["payload_sha256"],
                        "Missing forced crypto-success control")
    for case in CASES:
        require(ghidra["cases"][case]["patched"]["patched_sha256"] == ida["cases"][case]["patched"]["patched_sha256"],
                "Engines did not locate the same patch")
    save(args.out, {"schema": "releaseguard-dual-native-assets/v1", "ghidra": ghidra, "ida": ida})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("corpus", type=Path)
    prep.add_argument("--bits", type=int, choices=(32, 64), default=32)
    prep.set_defaults(func=prepare)
    for name, tool in (("ghidra", "Ghidra"), ("ida", "IDA")):
        run = sub.add_parser(name)
        run.add_argument("corpus", type=Path)
        run.add_argument("--out", type=Path, required=True)
        run.set_defaults(func=analyze, tool=tool)
        if name == "ghidra":
            source = run.add_mutually_exclusive_group(required=True)
            source.add_argument("--archive", type=Path)
            source.add_argument("--ghidra-home", type=Path)
            run.add_argument("--direct-java", action="store_true")
        else:
            run.add_argument("--observations", type=Path, required=True)
    both = sub.add_parser("compare")
    both.add_argument("--ghidra", type=Path, required=True)
    both.add_argument("--ida", type=Path, required=True)
    both.add_argument("--out", type=Path, required=True)
    both.set_defaults(func=compare)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
