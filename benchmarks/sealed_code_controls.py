"""Build and evaluate project-owned externally keyed VM code controls on Linux x86-64.

prepare creates three complete public ELFs and keeps source, key and reference
inputs in private/. analyze consumes genuine ghidra_function --include-program
observations. Candidate extraction receives only exported bytes and public
envelope/context. Successful authorized processes contain plaintext VM storage.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import time

if __package__:
    from . import native_code_controls as native
    from .ghidra_function import probe
    from .native_asset_controls import contiguous_windows
else:
    import native_code_controls as native
    from ghidra_function import probe
    from native_asset_controls import contiguous_windows

from releaseguard.core import GuardError, write_new
from releaseguard.native_asset import export_native_asset
from releaseguard.native_obfuscation import obfuscate_native_ir
from releaseguard.sealed import SEALED_FORMAT, _context, _envelope, open_asset


CASES = ("plaintext", "encrypted", "key_leak")
CONTEXT = {"product": "SealedCodeFixture", "release": "v1",
           "purpose": "vm-code", "asset_id": "compute"}
PATCH = bytes.fromhex("b8 01 00 00 00 c3")
HOOK_MARKER = b"RG_GCM_FINAL_FORCED\n"
HERE = Path(__file__).resolve().parent
CODE_FILES = ("releaseguard_native_code.hpp", "releaseguard_native_code.cpp",
              "releaseguard_native_code_asset.hpp", "releaseguard_sealed_asset.hpp")
LINK_FLAGS = ["-std=c++17", "-O2", "-g0", "-Wall", "-Wextra", "-Werror",
              "-fno-pie", "-no-pie", "-Wl,--export-dynamic-symbol=rg_compute",
              "-Wl,--export-dynamic-symbol=rg_code_gate"]
SCOPE = {"subject": "Function-instruction confidentiality in the release before external key delivery",
         "authorized_process_contains_plaintext_vm_storage": True,
         "candidate_search": "Every distinct contiguous 32-byte window in exported initialized loaded bytes",
         "gate_patch_target": "rg_code_gate",
         "inner_wrapper_ready_guard_patch_evaluated": False,
         "arbitrary_key_search_or_authorized_memory_extraction_evaluated": False}
require, digest, artifact = native.require, native.digest, native.artifact


def load(path):
    return json.loads(path.read_bytes())


def driver_source(namespace=None, leaked_key=None):
    includes = "#include <cstdint>\n#include <cstdio>\n"
    gate = "    (void)raw;\n    return 1;\n"
    clearing = ""
    if namespace is not None:
        includes += '#include "releaseguard_native_code.hpp"\n#include <cstring>\n'
        gate = ""
        if leaked_key is not None:
            require(len(leaked_key) == 32, "Leaked-key control requires exactly 32 bytes")
            values = ", ".join(str(value) for value in leaked_key)
            includes += ("__attribute__((used)) static const unsigned char accidentally_bundled_key[32] = {"
                         + values + "};\n")
            gate += "    if (CRYPTO_memcmp(raw, accidentally_bundled_key, 32) != 0) return 0;\n"
        gate += ("    releaseguard::native_asset_key key{};\n"
                 "    std::memcpy(key.data(), raw, key.size());\n"
                 f"    const bool ready = {namespace}::initialize_native_code(key);\n"
                 "    OPENSSL_cleanse(key.data(), key.size());\n"
                 "    return ready ? 1 : 0;\n")
        clearing = f"    {namespace}::clear_native_code();\n"
    return (includes + '''extern "C" std::uint32_t rg_compute(std::uint32_t);
extern "C" __attribute__((noinline)) int rg_code_gate(const unsigned char *raw) {
''' + gate + '''}
int main() {
    unsigned char key[32], input[4], output[4];
    if (std::fread(key, 1, 32, stdin) != 32) return 2;
    if (!rg_code_gate(key)) return 1;
    size_t count;
    while ((count = std::fread(input, 1, 4, stdin)) == 4) {
        const std::uint32_t x = std::uint32_t(input[0]) | std::uint32_t(input[1]) << 8
                              | std::uint32_t(input[2]) << 16 | std::uint32_t(input[3]) << 24;
        const std::uint32_t y = rg_compute(x);
        for (unsigned i = 0; i < 4; ++i) output[i] = static_cast<unsigned char>(y >> (i * 8));
        if (std::fwrite(output, 1, 4, stdout) != 4) return 2;
    }
''' + clearing + '''    return count == 0 && !std::ferror(stdin) && std::fflush(stdout) == 0 ? 0 : 2;
}
''').encode("ascii")


def invoke(binary, key, inputs, hook=None):
    env = native.environment()
    if hook is not None:
        env["LD_PRELOAD"] = str(hook.resolve(strict=True))
    try:
        process = subprocess.run([str(binary.resolve(strict=True))], input=key + inputs,
                                 capture_output=True, timeout=120, env=env)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Native code control timed out") from error
    return process


def process_record(process, expected_stderr=b""):
    return {"ok": process.returncode == 0 and process.stderr == expected_stderr,
            "returncode": process.returncode, "stdout_bytes": len(process.stdout),
            "stdout_sha256": digest(process.stdout), "stderr_bytes": len(process.stderr),
            "stderr_sha256": digest(process.stderr)}


def exact_output(process, expected, expected_stderr=b""):
    return native.compare_output(expected, process.stdout, process_record(process, expected_stderr))


def rejected(process, expected_stderr=b""):
    require(process.returncode == 1 and not process.stdout and process.stderr == expected_stderr,
            "Expected a clean native authorization rejection")
    return {**process_record(process, expected_stderr), "authorization_rejected": True}


def header_arrays(header):
    arrays = {}
    for match in re.finditer(r"std::array<unsigned char, ([0-9]+)> (embedded_asset_[a-z]+) = \{([^}]+)\};", header):
        values = bytes(int(value, 16) for value in re.findall(r"0x([0-9a-f]{2})", match[3]))
        require(len(values) == int(match[1]), "Incomplete generated asset array")
        require(match[2] not in arrays, "Duplicate generated asset array")
        arrays[match[2]] = values
    require(set(arrays) == {"embedded_asset_" + name for name in ("salt", "nonce", "ciphertext", "aad")},
            "Expected all four generated public asset arrays")
    return arrays


def public_envelope(header, context):
    arrays = header_arrays(header)
    require(arrays["embedded_asset_aad"] == _context(**context), "Generated trusted context differs")
    envelope = {"format": SEALED_FORMAT, **{
        name: base64.b64encode(arrays["embedded_asset_" + name]).decode("ascii")
        for name in ("salt", "nonce", "ciphertext")}}
    _envelope(envelope)
    return envelope


def compile_driver(compiler, folder, source, obj, loader=None):
    write_new(folder / "driver.cpp", source, secret=True)
    command = [compiler, *LINK_FLAGS, "-I", folder, folder / "driver.cpp", obj]
    if loader is not None:
        command += [loader, "-lcrypto"]
    native.tool([*command, "-o", folder / "app"])
    return folder / "app"


def negative_builds(private, encrypted, compiler, namespace, envelope, key, inputs):
    changed = dict(envelope)
    ciphertext = bytearray(base64.b64decode(changed["ciphertext"]))
    ciphertext[0] ^= 1
    changed["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
    wrong_context = {**CONTEXT, "asset_id": CONTEXT["asset_id"] + "-wrong"}
    rows = {}
    for name, document, context in (("tampered_ciphertext", changed, CONTEXT),
                                     ("wrong_context", envelope, wrong_context)):
        try:
            open_asset(document, key, **context)
        except GuardError:
            pass
        else:
            raise RuntimeError("Python AEAD negative control authenticated")
        folder = private / "build" / name
        folder.mkdir()
        export_native_asset(document, folder / "export", **context)
        for filename in CODE_FILES:
            source = encrypted / filename
            data = source.read_bytes()
            if filename == "releaseguard_native_code_asset.hpp":
                data = (folder / "export/releaseguard_asset.hpp").read_bytes().replace(
                    b'#include "releaseguard/sealed_asset.hpp"', b'#include "releaseguard_sealed_asset.hpp"')
            write_new(folder / filename, data, secret=True)
        binary = compile_driver(compiler, folder, driver_source(namespace), encrypted / "protected.o",
                                folder / "releaseguard_native_code.cpp")
        rows[name] = {"python_aead_rejected": True, "binary": artifact(binary),
                      "native": rejected(invoke(binary, key, inputs))}
    return rows


def prepare(args):
    root = native.new_path(args.corpus)
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "Sealed code controls currently require Linux x86-64")
    tools, versions = native.toolchain(args.llvm_bin)
    compiler = shutil.which("g++")
    require(compiler is not None, "A C++17 compiler and OpenSSL development files are required")
    seed = native.seed_value(args.seed)
    key, wrong_key = secrets.token_bytes(32), secrets.token_bytes(32)
    require(key != wrong_key, "Random key control collision")
    root.mkdir()
    private, public = root / "private", root / "public"
    private.mkdir(mode=0o700)
    public.mkdir()
    (private / "build").mkdir()
    for name, data in (("kernel.c", native.kernel_source(seed)), ("key.bin", key), ("wrong-key.bin", wrong_key)):
        write_new(private / name, data, secret=True)
    native.tool([tools / "clang", *native.FLAGS, "-emit-llvm", "-c", "kernel.c", "-o", "kernel.bc"], cwd=private)
    boundaries = sorted({((1 << bit) + offset) & 0xffffffff
                         for bit in range(32) for offset in (-1, 0, 1)} | {0xffffffff})
    low = list(range(1 << 16))
    values = low + boundaries + native.fresh_inputs(seed, native.RANDOM_INPUTS, low + boundaries)
    inputs = native.pack(values)
    write_new(private / "inputs.bin", inputs, secret=True)
    baseline = private / "build/baseline"
    baseline.mkdir()
    native.tool([tools / "llc", "-O=2", "-relocation-model=pic", "-filetype=obj",
                 private / "kernel.bc", "-o", baseline / "kernel.o"])
    binary = compile_driver(compiler, baseline, driver_source(), baseline / "kernel.o")
    reference = invoke(binary, key, inputs)
    require(process_record(reference)["ok"] and len(reference.stdout) == len(inputs)
            and reference.stdout != bytes(len(inputs)), "Native reference failed")
    expected = reference.stdout
    write_new(private / "expected.bin", expected, secret=True)
    builds = {}
    for case, profile in (("plaintext", "virtualize"), ("encrypted", "sealed-virtualize")):
        options = {}
        if case == "encrypted":
            options = {"code_key": key, "product": CONTEXT["product"], "release": CONTEXT["release"],
                       "module_id": CONTEXT["asset_id"]}
        builds[case] = obfuscate_native_ir(private / "kernel.bc", private / "build" / case,
                                          tools, args.plugin, args.plugin_sha256, ["rg_compute"],
                                          profile=profile, **options)
        require(builds[case].get("ok") is True and builds[case].get("profile") == profile,
                "Native transformation did not complete")
    sealed = builds["encrypted"]["code_seal"]
    namespace = sealed["cpp_namespace"]
    encrypted = private / "build/encrypted"
    envelope = public_envelope((encrypted / CODE_FILES[2]).read_text(), CONTEXT)
    opened = open_asset(envelope, key, **CONTEXT)
    require(len(opened) == sealed["payload_bytes"] and digest(opened) == sealed["payload_sha256"],
            "Public envelope does not contain the reported complete VM storage")
    native.save(root / "envelope.json", envelope)
    rows = {}
    for case in CASES:
        folder = private / "build" / case
        if case == "key_leak":
            folder.mkdir()
            for filename in CODE_FILES:
                write_new(folder / filename, (encrypted / filename).read_bytes(), secret=True)
        obj = private / "build/plaintext/protected.o" if case == "plaintext" else encrypted / "protected.o"
        selected = None if case == "plaintext" else namespace
        loader = None if case == "plaintext" else folder / CODE_FILES[1]
        binary = compile_driver(compiler, folder, driver_source(selected, key if case == "key_leak" else None), obj, loader)
        raw = binary.read_bytes()
        require((key in raw) == (case == "key_leak"), "Compiled key-exposure control differs from its intent")
        good = exact_output(invoke(binary, key, inputs), expected)
        require(good["ok"], f"Correct-key function comparison failed for {case}")
        wrong = invoke(binary, wrong_key, inputs)
        bad = exact_output(wrong, expected) if case == "plaintext" else rejected(wrong)
        require(case != "plaintext" or bad["ok"], "Plaintext VM incorrectly depends on the key")
        rows[case] = {"binary": artifact(binary), "good_key": good, "wrong_key": bad,
                      "embedded_master_key": case == "key_leak"}
        binary.rename(public / case)
    hook = private / "forced_final.so"
    native.tool(["gcc", "-shared", "-fPIC", HERE / "sealed_native/forced_final.c", "-o", hook])
    forced_wrong = rejected(invoke(public / "encrypted", wrong_key, inputs, hook), HOOK_MARKER)
    forced_good = exact_output(invoke(public / "encrypted", key, inputs, hook), expected, HOOK_MARKER)
    require(forced_good["ok"], "Forced-final correct-key control failed")
    negatives = negative_builds(private, encrypted, compiler, namespace, envelope, key, inputs)
    manifest = {"seed": seed, "files": {name: artifact(private / name) for name in
                ("kernel.c", "kernel.bc", "key.bin", "wrong-key.bin", "inputs.bin", "expected.bin")}}
    native.save(private / "manifest.json", manifest)
    fixture = {"schema": "releaseguard-sealed-code-corpus/v1", "ok": True,
               "created_utc": datetime.now(timezone.utc).isoformat(), "scope": SCOPE,
               "context": CONTEXT, "public_abi": "uint32_t rg_compute(uint32_t)",
               "stdin_contract": "32-byte key followed by little-endian uint32 inputs",
               "stdout_contract": "One little-endian uint32 output per input after successful gate",
               "platform": "Linux x86-64", "llvm_versions": versions,
               "compiler": native.tool([compiler, "--version"]).decode().splitlines()[0],
               "plugin_sha256": args.plugin_sha256.lower(), "compiler_flags": native.FLAGS,
               "link_flags": LINK_FLAGS, "input_count": len(values), "distinct_inputs": len(set(values)),
               "input_sha256": digest(inputs), "reference_sha256": digest(expected),
               "envelope": artifact(root / "envelope.json"), "code_seal": sealed, "cases": rows,
               "forced_final": {"binary": artifact(hook), "source": artifact(HERE / "sealed_native/forced_final.c"),
                                "wrong_key": forced_wrong, "good_key": forced_good},
               "negative_controls": negatives, "private_manifest": artifact(private / "manifest.json")}
    native.save(root / "fixture.json", fixture)
    return fixture


def observe(directory, image):
    run = load(directory / "run.json")
    require(run.get("schema") == "releaseguard.function-run.v1"
            and run.get("ghidra_version") == probe.VERSION and run.get("headless_exit") == 0
            and run.get("analysis_timed_out") is False and run.get("input_unchanged") is True
            and run.get("file_bytes_and_instruction_coverage_verified") is True,
            "Incomplete or unsupported Ghidra run")
    expected = digest(image)
    require(run["input_sha256"].lower() == expected and run["input_bytes"] == len(image),
            "Ghidra run input differs from the public ELF")
    required = {"function.json", "decompiled.c", "program.json", "program.c", "program-memory.json", "program.elf"}
    require(required <= run["output_sha256"].keys(), "Ghidra --include-program outputs are missing")
    for name, checksum in run["output_sha256"].items():
        require(Path(name).name == name and digest((directory / name).read_bytes()) == checksum,
                "Ghidra observation output hash mismatch")
    require((directory / "program.elf").read_bytes() == image, "Ghidra complete ELF copy differs")
    probe.validate_logs((directory / "console.log").read_text(), (directory / "headless.log").read_text())
    function = load(directory / "function.json")
    program = load(directory / "program.json")
    memory = load(directory / "program-memory.json")
    require(all(record["input_sha256"].lower() == expected for record in (function, program, memory)),
            "Ghidra observation input hash mismatch")
    require(function["tool"] == "Ghidra" and function["version"] == probe.VERSION
            and function["language"] == "x86:LE:64:default" and "ELF" in function["format"]
            and function["analysis_timed_out"] is False and function["target"]["name"] == "rg_compute",
            "Unexpected Ghidra target or architecture")
    probe.validate_bytes(function, image)
    summary = probe.validate_program_functions(program, (directory / "program.c").read_bytes())
    require(not summary["function_failures"], "Incomplete Ghidra function decompilation requires review")
    summary.update(probe.validate_program_memory(memory, image))
    gates = [row for row in program["functions"] if row["name"] == "rg_code_gate" and not row["external"]]
    require(len(gates) == 1, "Ghidra must discover exactly one public rg_code_gate")
    return memory, gates[0], {"tool": "Ghidra", "version": probe.VERSION,
                             "input_sha256": expected, "run_sha256": digest((directory / "run.json").read_bytes()),
                             "observation_hashes": run["output_sha256"], **summary}


def exported_bytes(memory):
    result = {}
    for block in memory["blocks"]:
        if block["loaded"] and block["initialized"]:
            for row in block["memory"]["ranges"]:
                start = int(row["start"], 16)
                for offset, value in enumerate(bytes.fromhex(row["loaded_hex"])):
                    require(start + offset not in result, "Overlapping exported initialized bytes")
                    result[start + offset] = value
    require(result, "Ghidra exported no initialized bytes")
    return result


def candidate_keys(memory, envelope, context):
    """Test exported-byte candidates without issuer keys, source or private inputs."""
    candidates = contiguous_windows(exported_bytes(memory))
    require(candidates, "No complete 32-byte candidates were exported")
    started = time.perf_counter()
    recovered = []
    for candidate in sorted(candidates):
        try:
            plaintext = open_asset(envelope, candidate, **context)
        except GuardError:
            continue
        recovered.append((candidate, {"payload_bytes": len(plaintext), "payload_sha256": digest(plaintext)}))
    return recovered, {"distinct_32byte_candidates": len(candidates),
                       "candidate_set_sha256": digest(b"".join(sorted(candidates))),
                       "candidate_test_seconds": time.perf_counter() - started,
                       "all_candidates_tested_with_public_envelope": True,
                       "successful_key_decryptions": len(recovered),
                       "candidate_inputs": ["exported initialized loaded bytes", "public envelope", "trusted context"]}


def executable_file_offset(image, address, size):
    require(len(image) >= 64 and image[:7] == b"\x7fELF\x02\x01\x01"
            and struct.unpack_from("<H", image, 18)[0] == 62, "Expected Linux x86-64 ELF")
    offset = struct.unpack_from("<Q", image, 32)[0]
    width, count = struct.unpack_from("<HH", image, 54)
    require(width == 56 and count > 0 and offset + width * count <= len(image), "Invalid ELF program headers")
    matches = []
    for position in range(offset, offset + width * count, width):
        kind, flags, file_offset, virtual, _, file_size, _, _ = struct.unpack_from("<II6Q", image, position)
        if kind == 1 and flags & 1 and virtual <= address and address + size <= virtual + file_size:
            result = file_offset + address - virtual
            require(0 <= result <= result + size <= len(image), "Executable segment extends beyond ELF")
            matches.append(result)
    require(len(matches) == 1, "Gate has no unique file-backed executable mapping")
    return matches[0]


def gate_patch(image, memory, gate):
    require(gate["name"] == "rg_code_gate" and gate["status"] == "completed", "Invalid analyzed gate")
    entry = int(gate["entry"], 16)
    body = probe.address_set(gate["body_ranges"])
    require(len(body) == gate["body_addresses"] and set(range(entry, entry + len(PATCH))) <= body,
            "Analyzed gate body is too short for the complete patch")
    offset = executable_file_offset(image, entry, len(PATCH))
    observed = {}
    for block in memory["blocks"]:
        if not (block["loaded"] and block["initialized"] and block["execute"]):
            continue
        for row in block["memory"]["ranges"]:
            if "file_offset" not in row:
                continue
            start = int(row["start"], 16)
            raw = bytes.fromhex(row["hex"])
            for address in range(max(start, entry), min(start + len(raw), entry + len(PATCH))):
                index = address - start
                require(row["file_offset"] + index == offset + address - entry,
                        "Analyzer gate provenance disagrees with ELF segment mapping")
                observed[address] = raw[index]
    require(set(observed) == set(range(entry, entry + len(PATCH)))
            and bytes(observed[address] for address in sorted(observed)) == image[offset:offset + len(PATCH)],
            "Analyzer gate bytes differ from the public input")
    modified = image[:offset] + PATCH + image[offset + len(PATCH):]
    return modified, {"gate_name": "rg_code_gate", "gate_entry": hex(entry),
                      "gate_file_offset": offset, "patch_hex": PATCH.hex(),
                      "original_prefix_sha256": digest(image[offset:offset + len(PATCH)]),
                      "patched_sha256": digest(modified)}


def load_private(root, fixture):
    require(artifact(root / "private/manifest.json") == fixture["private_manifest"], "Private manifest changed")
    manifest = load(root / "private/manifest.json")
    for name, metadata in manifest["files"].items():
        require(Path(name).name == name and artifact(root / "private" / name) == metadata,
                "Private corpus artifact changed")
    key = (root / "private/key.bin").read_bytes()
    wrong = (root / "private/wrong-key.bin").read_bytes()
    inputs = (root / "private/inputs.bin").read_bytes()
    expected = (root / "private/expected.bin").read_bytes()
    require(len(key) == len(wrong) == 32 and key != wrong
            and len(inputs) == len(expected) == fixture["input_count"] * 4 and inputs
            and digest(inputs) == fixture["input_sha256"] and digest(expected) == fixture["reference_sha256"]
            and expected != bytes(len(expected)), "Private reference is incomplete")
    return key, wrong, inputs, expected


def analyze(args):
    root = args.corpus.resolve(strict=True)
    fixture = load(root / "fixture.json")
    require(fixture["schema"] == "releaseguard-sealed-code-corpus/v1" and fixture["ok"] is True
            and fixture["platform"] == "Linux x86-64" and set(fixture["cases"]) == set(CASES),
            "Invalid sealed-code corpus")
    require(artifact(root / "envelope.json") == fixture["envelope"], "Public envelope changed")
    envelope = load(root / "envelope.json")
    # Extraction finishes before the evaluator reads issuer key/reference files.
    observations = {}
    for case in CASES:
        binary = root / "public" / case
        require(artifact(binary) == fixture["cases"][case]["binary"], "Public ELF changed")
        image = binary.read_bytes()
        memory, gate, summary = observe(args.observations / case, image)
        recovered, extraction = candidate_keys(memory, envelope, fixture["context"])
        require(len(recovered) == (1 if case == "key_leak" else 0), "Unexpected candidate AEAD recovery count")
        observations[case] = (image, memory, gate, recovered, {**summary, **extraction})
    key, wrong, inputs, expected = load_private(root, fixture)
    rows = {}
    with tempfile.TemporaryDirectory(prefix="sealed-code-evaluate-", dir=root / "private") as temporary:
        work = Path(temporary)
        for case, (image, memory, gate, recovered, row) in observations.items():
            source = root / "public" / case
            good = exact_output(invoke(source, key, inputs), expected)
            require(good["ok"], "Correct-key public binary no longer matches the reference")
            replays = []
            for candidate, payload in recovered:
                require(payload["payload_bytes"] == fixture["code_seal"]["payload_bytes"]
                        and payload["payload_sha256"] == fixture["code_seal"]["payload_sha256"],
                        "Candidate authenticated an unexpected VM payload")
                replay = exact_output(invoke(source, candidate, inputs), expected)
                require(replay["ok"], "Recovered key did not reproduce the original native function")
                replays.append({**payload, "native_function": replay})
            modified, patched = gate_patch(image, memory, gate)
            target = work / case
            write_new(target, modified, secret=True)
            target.chmod(0o700)
            original_wrong = invoke(source, wrong, inputs)
            patched_wrong = invoke(target, wrong, inputs)
            if case == "plaintext":
                unpatched = exact_output(original_wrong, expected)
                patch_result = exact_output(patched_wrong, expected)
                require(unpatched["ok"] and patch_result["ok"], "Plaintext gate-patch positive control failed")
            else:
                unpatched = rejected(original_wrong)
                patch_result = exact_output(patched_wrong, expected)
                require(process_record(patched_wrong)["ok"] and patched_wrong.stdout == bytes(len(expected))
                        and not patch_result["ok"] and patch_result["difference_count"] > 0,
                        "Gate patch did not preserve the encrypted wrapper's locked-zero result")
            patched.update(wrong_key_original=unpatched, wrong_key_patched=patch_result,
                           all_patched_outputs_zero=patched_wrong.stdout == bytes(len(expected)))
            require(source.read_bytes() == image, "Evaluation changed the public binary")
            row.update(correct_key=good, native_recovered_key_replays=len(replays),
                       recovered_payloads=replays, patched=patched)
            rows[case] = row
    hook = root / "private/forced_final.so"
    require(artifact(hook) == fixture["forced_final"]["binary"], "Forced-final component changed")
    forced_wrong = rejected(invoke(root / "public/encrypted", wrong, inputs, hook), HOOK_MARKER)
    forced_good = exact_output(invoke(root / "public/encrypted", key, inputs, hook), expected, HOOK_MARKER)
    require(forced_good["ok"], "Forced-final correct-key replay failed")
    negative_rows = {}
    for name, recorded in fixture["negative_controls"].items():
        require(name in ("tampered_ciphertext", "wrong_context"), "Unknown negative control")
        binary = root / "private/build" / name / "app"
        require(artifact(binary) == recorded["binary"], "Negative-control binary changed")
        negative_rows[name] = {"binary": recorded["binary"], "native": rejected(invoke(binary, key, inputs))}
    require(set(negative_rows) == {"tampered_ciphertext", "wrong_context"}, "Missing native negative controls")
    return {"schema": "releaseguard-sealed-code-observation/v1", "ok": True,
            "completed_utc": datetime.now(timezone.utc).isoformat(), "scope": SCOPE,
            "fixture_sha256": digest((root / "fixture.json").read_bytes()), "context": fixture["context"],
            "input_count": fixture["input_count"], "reference_sha256": fixture["reference_sha256"],
            "cases": rows, "forced_final": {"wrong_key": forced_wrong, "good_key": forced_good,
                                              "post_authentication_payload_sha256_rejection": True},
            "negative_controls": negative_rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("corpus", type=Path)
    prep.add_argument("--llvm-bin", required=True, type=Path)
    prep.add_argument("--plugin", required=True, type=Path)
    prep.add_argument("--plugin-sha256", required=True)
    prep.add_argument("--seed")
    prep.set_defaults(func=prepare)
    evaluation = commands.add_parser("analyze")
    evaluation.add_argument("corpus", type=Path)
    evaluation.add_argument("--observations", type=Path, required=True)
    evaluation.add_argument("--out", type=Path, required=True)
    evaluation.set_defaults(func=analyze)
    args = parser.parse_args(argv)
    try:
        if args.command == "analyze":
            args.out = native.new_path(args.out)
            require(not args.out.is_relative_to(args.corpus.absolute() / "public"),
                    "Reports must stay outside public/")
        report = args.func(args)
        if args.command == "analyze":
            native.save(args.out, report)
    except (GuardError, OSError, RuntimeError, ValueError, KeyError) as error:
        print(f"Sealed code control failed: {error}", file=sys.stderr)
        return 2
    if args.command == "prepare":
        print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
