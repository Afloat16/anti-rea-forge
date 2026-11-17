"""Measure release exposure on newly built, project-owned Linux fixtures.

Real GNU binutils inspect the original and split ELF. A separate C++17/OpenSSL
fixture exercises externally keyed assets and an intentionally bundled key.
No third-party application, REA agent or decompiler is run. Reports contain
hashes and boolean observations, never the generated key or raw tool output.
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
import zipfile

from releaseguard import __version__
from releaseguard.core import GuardError, write_new
from releaseguard.distribution import scan_release
from releaseguard.native_asset import export_native_asset
from releaseguard.sealed import seal_asset
from releaseguard.split_elf import split_elf_debug


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_SYMBOL = "rg_owned_private_formula"
PAYLOAD = b"RG_OWNED_RESOURCE_FOR_RELEASE_EXPOSURE_CONTROL_2026"
CONTEXT = dict(product="owned-release-controls", release="1", purpose="fixture-data", asset_id="resource")
SYMBOL_SOURCE = f"""#include <stdio.h>
__attribute__((noinline)) static int {PRIVATE_SYMBOL}(int value) {{ return value * 3 + 1; }}
int main(void) {{ printf("%d\\n", {PRIVATE_SYMBOL}(7)); return 0; }}
""".encode("ascii")
PLAIN_SOURCE = b"#include <stdio.h>\nstatic const char data[] = \"" + PAYLOAD + b"\";\nint main(void) { return fwrite(data, 1, sizeof(data)-1, stdout) == sizeof(data)-1 ? 0 : 1; }\n"
SEALED_SOURCE = b"""#include "releaseguard_asset.hpp"
#include <cstdio>
#include <vector>
int main(void) {
    releaseguard::native_asset_key key{};
    std::vector<unsigned char> data;
    if (fread(key.data(), 1, key.size(), stdin) != key.size() || getchar() != EOF) return 2;
    bool ok = releaseguard::open_embedded_asset(key, data);
    OPENSSL_cleanse(key.data(), key.size());
    if (!ok) return 3;
    const bool written = fwrite(data.data(), 1, data.size(), stdout) == data.size();
    OPENSSL_cleanse(data.data(), data.size());
    return written ? 0 : 2;
}
"""
TOOLS = ("gcc", "g++", "objcopy", "strings", "nm", "readelf", "objdump", "openssl")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def command(arguments, *, input_bytes: bytes | None = None, checked: bool = True):
    """Execute only our selected tool or freshly compiled fixture, with no shell."""
    result = subprocess.run(list(map(str, arguments)), input=input_bytes, capture_output=True,
                            timeout=120, env={**os.environ, "LC_ALL": "C"}, check=False)
    if checked and result.returncode != 0:
        # Compiler diagnostics could contain generated key source. Do not publish them.
        raise RuntimeError(f"{Path(arguments[0]).name} exited with status {result.returncode}")
    return result


def toolchain() -> dict[str, str]:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("This control requires GNU/Linux")
    selected = {name: shutil.which(name) for name in TOOLS}
    missing = [name for name, path in selected.items() if not path]
    if missing:
        raise RuntimeError("Missing required tools: " + ", ".join(missing))
    for name in ("objcopy", "strings", "nm", "readelf", "objdump"):
        if b"GNU" not in command([selected[name], "--version"]).stdout:
            raise RuntimeError(f"This control requires GNU {name}")
    return selected


def parse_section_dump(output: bytes, address: int, size: int) -> bytes:
    """Validate GNU objdump's complete fixed-width hex columns, excluding ASCII."""
    data = bytearray()
    for line in output.decode("ascii", errors="strict").splitlines():
        match = re.match(r"^\s*([0-9a-fA-F]+) ([0-9a-fA-F ]{35})  ", line)
        if not match:
            continue
        if int(match[1], 16) != address + len(data):
            raise RuntimeError("objdump section output is discontinuous")
        try:
            chunk = bytes.fromhex(match[2])
        except ValueError as exc:
            raise RuntimeError("objdump section contains malformed bytes") from exc
        if not 1 <= len(chunk) <= 16 or len(data) + len(chunk) > size:
            raise RuntimeError("objdump section output exceeds its declared extent")
        data.extend(chunk)
    if len(data) != size or not data:
        raise RuntimeError("objdump section output is empty or incomplete")
    return bytes(data)


def text_bytes(binary: Path, tools: dict[str, str]) -> bytes:
    rows = command([tools["objdump"], "-h", binary]).stdout.decode("ascii").splitlines()
    matches = [line.split() for line in rows if len(line.split()) >= 7 and line.split()[1] == ".text"]
    if len(matches) != 1:
        raise RuntimeError("Expected one .text section in the owned fixture")
    row = matches[0]
    size, address, offset = int(row[2], 16), int(row[3], 16), int(row[5], 16)
    image = binary.read_bytes()
    if not 0 < size <= len(image) or offset + size > len(image):
        raise RuntimeError("objdump reported an invalid file extent")
    observed = parse_section_dump(command([tools["objdump"], "-s", "-j", ".text", binary]).stdout,
                                  address, size)
    if observed != image[offset:offset + size]:
        raise RuntimeError("objdump bytes do not match the original ELF file")
    return observed


def metadata_observation(binary: Path, tools: dict[str, str]) -> dict:
    strings = command([tools["strings"], "-a", binary]).stdout
    names = command([tools["nm"], "--defined-only", binary]).stdout
    section_output = command([tools["readelf"], "--sections", "--wide", binary]).stdout.decode("ascii")
    sections = re.findall(r"^\s*\[\s*\d+\]\s+(\S+)", section_output, re.MULTILINE)
    disassembly = command([tools["objdump"], "-d", binary]).stdout
    text = text_bytes(binary, tools)
    instructions = re.findall(rb"^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2}\s+)+\S", disassembly, re.MULTILINE)
    if ".text" not in sections or not instructions:
        raise RuntimeError("Native tool observation lacks sections or disassembly")
    return {
        "sha256": sha(binary.read_bytes()), "bytes": binary.stat().st_size,
        "private_name_in_strings": PRIVATE_SYMBOL.encode() in strings,
        "private_name_in_nm": any(row.split()[-1:] == [PRIVATE_SYMBOL.encode()] for row in names.splitlines()),
        "debug_info_in_readelf": ".debug_info" in sections,
        "static_symbols_in_readelf": ".symtab" in sections,
        "objdump_text_bytes": len(text), "objdump_text_sha256": sha(text),
        "objdump_bytes_match_file": True, "objdump_instruction_rows": len(instructions),
    }


def scan_observation(folder: Path, policy: Path, *, key_file: Path | None = None) -> dict:
    report = scan_release(folder, policy, asset_key_files=[key_file] if key_file else ())
    return {"ok": report["ok"], "finding_codes": sorted({f["code"] for f in report["findings"]}),
            "native_metadata_checked": report["checks"].get("native_metadata_checked", False),
            "files_scanned": report["checks"]["files_scanned"],
            "archives_scanned": report["checks"]["archives_scanned"],
            "asset_keys_checked": report["checks"]["asset_keys_checked"]}


def run_controls() -> dict:
    tools = toolchain()
    versions = {name: command([path, "version" if name == "openssl" else "--version"]).stdout
                .decode("utf-8", errors="replace").splitlines()[0] for name, path in tools.items()}
    checks = {}
    with tempfile.TemporaryDirectory(prefix="rg-exposure-controls-") as temporary:
        work = Path(temporary).resolve()
        private = work / "issuer"
        private.mkdir(mode=0o700)
        policy = private / "policy.json"
        policy.write_text('{"version":1}', encoding="ascii")
        original_dir = work / "original"
        original_dir.mkdir()
        source = private / "owned.c"
        source.write_bytes(SYMBOL_SOURCE)
        original = original_dir / "application.bin"
        command([tools["gcc"], "-g", "-O1", source, "-o", original])
        separated = split_elf_debug(original, work / "public", work / "private-debug", [PRIVATE_SYMBOL])
        if not separated["ok"]:
            raise RuntimeError("The owned ELF fixture could not be split")
        public, sidecar = Path(separated["public_elf"]), Path(separated["private_debug"])
        before, after = metadata_observation(original, tools), metadata_observation(public, tools)
        before["scan"] = scan_observation(original_dir, policy)
        after["scan"] = scan_observation(public.parent, policy)
        sidecar_names = command([tools["nm"], "--defined-only", sidecar]).stdout
        renamed_dir, packed_dir = work / "renamed-leak", work / "packed-leak"
        renamed_dir.mkdir()
        packed_dir.mkdir()
        shutil.copyfile(sidecar, renamed_dir / "resource.dat")
        with zipfile.ZipFile(packed_dir / "application.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            archive.write(public, "app")
            archive.write(sidecar, "assets/resource.dat")
        renamed_scan, packed_scan = scan_observation(renamed_dir, policy), scan_observation(packed_dir, policy)
        expected_metadata = {"native_debug_metadata", "native_symbol_table"}
        checks.update({
            "original_private_name_visible_to_strings_and_nm": before["private_name_in_strings"] and before["private_name_in_nm"],
            "original_debug_and_symbol_sections_visible_to_readelf": before["debug_info_in_readelf"] and before["static_symbols_in_readelf"],
            "split_removes_private_name_and_metadata": not any(after[k] for k in ("private_name_in_strings", "private_name_in_nm", "debug_info_in_readelf", "static_symbols_in_readelf")),
            "split_preserves_exact_text_bytes": before["objdump_text_sha256"] == after["objdump_text_sha256"],
            "split_preserves_execution": command([original]).stdout == command([public]).stdout == b"22\n",
            "split_keeps_private_symbols_in_private_sidecar": PRIVATE_SYMBOL.encode() in sidecar_names,
            "public_code_remains_disassemblable": after["objdump_instruction_rows"] > 0,
            "metadata_gate_blocks_original": not before["scan"]["ok"] and expected_metadata <= set(before["scan"]["finding_codes"]),
            "metadata_gate_accepts_split_release": after["scan"]["ok"] and after["scan"]["native_metadata_checked"],
            "metadata_gate_blocks_renamed_sidecar": not renamed_scan["ok"] and expected_metadata <= set(renamed_scan["finding_codes"]),
            "metadata_gate_blocks_zipped_sidecar": not packed_scan["ok"] and expected_metadata <= set(packed_scan["finding_codes"]) and packed_scan["archives_scanned"] == 1,
        })
        metadata = {"original": before, "split_public": after,
                    "private_sidecar_sha256": sha(sidecar.read_bytes()),
                    "renamed_sidecar_scan": renamed_scan, "zipped_sidecar_scan": packed_scan}

        key = secrets.token_bytes(32)
        wrong_key = bytes(byte ^ 0xff for byte in key)
        key_file = private / "asset.key"
        write_new(key_file, key, secret=True)
        asset_policy = private / "asset-policy.json"
        asset_policy.write_text(json.dumps({"version": 1, "forbid_literals": [PAYLOAD.decode("ascii")]}), encoding="ascii")
        envelope = seal_asset(PAYLOAD, key, **CONTEXT)
        generated = private / "generated"
        export_native_asset(envelope, generated, **CONTEXT)
        plain_source, sealed_source, leak_source = private / "plain.c", private / "sealed.cpp", private / "leak.cpp"
        plain_source.write_bytes(PLAIN_SOURCE)
        sealed_source.write_bytes(SEALED_SOURCE)
        leak = 'extern "C" __attribute__((used)) const unsigned char owned_bundled_key[32] = {' + ",".join(map(str, key)) + '};\n'
        leak_source.write_bytes(SEALED_SOURCE + leak.encode("ascii"))
        assets = {}
        for name, input_source in (("plaintext", plain_source), ("external_key", sealed_source), ("bundled_key", leak_source)):
            folder = work / name
            folder.mkdir()
            binary = folder / "application.bin"
            if name == "plaintext":
                command([tools["gcc"], "-O2", "-g0", "-s", input_source, "-o", binary])
            else:
                command([tools["g++"], "-std=c++17", "-O2", "-g0", "-s", "-I", generated,
                         input_source, "-lcrypto", "-o", binary])
            image = binary.read_bytes()
            good = command([binary], input_bytes=key, checked=False)
            wrong = command([binary], input_bytes=wrong_key, checked=False)
            observed_strings = command([tools["strings"], "-a", binary]).stdout
            assets[name] = {
                "sha256": sha(image), "bytes": len(image),
                "resource_in_file": PAYLOAD in image, "resource_in_strings": PAYLOAD in observed_strings,
                "master_key_in_file": key in image,
                "correct_key_returns_original": good.returncode == 0 and good.stdout == PAYLOAD and not good.stderr,
                "wrong_key_returncode": wrong.returncode,
                "wrong_key_output_bytes": len(wrong.stdout),
                "wrong_key_returns_original": wrong.returncode == 0 and wrong.stdout == PAYLOAD,
                "scan": scan_observation(folder, asset_policy, key_file=key_file),
            }
        plain, sealed, exposed = (assets[name] for name in ("plaintext", "external_key", "bundled_key"))
        checks.update({
            "plaintext_resource_visible_to_strings": plain["resource_in_file"] and plain["resource_in_strings"],
            "sealed_resource_not_in_file_or_strings": not sealed["resource_in_file"] and not sealed["resource_in_strings"],
            "sealed_master_key_not_in_release": not sealed["master_key_in_file"],
            "all_correct_key_outputs_match_original": all(item["correct_key_returns_original"] for item in assets.values()),
            "sealed_wrong_key_rejected_without_output": sealed["wrong_key_returncode"] == 3 and sealed["wrong_key_output_bytes"] == 0,
            "bundled_key_control_contains_actual_key": exposed["master_key_in_file"],
            "asset_gate_blocks_plaintext": not plain["scan"]["ok"] and "forbidden_literal" in plain["scan"]["finding_codes"],
            "asset_gate_accepts_external_key_release": sealed["scan"]["ok"] and sealed["scan"]["asset_keys_checked"] == 1,
            "asset_gate_blocks_bundled_key": not exposed["scan"]["ok"] and "asset_key_exposure" in exposed["scan"]["finding_codes"],
        })
        escaped_map = work / "escaped-source-map"
        escaped_map.mkdir()
        (escaped_map / "resource.dat").write_bytes(
            b'{"ver\\u0073ion":3,"sour\\u0063es":["owned.ts"],"names":[],"mappings":"AAAA",'
            b'"sourcesCont\\u0065nt":["export const owned = 1;"]}')
        map_scan = scan_observation(escaped_map, policy)
        checks["semantic_gate_blocks_escaped_source_map"] = not map_scan["ok"] and "source_map_structure" in map_scan["finding_codes"]

    source_paths = [Path(__file__), ROOT / "src/releaseguard/distribution.py", ROOT / "src/releaseguard/split_elf.py",
                    ROOT / "src/releaseguard/native_asset.py", ROOT / "src/releaseguard/sealed.py",
                    ROOT / "src/releaseguard/data/include/releaseguard/sealed_asset.hpp"]
    return {
        "schema": "releaseguard-release-exposure-controls/v1", "ok": all(checks.values()),
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "core_version": __version__,
        "environment": {"platform": platform.platform(), "machine": platform.machine(), "python": platform.python_version(), "tools": versions},
        "source_sha256": {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in source_paths},
        "fixture_source_sha256": {"symbols": sha(SYMBOL_SOURCE), "plaintext": sha(PLAIN_SOURCE), "sealed": sha(SEALED_SOURCE)},
        "resource_sha256": sha(PAYLOAD), "resource_bytes": len(PAYLOAD),
        "metadata": metadata, "assets": assets, "escaped_source_map_scan": map_scan, "checks": checks,
        "scope": {
            "owned_fixtures_only": True, "real_binutils_executed": True, "real_cpp_openssl_executed": True,
            "rea_cli_executed": False, "agent_or_model_executed": False,
            "decompiler_executed": False, "runtime_instrumentation_executed": False,
            "algorithm_recovery_resistance": "not_evaluated",
            "authorized_plaintext_memory": "not_protected_by_this_control",
            "notes": ["Absent literal bytes or a passing scan do not prove arbitrary data or algorithms cannot be recovered.",
                      "The plaintext data control has no key gate; encrypted controls require the independently held key.",
                      "Symbols are separated while executable .text stays identical and disassemblable.",
                      "Only source hashes, artifact hashes and observations are retained; generated key material is temporary."]},
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="Write a new JSON report; never overwrite an existing path")
    args = parser.parse_args(argv)
    try:
        if args.out is not None and os.path.lexists(args.out):
            raise FileExistsError("Report path already exists")
        report = run_controls()
        data = (json.dumps(report, indent=2) + "\n").encode("utf-8")
        if args.out is not None:
            write_new(args.out, data)
        print(data.decode("utf-8"), end="")
        return 0 if report["ok"] else 1
    except (GuardError, OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ok": False, "status": "execution_error", "error": str(exc),
                          "protection_outcome": "not_measured"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
