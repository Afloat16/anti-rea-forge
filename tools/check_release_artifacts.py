#!/usr/bin/env python3
"""Build and exercise the actual release archives outside the source checkout.

This is an installation/behavior check, not a reverse-engineering resistance score.
Only project-owned temporary fixtures and fresh virtual environments are used.
"""
from __future__ import annotations

import argparse
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import venv
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def validate_wheel_metadata(data: bytes, version: str) -> None:
    # Wheel metadata is an email-style header document. Both CRLF (Windows)
    # and LF are valid; duplicate/incorrect identity fields still fail closed.
    headers = BytesParser().parsebytes(data, headersonly=True)
    require(headers.get_all("Name") == ["open-release-guard"], "Wheel metadata name differs")
    require(headers.get_all("Version") == [version], "Wheel metadata version differs")


def run(args: list[str], *, cwd: Path, env: dict[str, str] | None = None,
        expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=cwd, env=env, text=True, encoding="utf-8",
                            errors="replace", capture_output=True, timeout=300)
    if result.returncode != expected:
        raise RuntimeError(f"Command failed ({result.returncode}): {args[0:4]!r}\n"
                           f"{result.stdout[-8000:]}\n{result.stderr[-8000:]}")
    return result


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def python_in(directory: Path) -> Path:
    return directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def cli(python: Path, work: Path, *args: str, expected: int = 0) -> dict:
    output = run([str(python), "-I", "-m", "releaseguard", *args], cwd=work,
                 expected=expected)
    return json.loads(output.stdout)


def installed_disclosure_controls(python: Path, work: Path, release: Path, policy: Path) -> dict:
    """Exercise new installed-module paths using bounded, locally authored inputs."""
    private_input = work / "owned-private-implementation.py"
    private_bytes = b"def owned_private_quote(x):\n    return x * 37 + 19\n"
    private_input.write_bytes(private_bytes)
    private_args = ["scan-release", "--root", str(release), "--policy", str(policy),
                    "--private-input-file", str(private_input)]
    clean = cli(python, work, *private_args)
    require(clean["ok"] is True and clean["checks"]["private_inputs_checked"] == 1,
            "Installed private-input clean control failed")
    copied = release / "renamed-private.data"
    copied.write_bytes(private_bytes)
    exposed = cli(python, work, *private_args, expected=3)
    require(exposed["ok"] is False and exposed["checks"]["private_inputs_checked"] == 1
            and any(item["code"] == "private_input_exposure" and item["rule_index"] == 0
                    for item in exposed["findings"]), "Installed private-input copy was not rejected")
    copied.unlink()

    # Compile only this trusted, locally authored source under the installed
    # interpreter. No module or fixture is imported from the source checkout.
    pyc = release / "renamed-bytecode.data"
    pyc_key = work / "owned-pyc.key"
    pem = work / "owned-wrapped-pem.json"
    generator = r'''
import base64, importlib.util, json, marshal, pathlib, struct, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = bytes(range(224, 256))
source = "def owned_key():\n    return (%d).to_bytes(32, 'big')\n" % int.from_bytes(key, "big")
code = compile(source, "/owned-installation/fixture.py", "exec", dont_inherit=True, optimize=0)
body = importlib.util.MAGIC_NUMBER + struct.pack("<I", 3) + importlib.util.source_hash(source.encode()) + marshal.dumps(code, 4)
assert key not in body and key.hex().encode() not in body
pathlib.Path(sys.argv[1]).write_bytes(body)
pathlib.Path(sys.argv[2]).write_bytes(key)
issuer = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
private = issuer.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
wrapped = base64.b64encode(private).decode("ascii")
recovered = serialization.load_pem_private_key(base64.b64decode(wrapped), password=None)
issuer.public_key().verify(recovered.sign(b"owned installed PEM control"), b"owned installed PEM control")
pathlib.Path(sys.argv[3]).write_text(json.dumps({"wrapped": wrapped}), encoding="ascii")
'''
    run([str(python), "-I", "-c", generator, str(pyc), str(pyc_key), str(pem)], cwd=work)
    pyc_report = cli(python, work, "scan-release", "--root", str(release), "--policy", str(policy),
                     "--asset-key-file", str(pyc_key), expected=3)
    require(pyc_report["checks"]["pyc_asset_key_files_checked"] == 1
            and pyc_report["checks"]["pyc_asset_key_scan_completed"] is True
            and any(item["code"] == "asset_key_exposure"
                    and item.get("representation") == "python-marshal-integer"
                    for item in pyc_report["findings"]), "Installed canonical PYC integer key was not rejected")
    pyc.unlink()
    wrapped = release / "wrapped-private-key.json"
    wrapped.write_bytes(pem.read_bytes())
    pem_report = cli(python, work, "scan-release", "--root", str(release), "--policy", str(policy), expected=3)
    require(pem_report["checks"]["structured_secret_scan_completed"] is True
            and any(item["code"] == "private_key_marker"
                    and item.get("representation") == "json-base64-pem"
                    for item in pem_report["findings"]), "Installed wrapped private PEM was not rejected")
    wrapped.unlink()

    # Signature-boundary fixtures deliberately claim no LLVM module parsing.
    # The exact unsupported/incomplete result is the installed behavior tested.
    llvm = release / "renamed-compiler.data"
    for magic, format_name in ((b"BC\xc0\xde", "llvm-bitcode"),
                               (b"\xde\xc0\x17\x0b", "llvm-bitcode-wrapper")):
        llvm.write_bytes(magic + b"\0" * 20)
        report = cli(python, work, "scan-release", "--root", str(release), "--policy", str(policy), expected=3)
        require(report["checks"]["native_metadata_scan_completed"] is False
                and any(item["code"] == "native_metadata_unverifiable"
                        and item.get("format") == format_name
                        and item.get("reason") == "unsupported_standalone_metadata"
                        for item in report["findings"]), "Installed LLVM signature was incorrectly treated as inspected absence")
    llvm.unlink()
    require(cli(python, work, *private_args)["ok"] is True, "Clean release after disclosure controls failed")
    return {"private_input_clean_accepted": True, "private_input_copy_blocked": True,
            "pyc_integer_key_blocked": True, "encoded_pem_blocked": True,
            "standalone_llvm_unverifiable": True}


def installation(artifact: Path, version: str, work: Path) -> tuple[Path, dict]:
    environment = work / "venv"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = python_in(environment)
    run([str(python), "-m", "pip", "install", "--disable-pip-version-check",
         str(artifact)], cwd=work)
    require(run([str(python), "-I", "-m", "releaseguard", "--version"],
                cwd=work).stdout.strip() == version, "Installed core version differs")
    installed = Path(run([str(python), "-I", "-c",
                          "import releaseguard;print(releaseguard.__file__)"],
                         cwd=work).stdout.strip()).resolve()
    require(environment.resolve() in installed.parents, "Import escaped the fresh environment")

    release = work / "release"
    release.mkdir()
    (release / "app.js").write_text("export const message = 'public';\n", encoding="utf-8")
    policy = work / "policy.json"
    policy.write_text('{"version":1}', encoding="utf-8")
    passed = cli(python, work, "scan-release", "--root", str(release), "--policy", str(policy))
    require(passed["ok"] is True, "Clean release rejected")
    (release / "renamed.dat").write_text(
        '{"version":3,"sources":["private.ts"],"sourcesContent":["owned private source"],'
        '"names":[],"mappings":"AAAA"}', encoding="utf-8")
    blocked = cli(python, work, "scan-release", "--root", str(release),
                  "--policy", str(policy), expected=3)
    require(blocked["ok"] is False, "Renamed source map accepted")
    (release / "renamed.dat").unlink()

    native = cli(python, work, "native-init", "--out", str(work / "native"))
    require(native["ok"] is True, "Native resource initialization failed")
    resources = ["data/cmake/ReleaseGuard.cmake", "data/include/releaseguard/literal.hpp",
                 "data/include/releaseguard/secure_buffer.hpp",
                 "data/include/releaseguard/sealed_asset.hpp",
                 "data/include/releaseguard/token_verify.hpp"]
    for relative in resources:
        require((installed.parent / relative).is_file(), "Missing native resource: " + relative)

    # Use fresh public CLI outputs to verify the installed cryptographic dependency.
    key = work / "asset-key.bin"
    payload = work / "payload.bin"
    envelope = work / "envelope.json"
    opened = work / "opened.bin"
    payload.write_bytes(bytes(range(256)) * 16)
    cli(python, work, "asset-keygen", "--out", str(key))
    context = ["--product", "owned-package-control", "--release", version,
               "--purpose", "installation", "--asset-id", "fixture"]
    cli(python, work, "asset-seal", str(payload), "--key-file", str(key),
        *context, "--out", str(envelope))
    cli(python, work, "asset-open", str(envelope), "--key-file", str(key),
        *context, "--out", str(opened))
    require(opened.read_bytes() == payload.read_bytes(), "Authenticated asset roundtrip differs")
    (release / "leaked.dat").write_bytes(key.read_bytes())
    rejected = cli(python, work, "scan-release", "--root", str(release),
                   "--policy", str(policy), "--asset-key-file", str(key), expected=3)
    require(any(item["code"] == "asset_key_exposure" for item in rejected["findings"]),
            "Leaked asset key was not reported")
    (release / "leaked.dat").unlink()
    # Exercise new modules through the installed wheel/sdist, outside the tree.
    (release / "encoded-key.json").write_text(json.dumps({"key": list(key.read_bytes())}), encoding="ascii")
    structured = cli(python, work, "scan-release", "--root", str(release),
                     "--policy", str(policy), "--asset-key-file", str(key), expected=3)
    require(structured["checks"]["structured_secret_scan_completed"] is True
            and any(item["code"] == "asset_key_exposure" for item in structured["findings"]),
            "Encoded key was not inspected and rejected")
    (release / "encoded-key.json").unlink()
    (release / "consumer-key.json").write_text(
        json.dumps({"data": [999, *[float(value) for value in key.read_bytes()], -1]}), encoding="ascii")
    consumer = cli(python, work, "scan-release", "--root", str(release),
                   "--policy", str(policy), "--asset-key-file", str(key), expected=3)
    require(consumer["checks"]["structured_secret_scan_completed"] is True
            and any(item["code"] == "asset_key_exposure" for item in consumer["findings"]),
            "Consumer-compatible key bytes were not rejected")
    (release / "consumer-key.json").unlink()
    (release / "incomplete-map.json").write_text(
        '{"version":3,"sources":["owned.ts"],"sourcesCont\\u0065nt":["owned source"]}', encoding="ascii")
    incomplete = cli(python, work, "scan-release", "--root", str(release), "--policy", str(policy), expected=3)
    require(any(item["code"] == "source_map_marker" and item.get("representation") == "json-decoded-key"
                for item in incomplete["findings"]), "Incomplete source map was not rejected")
    (release / "incomplete-map.json").unlink()
    wasm_header = b"\0asm\1\0\0\0"
    wasm_input = work / "owned.wasm"
    wasm_bytes = wasm_header + b"\0\5\4name"
    wasm_input.write_bytes(wasm_bytes)
    private_dir = work / "wasm-private"
    private_dir.mkdir()
    public_wasm, private_wasm = release / "owned.wasm", private_dir / "original.wasm"
    split = cli(python, work, "split-wasm-debug", "--input", str(wasm_input),
                "--public", str(public_wasm), "--private", str(private_wasm))
    require(split["ok"] is True and split["checks"]["retained_bytes_identical"] is True
            and public_wasm.read_bytes() == wasm_header and private_wasm.read_bytes() == wasm_bytes,
            "Installed Wasm splitter failed byte preservation")
    public_check = cli(python, work, "scan-release", "--root", str(release), "--policy", str(policy))
    private_check = cli(python, work, "scan-release", "--root", str(private_dir),
                        "--policy", str(policy), expected=3)
    require(public_check["ok"] is True and any(item["code"] == "native_debug_metadata"
            and item["format"] == "wasm" for item in private_check["findings"]),
            "Installed Wasm metadata scan failed its paired control")
    (release / "unlinked.wasm").write_bytes(wasm_header + b"\0\x09\x07linking\x02")
    unlinked = cli(python, work, "scan-release", "--root", str(release), "--policy", str(policy), expected=3)
    require(unlinked["checks"]["native_metadata_scan_completed"] is False
            and any(item.get("reason") == "linker_metadata_requires_final_link" for item in unlinked["findings"]),
            "Unexamined Wasm linker metadata was not rejected")
    (release / "unlinked.wasm").unlink()
    new_controls = installed_disclosure_controls(python, work, release, policy)
    return python, {"artifact": artifact.name, "version": version,
                    "isolated_import": True, "clean_release_accepted": True,
                    "renamed_source_map_blocked": True, "native_resources_present": len(resources),
                    "asset_roundtrip_bytes": len(payload.read_bytes()), "leaked_key_blocked": True,
                    "structured_key_blocked": True, "wasm_split_verified": True,
                    "consumer_key_encodings_blocked": True, "incomplete_source_map_blocked": True,
                    "relocatable_wasm_blocked": True, **new_controls}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="Fresh artifact directory")
    args = parser.parse_args()
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    package = json.loads((ROOT / "packages/releaseguard/package.json").read_text())
    version = package["version"]
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    node = shutil.which("node")
    if not npm or not node:
        raise RuntimeError("Node.js and npm are required")
    run([sys.executable, "-m", "build", "--outdir", str(output)], cwd=ROOT)
    packed = json.loads(run([npm, "pack", "--json", "--pack-destination", str(output)],
                            cwd=ROOT / "packages/releaseguard").stdout)
    sdk = output / packed[0]["filename"]
    wheels = list(output.glob("*.whl"))
    sources = [p for p in output.glob("*.tar.gz") if p.name.startswith("open_release_guard-")]
    if len(wheels) != 1 or len(sources) != 1 or not sdk.is_file():
        raise RuntimeError("Expected one wheel, one source archive and one SDK archive")
    with zipfile.ZipFile(wheels[0]) as archive:
        metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        require(len(metadata) == 1, "Ambiguous wheel metadata")
        validate_wheel_metadata(archive.read(metadata[0]), version)

    observations = []
    with tempfile.TemporaryDirectory(prefix="releaseguard-install-") as temporary:
        work = Path(temporary).resolve()
        interpreters = []
        for name, artifact in (("wheel", wheels[0]), ("sdist", sources[0])):
            case = work / name
            case.mkdir()
            python, result = installation(artifact, version, case)
            interpreters.append(python)
            observations.append(result)
        js = work / "javascript"
        js.mkdir()
        (js / "package.json").write_text('{"private":true,"type":"module"}', encoding="utf-8")
        run([npm, "install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false",
             str(sdk)], cwd=js)
        installed_sdk = json.loads((js / "node_modules/@anti-rea-forge/releaseguard/package.json").read_text())
        require(installed_sdk["version"] == version, "Installed SDK version differs")
        require(not installed_sdk.get("dependencies"), "SDK runtime dependencies changed")
        smoke = """import assert from 'node:assert/strict';
import {mkdir, writeFile, unlink} from 'node:fs/promises';
import {createReleaseGuard} from '@anti-rea-forge/releaseguard';
await mkdir('release'); await writeFile('release/app.js', 'export const x = 1;');
await writeFile('policy.json', JSON.stringify({version:1}));
const guard=createReleaseGuard({python:process.env.RELEASEGUARD_PYTHON});
assert.equal((await guard.scanRelease({root:'release',policy:'policy.json'})).ok,true);
await writeFile('release/app.js.map','{}');
const denied=await guard.scanRelease({root:'release',policy:'policy.json'});
assert.equal(denied.ok,false); assert.equal(denied.exitCode,3);
await unlink('release/app.js.map');
const privateBytes='def owned_private_quote(x):\\n    return x * 37 + 19\\n';
await writeFile('private-implementation.py',privateBytes);
const options={root:'release',policy:'policy.json',privateInputFiles:['private-implementation.py']};
const privateClean=await guard.scanRelease(options);
assert.equal(privateClean.ok,true); assert.equal(privateClean.checks.private_inputs_checked,1);
await writeFile('release/renamed-private.data',privateBytes);
const privateCopy=await guard.scanRelease(options);
assert.equal(privateCopy.ok,false); assert.equal(privateCopy.exitCode,3);
assert.equal(privateCopy.findings.some(item=>item.code==='private_input_exposure' && item.rule_index===0),true);
await unlink('release/renamed-private.data');
assert.equal((await guard.scanRelease(options)).ok,true);
console.log(JSON.stringify({installed_sdk:true,clean_release_accepted:true,source_map_blocked:true,
  private_input_clean_accepted:true,private_input_copy_blocked:true}));
"""
        (js / "smoke.mjs").write_text(smoke, encoding="utf-8")
        env = {**os.environ, "RELEASEGUARD_PYTHON": str(interpreters[0])}
        sdk_result = json.loads(run([node, "smoke.mjs"], cwd=js, env=env).stdout)

    artifacts = [wheels[0], sources[0], sdk]
    report = {"schema": "anti-rea-forge.installation.v1", "ok": True, "version": version,
              "source_commit": os.environ.get("RELEASEGUARD_SOURCE_SHA") or
              run(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip(),
              "source_dirty": bool(run(["git", "status", "--porcelain"], cwd=ROOT).stdout.strip()),
              "platform": platform.system(), "python": platform.python_version(),
              "node": run([node, "--version"], cwd=ROOT).stdout.strip(),
              "python_installations": observations, "javascript_installation": sdk_result,
              "artifacts": [{"name": p.name, "bytes": p.stat().st_size, "sha256": digest(p)}
                            for p in artifacts],
              "scope": "Fresh wheel and source installs plus packed SDK behavior; no resistance score."}
    (output / "installation-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
