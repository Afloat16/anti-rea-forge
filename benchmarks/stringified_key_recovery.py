"""Official v1.3 paired gates for owned keys inside serialized JSON strings.

Node's real JSON.parse and crypto consumers recover signatures and an AES-GCM
asset. Only public synthetic fixture keys are used. This does not run REA or a
model, and a refused publication does not make the fixture key unrecoverable.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from llvm_metadata_recovery import installed_identity


BASELINE_SHA256 = "1bb79222ca7aa1224f3815b2cacf235985e9c9f08bf7330ce0a80099df7bc3a6"
SEED = bytes(range(255, 223, -1))
ASSET_KEY = bytes(range(224, 256))
MESSAGE = b"owned serialized JSON configuration proof"
PLAINTEXT = b"owned private release asset kept outside staging"
NONCE = bytes(range(12))
CIPHERTEXT = AESGCM(ASSET_KEY).encrypt(NONCE, PLAINTEXT, MESSAGE)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def serialized(value, layers=1):
    for _ in range(layers):
        value = json.dumps(value, separators=(",", ":"))
    return value


def cli(python, *arguments):
    result = subprocess.run([str(python), "-I", "-m", "releaseguard", *map(str, arguments)],
                            capture_output=True, text=True, timeout=60)
    require(result.returncode in (0, 3) and result.stderr == "", "Publication scanner did not complete")
    report = json.loads(result.stdout)
    require(type(report.get("ok")) is bool and result.returncode == (0 if report["ok"] else 3),
            "Publication scanner decision and exit status differ")
    return report


def timing(python, path):
    script = r'''
import json, pathlib, statistics, sys, time
from releaseguard.structured_secrets import scan_json_secrets
document = json.loads(pathlib.Path(sys.argv[1]).read_text())
samples = []
for _ in range(9):
    start = time.perf_counter()
    if scan_json_secrets(document):
        raise RuntimeError("Normal performance control produced a finding")
    samples.append((time.perf_counter() - start) * 1000)
print(json.dumps({"iterations": len(samples), "median_ms": statistics.median(samples), "min_ms": min(samples)}))
'''
    result = subprocess.run([str(python), "-I", "-c", script, str(path)],
                            capture_output=True, text=True, timeout=60)
    require(result.returncode == 0 and result.stderr == "", "Performance control did not complete")
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-python", type=Path, required=True)
    parser.add_argument("--baseline-wheel", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--node", default=shutil.which("node"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(bool(args.node), "Real Node is required for JSON.parse consumer verification")
    wheel = args.baseline_wheel.resolve(strict=True)
    require(hashlib.sha256(wheel.read_bytes()).hexdigest() == BASELINE_SHA256,
            "Expected the verified official v1.3.0 wheel")
    baseline_before = installed_identity(args.baseline_python, wheel)
    candidate_before = installed_identity(args.python)
    require(baseline_before["version"] == "1.3.0", "Expected the official v1.3 installed baseline")

    issuer = Ed25519PrivateKey.from_private_bytes(SEED)
    public = issuer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    url = lambda data: base64.urlsafe_b64encode(data).decode().rstrip("=")
    jwk = {"kty": "OKP", "crv": "Ed25519", "d": url(SEED), "x": url(public)}
    public_jwk = {key: value for key, value in jwk.items() if key != "d"}
    unicode_jwk = '"' + "".join("\\u%04x" % ord(char) for char in serialized(jwk)) + '"'
    cases = [
        ("jwk-object-string", {"key": serialized(jwk)}, 1, "jwk"),
        ("jwk-two-string-layers", {"key": serialized(jwk, 2)}, 2, "jwk"),
        ("jwk-unicode-string-layer", {"key": unicode_jwk}, 2, "jwk"),
        ("known-key-array-string", {"key": serialized(list(ASSET_KEY))}, 1, "asset"),
        ("known-key-array-two-string-layers", {"key": serialized(list(ASSET_KEY), 2)}, 2, "asset"),
        ("known-key-array-integral-floats", {"key": serialized([float(n) for n in ASSET_KEY])}, 1, "asset"),
    ]
    # These are still recovered by Node. The candidate refuses an incomplete
    # inspection; they are excluded from the six positive disclosure findings.
    incomplete_cases = [
        ("third-json-parse", {"key": serialized(jwk, 3)}, 3, "jwk"),
        ("single-container-text-budget", {"key": serialized(dict(jwk, note="x" * (64 * 1024)))}, 1, "jwk"),
        ("shared-decoded-byte-budget", {"key": serialized(jwk),
                                        "aux": [serialized({"data": "." * 50000})] * 6}, 1, "jwk"),
        ("shared-candidate-budget", {"key": serialized(jwk), "aux": ['{"public":1}'] * 64}, 1, "jwk"),
        ("duplicate-jwk-member", {"key": '{"kty":"oct",' + serialized(jwk)[1:]}, 1, "jwk"),
        ("nonfinite-optional-member", {"key": serialized(jwk)[:-1] + ',"counter":1e999}'}, 1, "jwk"),
    ]
    controls = [
        ("ordinary-text", {"text": "ordinary release documentation"}),
        ("serialized-public-jwk", {"key": serialized(public_jwk)}),
        ("serialized-public-array", {"settings": "[1,2,3,4]"}),
        ("invalid-template-text", {"template": "{render at runtime}"}),
        ("large-unrelated-string", {"data": "public-data" * 100000}),
        ("many-empty-public-containers", {"placeholders": ["[]", "{}", '""', " \t[ \r\n ] "] * 65}),
    ]
    program = r"""const fs=require('node:fs'),c=require('node:crypto');
const doc=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));
let key=doc.key;
for(let i=0;i<Number(process.argv[2]);i++)key=JSON.parse(key);
const message=Buffer.from('owned serialized JSON configuration proof');
if(process.argv[3]==='jwk'){
 console.log(JSON.stringify({signature:c.sign(null,message,c.createPrivateKey({key,format:'jwk'})).toString('base64')}));
}else{
 const ciphertext=Buffer.from(process.argv[4],'base64');
 const decipher=c.createDecipheriv('aes-256-gcm',Buffer.from(key),Buffer.from(process.argv[5],'base64'));
 decipher.setAAD(message);
 decipher.setAuthTag(ciphertext.subarray(-16));
 console.log(JSON.stringify({plaintext:Buffer.concat([decipher.update(ciphertext.subarray(0,-16)),decipher.final()]).toString('base64')}));
}"""
    node_version = subprocess.check_output([args.node, "--version"], text=True, timeout=15).strip()
    positive, incomplete, normal = [], [], []
    with tempfile.TemporaryDirectory(prefix="owned-stringified-keys-") as directory:
        work = Path(directory)
        policy = work / "policy.json"
        policy.write_text('{"version":1}', encoding="ascii")
        keyfile = work / "asset-key.bin"
        keyfile.write_bytes(ASSET_KEY)

        def fixture(name, document):
            root = work / name
            root.mkdir()
            path = root / "configuration.json"
            path.write_text(json.dumps(document), encoding="ascii")
            return root, path

        def decision(python, root, kind):
            return cli(python, "scan-release", "--root", root, "--policy", policy,
                       *(["--asset-key-file", keyfile] if kind == "asset" else []))

        def recovery(path, parses, kind):
            process = subprocess.run([args.node, "-e", program, str(path), str(parses), kind,
                                      base64.b64encode(CIPHERTEXT).decode(), base64.b64encode(NONCE).decode()],
                                     capture_output=True, text=True, timeout=30)
            require(process.returncode == 0 and process.stderr == "", "Real Node consumer did not complete")
            recovered = json.loads(process.stdout)
            if kind == "jwk":
                issuer.public_key().verify(base64.b64decode(recovered["signature"]), MESSAGE)
            else:
                require(base64.b64decode(recovered["plaintext"]) == PLAINTEXT,
                        "Real Node did not recover the exact owned asset")

        def blinded(report):
            raw = json.dumps(report).encode()
            for private in (SEED, SEED.hex().encode(), jwk["d"].encode(), ASSET_KEY.hex().encode(),
                            hashlib.sha256(SEED).hexdigest().encode()):
                require(private not in raw, "Report disclosed owned private material")

        for is_incomplete, group in [(False, cases), (True, incomplete_cases)]:
            for name, document, parses, kind in group:
                root, path = fixture(name, document)
                original = path.read_bytes()
                recovery(path, parses, kind)
                baseline = decision(args.baseline_python, root, kind)
                candidate = decision(args.python, root, kind)
                blinded(candidate)
                require(baseline["ok"] and baseline["checks"]["structured_secret_scan_completed"],
                        "Official v1.3 did not reproduce the expected allowed disclosure")
                require(not candidate["ok"], "Candidate allowed the owned disclosure")
                codes = sorted({finding["code"] for finding in candidate["findings"]})
                completed = candidate["checks"]["structured_secret_scan_completed"]
                if is_incomplete:
                    require(not completed and "structured_secret_unverifiable" in codes,
                            "Incomplete profile was not explicitly refused")
                else:
                    expected = "asset_key_exposure" if kind == "asset" else "private_key_structure"
                    require(completed and expected in codes, "Expected a completed positive key finding")
                require(path.read_bytes() == original, "A consumer or gate modified the inspected JSON input")
                record = {"case": name, "additional_json_parses": parses,
                          "input_bytes": len(original), "input_sha256": hashlib.sha256(original).hexdigest(),
                          "input_unchanged": True,
                          "consumer": "Node JSON.parse + " + ("Ed25519 signature" if kind == "jwk" else "AES-256-GCM decrypt"),
                          "real_recovery_verified": True, "baseline_ok": baseline["ok"],
                          "candidate_ok": candidate["ok"], "candidate_codes": codes,
                          "structured_secret_scan_completed": completed,
                          "candidate_report_contains_key_material": False}
                (incomplete if is_incomplete else positive).append(record)

        for name, document in controls:
            root, path = fixture(name, document)
            original = path.read_bytes()
            baseline = decision(args.baseline_python, root, "normal")
            candidate = decision(args.python, root, "normal")
            require(baseline["ok"] and candidate["ok"], "Normal compatibility control was refused")
            require(candidate["checks"]["structured_secret_scan_completed"], "Normal control inspection incomplete")
            normal.append({"case": name, "json_bytes": len(original),
                           "input_sha256": hashlib.sha256(original).hexdigest(),
                           "input_unchanged": True, "baseline_ok": True, "candidate_ok": True,
                           "baseline_scan_json": timing(args.baseline_python, path),
                           "candidate_scan_json": timing(args.python, path)})
            require(path.read_bytes() == original, "A gate or timing control modified the normal JSON input")

    baseline_after = installed_identity(args.baseline_python, wheel)
    candidate_after = installed_identity(args.python)
    require(baseline_before == baseline_after and candidate_before == candidate_after,
            "Installed package identity changed while the benchmark was running")
    output = {
        "schema": "open-release-guard/stringified-key-recovery/v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "benchmark_files_sha256": {"driver": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "identity_helper": hashlib.sha256(Path(__file__).with_name("llvm_metadata_recovery.py").read_bytes()).hexdigest()},
        "environment": {"python": platform.python_version(), "node": node_version,
                        "cryptography": cryptography.__version__, "platform": platform.platform()},
        "baseline_wheel_sha256": BASELINE_SHA256,
        "baseline_identity_before": baseline_before, "baseline_identity_after": baseline_after,
        "candidate_identity_before": candidate_before, "candidate_identity_after": candidate_after,
        "profile": {"maximum_additional_json_parses": 2, "single_container_utf8_bytes": 65536,
                    "shared_decode_candidates": 64, "shared_decoded_bytes": 262144,
                    "shared_json_nodes": 100000, "shared_structure_depth": 64},
        "positive_cases": positive, "incomplete_cases": incomplete, "normal_controls": normal,
        "summary": {"baseline_allowed_real_recoveries": len(positive), "candidate_positive_refusals": len(positive),
                    "baseline_allowed_incomplete_recoveries": len(incomplete),
                    "candidate_explicit_incomplete_refusals": len(incomplete), "normal_controls_allowed": len(normal)},
        "limitations": ["Owned synthetic keys only; no REA or model was invoked.",
                        "Only object, array or string JSON envelopes are decoded, at most twice beyond the outer document.",
                        "DER, PEM and JSON attempts share the candidate and byte budgets; invalid template attempts also consume budget.",
                        "Budget, duplicate-member and numeric-profile refusals are incomplete inspections, not positive secret findings.",
                        "Arbitrary nested encoding, expressions, custom transforms and unknown secrets remain outside this profile.",
                        "Timing is a local nine-iteration parser control, not a general release-throughput claim."],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(output, indent=2) + "\n")
    print(json.dumps(output["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
