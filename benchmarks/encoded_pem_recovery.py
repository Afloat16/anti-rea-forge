"""Official v1.2 paired gate and real consumer recovery of owned PEM wrappers.

These public fixture keys are unsuitable for production. This benchmark uses
standard Python/Node decoders and real Ed25519 signatures; it does not run REA
or a model, and does not equate a refused publication with an unreadable key.
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

# This verifier checks complete installed package bytes without importing any
# compiler tools. Keep the official v1.2 identity check shared across controls.
from llvm_metadata_recovery import BASELINE_SHA256, installed_identity


MESSAGE = b"owned wrapped PEM benchmark"
SEED = bytes(range(255, 223, -1))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-python", type=Path, required=True)
    parser.add_argument("--baseline-wheel", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--node", default=shutil.which("node"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(bool(args.node), "Real Node is required for consumer compatibility controls")
    wheel = args.baseline_wheel.resolve(strict=True)
    require(sha256(wheel.read_bytes()) == BASELINE_SHA256, "Expected the verified official v1.2 wheel")
    before = installed_identity(args.baseline_python, wheel)
    candidate = installed_identity(args.python)
    require(before["version"] == "1.2.0", "Expected the installed v1.2 baseline")
    issuer = Ed25519PrivateKey.from_private_bytes(SEED)
    pem = issuer.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
    public = issuer.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    encoded = base64.b64encode(pem).decode()
    cases = [
        ("pem-base64", encoded, "base64"),
        ("pem-hex", pem.hex(), "hex"),
        ("pem-leading-one-byte", base64.b64encode(b"\n" + pem).decode(), "base64"),
        ("pem-leading-two-bytes", base64.b64encode(b"\n\n" + pem).decode(), "base64"),
        ("pem-leading-notes", base64.b64encode(b"Owned build notes\n" * 40 + pem).decode(), "base64"),
        ("pem-base64-ignored-noise", encoded[:15] + "\r\n!\0" + encoded[15:], "node-base64"),
        ("pem-base64-utf16-alias", "".join(chr(ord(char) + 256) for char in encoded), "node-base64"),
        ("pem-hex-ascii-folding", " \n".join(pem.hex().upper()[i:i + 2]
                                             for i in range(0, len(pem) * 2, 2)), "hex"),
    ]
    # Both cases are independently recoverable. They are excluded from the
    # positive detections because the gate refuses incomplete inspection.
    budget_cases = [
        ("pem-raw-text-budget", base64.b64encode(b"Owned notes\n" * 25_000 + pem).decode(), "base64"),
        ("pem-decoded-byte-budget", base64.b64encode(b"Owned notes\n" * 6_000 + pem).decode(), "base64"),
    ]
    observations, normal, incomplete = [], [], []
    node_program = """const fs=require('node:fs'),c=require('node:crypto');
const v=JSON.parse(fs.readFileSync(process.argv[1],'utf8')).encoded;
const key=c.createPrivateKey(Buffer.from(v,'base64'));
console.log(JSON.stringify(c.sign(null,Buffer.from('owned wrapped PEM benchmark'),key).toString('base64')));"""
    node_version = subprocess.check_output([args.node, "--version"], text=True, timeout=15).strip()
    with tempfile.TemporaryDirectory(prefix="owned-wrapped-pem-") as directory:
        work = Path(directory)
        policy = work / "policy.json"
        policy.write_text('{"version":1}', encoding="ascii")

        def recover(path, consumer):
            if consumer == "node-base64":
                result = subprocess.run([args.node, "-e", node_program, str(path)],
                                        capture_output=True, text=True, timeout=30)
                require(result.returncode == 0 and result.stderr == "", "Real Node recovery did not complete")
                signature = base64.b64decode(json.loads(result.stdout))
            else:
                value = json.loads(path.read_bytes())["encoded"]
                raw = bytes.fromhex(value) if consumer == "hex" else base64.b64decode(value)
                recovered = serialization.load_pem_private_key(raw, password=None)
                signature = recovered.sign(MESSAGE)
            issuer.public_key().verify(signature, MESSAGE)
            require(signature == issuer.sign(MESSAGE), "Recovered signing key differs")

        def scan(python, root, expected):
            result = subprocess.run([str(python), "-I", "-m", "releaseguard", "scan-release",
                                     "--root", str(root), "--policy", str(policy)],
                                    capture_output=True, timeout=60)
            require(result.returncode == expected and result.stderr == b"", "Gate did not complete as expected")
            return json.loads(result.stdout)

        def inspect(name, value, consumer=None, *, budget=False):
            root = work / name
            root.mkdir()
            path = root / "settings.json"
            data = json.dumps({"encoded": value}, ensure_ascii=True).encode("ascii")
            path.write_bytes(data)
            if consumer:
                recover(path, consumer)
            baseline = scan(args.baseline_python, root, 0)
            current = scan(args.python, root, 3 if consumer else 0)
            require(baseline["ok"] and current["ok"] is (consumer is None), "Paired gate result differs")
            require(current["checks"]["scan_completed"], "Gate plan did not complete")
            require(current["checks"]["structured_secret_scan_completed"] is (not budget),
                    "Inspection completion was not classified accurately")
            codes = sorted({finding["code"] for finding in current["findings"]})
            if consumer:
                require(("structured_secret_unverifiable" if budget else "private_key_marker") in codes,
                        "Expected the precise positive or incomplete inspection finding")
            require(path.read_bytes() == data, "Inspection modified its release input")
            record = {"case": name, "bytes": len(data), "sha256": sha256(data),
                      "baseline_allowed": True, "current_allowed": current["ok"],
                      "structured_inspection_complete": not budget, "current_finding_codes": codes,
                      "input_unchanged": True, "counted_as_positive_detection": bool(consumer) and not budget}
            if consumer:
                record.update({"consumer": "Node Buffer.from / crypto.createPrivateKey" if consumer == "node-base64"
                               else "Python standard decoder / cryptography PEM loader",
                               "recovery_proof": "valid-exact-ed25519-signature", "actual_recovery_completed": True})
            return record

        for name, value, consumer in cases:
            observations.append(inspect(name, value, consumer))
        for name, value, consumer in budget_cases:
            incomplete.append(inspect(name, value, consumer, budget=True))
        normal.append(inspect("public-pem-base64", base64.b64encode(public).decode()))
        normal.append(inspect("public-unrelated-hex", (b"public data\n" * 30_000).hex()))
    require(installed_identity(args.baseline_python, wheel) == before
            and installed_identity(args.python) == candidate, "Compared package changed during the experiment")
    report = {
        "schema": "releaseguard/encoded-pem-recovery/v1", "ok": True,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "baseline": {**before, "wheel_sha256": BASELINE_SHA256,
                     "release": "https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.2.0"},
        "candidate": candidate, "benchmark_sha256": sha256(Path(__file__).read_bytes()),
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "cryptography": cryptography.__version__, "node": node_version},
        "recoverable_cases": observations, "nonsecret_controls": normal, "over_budget_controls": incomplete,
        "summary": {"positive_recoveries": len(observations), "baseline_missed": len(observations),
                    "current_positive_blocks": len(observations), "nonsecret_controls_allowed": len(normal),
                    "recoverable_over_budget_rejections": len(incomplete)},
        "limitations": [
            "Eight representations of one owned key, not eight independent vulnerabilities or general recall.",
            "Marker recognition is conservative; it does not prove every marked PEM is a mathematically valid key.",
            "One outer hex/Base64 encoding is inspected; arbitrary nested encodings or computed keys remain outside scope.",
            "Both over-budget cases really recover, but are refused as incomplete and excluded from positive detections.",
            "REA and AI models are not called by this standard-consumer experiment.",
            "Refusing a release does not erase keys already disclosed; fixture keys are public test material.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(json.dumps({"out": str(args.out), **report["summary"]}))


if __name__ == "__main__":
    main()
