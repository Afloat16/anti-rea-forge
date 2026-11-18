"""Paired v1.0/current release checks against recoverable, project-owned keys.

All keys below are public synthetic test material. Never use them in a product.
The recovery controls use standard JSON/base64/cryptography readers, not REA or
an AI model. A scanner error is never counted as successful disclosure blocking.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

import cryptography
from releaseguard import __version__
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BASELINE_SHA256 = "d49b525b889bfd930f0c242a2afdb4240d06f5471a7e1b0c308241a9ef44e970"
KEY = hashlib.sha256(b"releaseguard-owned-only-asset-recovery-v1").digest()
ISSUER = hashlib.sha256(b"releaseguard-owned-only-issuer-recovery-v1").digest()
MESSAGE = b"owned fixture: privileged pricing service proof"
PLAINTEXT = b"owned fixture: unpublished pricing data"
NONCE = bytes(range(12))
CONTEXT = b"releaseguard-owned-structured-key-control"
CIPHERTEXT = AESGCM(KEY).encrypt(NONCE, PLAINTEXT, CONTEXT)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def escaped(value: str) -> str:
    return '"' + "".join("\\u%04x" % ord(char) for char in value) + '"'


def run(python: Path, arguments: list[str], expected: int) -> bytes:
    completed = subprocess.run([str(python), "-I", "-m", "releaseguard", *arguments],
                               capture_output=True, timeout=60, check=False)
    require(completed.returncode == expected,
            "Release check failed to complete with the expected decision (exit %s)" % completed.returncode)
    return completed.stdout


def version(python: Path) -> str:
    return run(python, ["--version"], 0).decode("ascii").strip().split()[-1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-python", type=Path, required=True)
    parser.add_argument("--baseline-wheel", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(digest(args.baseline_wheel.read_bytes()) == BASELINE_SHA256,
            "Baseline must be the SHA-256-verified public v1.0.0 wheel")
    before_version, after_version = version(args.baseline_python), version(args.python)
    require(before_version == "1.0.0", "Expected baseline release 1.0.0")
    require(after_version == __version__, "Expected the installed candidate core version")
    issuer = Ed25519PrivateKey.from_private_bytes(ISSUER)
    public = issuer.public_key()
    pem = issuer.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption()).decode("ascii")
    der = issuer.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(public.public_bytes_raw())}
    private_jwk = {**public_jwk, "d": b64url(ISSUER)}
    cases = [
        ("asset-unicode.json", ('{"key":' + escaped(KEY.hex()) + '}').encode(), "asset-hex"),
        ("asset-array.json", json.dumps({"key": list(KEY)}).encode(), "asset-array"),
        ("issuer-escaped.json", ('{"issuer":' + escaped(pem) + '}').encode(), "issuer-pem"),
        ("issuer-jwk.json", json.dumps(private_jwk).encode(), "issuer-jwk"),
        ("issuer.data", der, "issuer-der"),
    ]
    rows = []
    negatives = []
    with tempfile.TemporaryDirectory(prefix="releaseguard-owned-key-controls-") as work:
        root = Path(work)
        policy = root / "policy.json"
        policy.write_text('{"version":1}', encoding="ascii")
        asset_key_file = root / "external.key"
        asset_key_file.write_bytes(KEY)

        def inspect(data: bytes, filename: str, case: str, blocked: bool) -> dict:
            folder = root / case
            folder.mkdir()
            target = folder / filename
            target.write_bytes(data)
            arguments = ["scan-release", "--root", str(folder), "--policy", str(policy),
                         "--asset-key-file", str(asset_key_file)]
            before = json.loads(run(args.baseline_python, arguments, 0))
            after = json.loads(run(args.python, arguments, 3 if blocked else 0))
            require(before["ok"] is True and after["ok"] is (not blocked), "Unexpected paired gate verdict")
            require(before["checks"]["scan_completed"] is True and after["checks"]["scan_completed"] is True,
                    "Incomplete execution cannot establish a verdict")
            require(after["checks"]["structured_secret_scan_completed"] is True,
                    "Unsupported or incomplete inspection cannot establish a blocked secret")
            require(target.read_bytes() == data, "Inspection modified its input")
            codes = sorted({row["code"] for row in after["findings"]})
            if blocked:
                require(any(code in {"private_key_marker", "private_key_structure", "asset_key_exposure"}
                            for code in codes), "Expected a positive secret finding, not a parser failure")
            return {"file": filename, "bytes": len(data), "sha256": digest(data),
                    "baseline_allowed": before["ok"], "current_allowed": after["ok"],
                    "current_finding_codes": codes, "inspection_complete": True,
                    "input_unchanged": True}

        for filename, data, kind in cases:
            if kind.startswith("asset"):
                value = json.loads(data)["key"]
                recovered = bytes.fromhex(value) if kind == "asset-hex" else bytes(value)
                require(AESGCM(recovered).decrypt(NONCE, CIPHERTEXT, CONTEXT) == PLAINTEXT,
                        "Asset recovery positive control failed")
                proof = "exact-aes-gcm-plaintext"
            else:
                if kind == "issuer-pem":
                    recovered = serialization.load_pem_private_key(json.loads(data)["issuer"].encode(), None)
                elif kind == "issuer-jwk":
                    recovered = Ed25519PrivateKey.from_private_bytes(unb64url(json.loads(data)["d"]))
                else:
                    recovered = serialization.load_der_private_key(data, None)
                public.verify(recovered.sign(MESSAGE), MESSAGE)
                proof = "valid-ed25519-signature"
            rows.append({**inspect(data, filename, kind, True), "standard_reader_recovery": True,
                         "recovery_proof": proof})
        negatives.append(inspect(json.dumps(public_jwk).encode(), "public-jwk.json", "public-key", False))
        negatives.append(inspect(NONCE + CIPHERTEXT, "ciphertext.bin", "external-key-ciphertext", False))
    report = {
        "schema": "releaseguard/structured-secret-recovery/v1", "ok": True,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "baseline": {"version": before_version, "wheel_sha256": BASELINE_SHA256,
                     "release": "https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.0.0"},
        "current_version": after_version,
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "cryptography": cryptography.__version__},
        "recoverable_cases": rows, "nonsecret_controls": negatives,
        "summary": {"standard_reader_recoveries": len(rows), "baseline_missed": len(rows),
                    "current_positive_blocks": len(rows), "nonsecret_controls_allowed": len(negatives)},
        "limitations": ["Five owned encodings, not a general secret-detection recall estimate.",
                        "Standard readers, not REA, recover these keys; the separate Wasm and source-map controls execute REA.",
                        "The gate stops a release; it does not make already disclosed key material unrecoverable.",
                        "Fixture keys are public test material and must never be used in a product."],
    }
    encoded = json.dumps(report, indent=2) + "\n"
    with args.out.open("x", encoding="utf-8") as destination:
        destination.write(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
