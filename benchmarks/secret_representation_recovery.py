"""Real consumer recoveries missed by v1.1, on public synthetic keys only.

Node imports the JWK variants and materializes numeric byte arrays. Standard
Python/cryptography decoders prove exact AES-GCM decryption and Ed25519 signing.
No REA or model is run here. These known test keys must never be used in a product.
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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from releaseguard import __version__


BASELINE_SHA256 = "5040a0f33c6b5a640302af4983556abdcab1918e845f4bac4010ec2fa2233086"
KEY = bytes(range(224, 256))
SEED = bytes(range(255, 223, -1))
MESSAGE = b"owned expanded representation proof"
PAYLOAD = b"owned private asset retained outside the release"
NONCE = bytes(range(12))
CIPHERTEXT = AESGCM(KEY).encrypt(NONCE, PAYLOAD, MESSAGE)
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def cli(python: Path, arguments: list[str], expected: int) -> bytes:
    completed = subprocess.run([str(python), "-I", "-m", "releaseguard", *arguments],
                               capture_output=True, timeout=60, check=False)
    require(completed.returncode == expected,
            "Scanner did not complete with the expected decision (exit %s)" % completed.returncode)
    require(completed.stderr == b"", "Scanner emitted unexpected diagnostics")
    return completed.stdout


def version(python: Path) -> str:
    return cli(python, ["--version"], 0).decode("ascii").strip().split()[-1]


def node_json(node: str, program: str, path: Path) -> dict | str:
    process = subprocess.run([node, "-e", program, str(path)], capture_output=True,
                             text=True, timeout=30, check=False)
    require(process.returncode == 0 and process.stderr == "", "Real Node recovery did not complete")
    return json.loads(process.stdout)


def verify_baseline(python: Path, wheel: Path) -> dict:
    """Bind the isolated interpreter's installed package to the official wheel."""
    require(digest(wheel.read_bytes()) == BASELINE_SHA256,
            "Baseline wheel must match the verified public v1.1.0 release")
    script = r'''
import hashlib, importlib.metadata, json, pathlib, releaseguard, sys, zipfile
root = pathlib.Path(releaseguard.__file__).resolve().parent
with zipfile.ZipFile(sys.argv[1]) as wheel:
    files = sorted(n for n in wheel.namelist() if n.startswith("releaseguard/") and not n.endswith("/"))
    expected = {n[len("releaseguard/"):] for n in files}
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
    if actual != expected:
        raise RuntimeError("Installed baseline files differ from official wheel")
    inventory = hashlib.sha256()
    for name in files:
        data = wheel.read(name)
        if (root / name[len("releaseguard/"):]).read_bytes() != data:
            raise RuntimeError("Installed baseline bytes differ from official wheel")
        inventory.update((name + " " + hashlib.sha256(data).hexdigest() + "\n").encode())
version = importlib.metadata.version("open-release-guard")
if version != "1.1.0" or releaseguard.__version__ != version:
    raise RuntimeError("Expected the official v1.1.0 installed package")
print(json.dumps({"version": version, "verified_package_files": len(files), "package_inventory_sha256": inventory.hexdigest()}))
'''
    result = subprocess.run([str(python), "-I", "-c", script, str(wheel.resolve())],
                            capture_output=True, timeout=30, check=False)
    require(result.returncode == 0 and result.stderr == b"", "Installed baseline verification failed")
    return json.loads(result.stdout)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-python", type=Path, required=True)
    parser.add_argument("--baseline-wheel", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--node", default=shutil.which("node"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(bool(args.node), "Node.js is required; missing tools are not protection")
    baseline_identity = verify_baseline(args.baseline_python, args.baseline_wheel)
    before_version, after_version = version(args.baseline_python), version(args.python)
    require(before_version == "1.1.0" and after_version == __version__, "Unexpected compared release versions")
    node_version = subprocess.check_output([args.node, "--version"], text=True, timeout=15).strip()
    issuer = Ed25519PrivateKey.from_private_bytes(SEED)
    public = issuer.public_key()
    der = issuer.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
    spki = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(public.public_bytes_raw())}
    private_jwk = {**public_jwk, "d": b64url(SEED)}
    rsa_issuer = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    numbers = rsa_issuer.private_numbers()
    rsa_numbers = {"n": numbers.public_numbers.n, "e": numbers.public_numbers.e,
                   "d": numbers.d, "p": numbers.p, "q": numbers.q,
                   "dp": numbers.dmp1, "dq": numbers.dmq1, "qi": numbers.iqmp}
    padded_rsa = {"kty": "RSA", **{field: b64url(b"\0" + value.to_bytes((value.bit_length() + 7) // 8, "big"))
                                   for field, value in rsa_numbers.items()}}
    spelling = private_jwk["d"]
    classic = spelling.replace("-", "+").replace("_", "/")
    noncanonical = spelling[:-1] + ALPHABET[ALPHABET.index(spelling[-1]) | 1]
    require(classic != spelling and noncanonical != spelling, "Fixture variants must differ from canonical input")
    folded_key = base64.b64encode(KEY).decode("ascii")
    encoded_der = base64.b64encode(der).decode("ascii")
    cases = [
        ("jwk-classic-alphabet", {**private_jwk, "d": classic}, "jwk"),
        ("jwk-ascii-folding", {**private_jwk, "d": spelling[:15] + "\r\n " + spelling[15:]}, "jwk"),
        ("jwk-unused-pad-bits", {**private_jwk, "d": noncanonical}, "jwk"),
        ("asset-integral-floats", {"data": [float(value) for value in KEY], "start": 0}, "array"),
        ("asset-embedded-window", {"data": [9, 7, *KEY, 5, 2], "start": 2}, "array"),
        ("asset-folded-base64", {"key": folded_key[:20] + "\r\n" + folded_key[20:]}, "base64"),
        ("asset-mixed-case-hex", {"key": "".join(char.upper() if index % 2 else char
                                                 for index, char in enumerate(KEY.hex()))}, "hex"),
        ("private-der-base64", {"privateKey": encoded_der}, "der-base64"),
        ("private-der-hex", {"privateKey": der.hex()}, "der-hex"),
        ("jwk-ignored-ascii", {**private_jwk, "d": spelling[:10] + "!" + spelling[10:]}, "jwk"),
        ("jwk-nbsp", {**private_jwk, "d": "\u00a0" + spelling}, "jwk"),
        ("jwk-nul", {**private_jwk, "d": "\0" + spelling}, "jwk"),
        ("jwk-excess-padding", {**private_jwk, "d": spelling + "===="}, "jwk"),
        ("jwk-data-after-padding", {**private_jwk, "d": spelling + "=YWJj"}, "jwk"),
        ("jwk-utf16-low-byte-alias", {**private_jwk, "d": "".join(chr(ord(char) + 256) for char in spelling)}, "jwk"),
        ("jwk-non-bmp-alias", {**private_jwk, "d": "".join(chr(0x10000 + ord(char)) for char in spelling)}, "jwk"),
        ("jwk-lone-surrogate", {**private_jwk, "d": "\ud800" + spelling}, "jwk"),
        ("jwk-rsa-leading-zero-integers", padded_rsa, "rsa"),
        ("private-der-ignored-separator", {"privateKey": encoded_der[:10] + "!" + encoded_der[10:]}, "der-base64"),
    ]
    jwk_reader = """const fs=require('node:fs'),c=require('node:crypto');
const key=c.createPrivateKey({key:JSON.parse(fs.readFileSync(process.argv[1],'utf8')),format:'jwk'});
console.log(JSON.stringify({public:c.createPublicKey(key).export({type:'spki',format:'der'}).toString('base64'),
signature:c.sign(key.asymmetricKeyType==='rsa'?'sha256':null,Buffer.from('owned expanded representation proof'),key).toString('base64')}));"""
    array_reader = """const fs=require('node:fs');const value=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));
console.log(JSON.stringify(Buffer.from(value.data).subarray(value.start,value.start+32).toString('base64')));"""
    observations, normal, budget_controls = [], [], []
    with tempfile.TemporaryDirectory(prefix="releaseguard-owned-representation-") as directory:
        work = Path(directory)
        policy = work / "policy.json"
        policy.write_text('{"version":1}', encoding="ascii")
        key_file = work / "external.key"
        key_file.write_bytes(KEY)

        def inspect(name: str, document, *, known_key: bool, blocked: bool, proof=None,
                    inspection_complete: bool = True) -> dict:
            root = work / name
            root.mkdir()
            target = root / "payload.json"
            data = json.dumps(document, separators=(",", ":")).encode("utf-8")
            target.write_bytes(data)
            if proof is not None:
                proof(target)
            arguments = ["scan-release", "--root", str(root), "--policy", str(policy)]
            if known_key:
                arguments.extend(["--asset-key-file", str(key_file)])
            baseline = json.loads(cli(args.baseline_python, arguments, 0))
            current = json.loads(cli(args.python, arguments, 3 if blocked else 0))
            require(baseline["ok"] is True and current["ok"] is (not blocked), "Unexpected paired gate verdict")
            require(baseline["checks"]["scan_completed"] is True and current["checks"]["scan_completed"] is True,
                    "Incomplete scanner execution cannot establish a result")
            require(current["checks"]["structured_secret_scan_completed"] is inspection_complete,
                    "Structured inspection did not have the expected completion state")
            codes = sorted({finding["code"] for finding in current["findings"]})
            if blocked and inspection_complete:
                require(any(code in {"private_key_structure", "asset_key_exposure"} for code in codes),
                        "Expected a positive secret finding, not a parser failure")
            elif blocked:
                require("structured_secret_unverifiable" in codes,
                        "An exceeded inspection budget must explicitly prevent publication")
            require(target.read_bytes() == data, "Inspection modified its owned input")
            return {"case": name, "bytes": len(data), "sha256": digest(data),
                    "baseline_allowed": baseline["ok"], "current_allowed": current["ok"],
                    "current_finding_codes": codes, "inspection_complete": inspection_complete, "input_unchanged": True}

        for name, document, kind in cases:
            def prove(path: Path) -> None:
                if kind in {"jwk", "rsa"}:
                    result = node_json(args.node, jwk_reader, path)
                    expected_issuer = rsa_issuer if kind == "rsa" else issuer
                    expected_spki = expected_issuer.public_key().public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                    require(base64.b64decode(result["public"]) == expected_spki, "Node recovered a different key")
                    signature = base64.b64decode(result["signature"])
                    options = (padding.PKCS1v15(), hashes.SHA256()) if kind == "rsa" else ()
                    expected_issuer.public_key().verify(signature, MESSAGE, *options)
                    require(signature == expected_issuer.sign(MESSAGE, *options), "Recovered issuer signature differs")
                elif kind in {"array", "base64", "hex"}:
                    value = json.loads(path.read_bytes())
                    recovered = (base64.b64decode(node_json(args.node, array_reader, path)) if kind == "array"
                                 else base64.b64decode(value["key"]) if kind == "base64"
                                 else bytes.fromhex(value["key"]))
                    require(AESGCM(recovered).decrypt(NONCE, CIPHERTEXT, MESSAGE) == PAYLOAD,
                            "Recovered asset key did not decrypt the original payload")
                else:
                    value = json.loads(path.read_bytes())["privateKey"]
                    raw = base64.b64decode(value) if kind == "der-base64" else bytes.fromhex(value)
                    recovered = serialization.load_der_private_key(raw, password=None)
                    signature = recovered.sign(MESSAGE)
                    public.verify(signature, MESSAGE)
                    require(signature == issuer.sign(MESSAGE), "Recovered DER issuer signature differs")
            record = inspect(name, document, known_key=name.startswith("asset-"), blocked=True, proof=prove)
            record.update({"recovery_proof": "exact-aes-gcm-plaintext" if name.startswith("asset-") else
                                            "valid-rsa-sha256-signature" if kind == "rsa" else "valid-ed25519-signature",
                           "consumer": "Node.js crypto.createPrivateKey" if kind in {"jwk", "rsa"} else
                                       "Node.js Buffer.from" if kind == "array" else "Python standard decoder / cryptography",
                           "standard_reader_recovery": True})
            observations.append(record)
        normal.append(inspect("mixed-public-keys", {"jwk": public_jwk, "spki": [spki.hex(), base64.b64encode(spki).decode()]},
                              known_key=True, blocked=False))
        unrelated = hashlib.sha256(b"owned nonsecret byte payload").digest()
        normal.append(inspect("unrelated-bytes", {"base64": base64.b64encode(unrelated).decode(),
                                                   "hex": unrelated.hex(), "array": list(unrelated)},
                              known_key=True, blocked=False))
        def prove_over_budget(path: Path) -> None:
            reader = """const fs=require('node:fs');const value=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));
console.log(JSON.stringify(Buffer.from(value.encoded,'base64').toString('base64')));"""
            recovered = base64.b64decode(node_json(args.node, reader, path))
            require(AESGCM(recovered).decrypt(NONCE, CIPHERTEXT, MESSAGE) == PAYLOAD,
                    "Over-budget representation did not recover the original asset")
        over_budget = inspect("asset-ignored-bytes-over-budget",
                              {"encoded": ("!" * 900).join(base64.b64encode(KEY).decode())},
                              known_key=True, blocked=True, proof=prove_over_budget, inspection_complete=False)
        over_budget.update({"disposition": "inspection-budget-rejection", "counted_as_positive_block": False,
                            "recovery_proof": "exact-aes-gcm-plaintext", "consumer": "Node.js Buffer.from",
                            "standard_reader_recovery": True})
        budget_controls.append(over_budget)
    require(verify_baseline(args.baseline_python, args.baseline_wheel) == baseline_identity,
            "Installed baseline changed during the recovery experiment")
    report = {"schema": "releaseguard/secret-representation-recovery/v1", "ok": True,
              "recorded_at": datetime.now(timezone.utc).isoformat(),
              "baseline": {**baseline_identity, "wheel_sha256": BASELINE_SHA256,
                           "release": "https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.1.0"},
              "current_version": after_version,
              "environment": {"python": platform.python_version(), "platform": platform.platform(),
                              "cryptography": cryptography.__version__, "node": node_version},
              "recoverable_cases": observations, "nonsecret_controls": normal, "over_budget_controls": budget_controls,
              "summary": {"standard_reader_recoveries": len(observations), "baseline_missed": len(observations),
                          "current_positive_blocks": len(observations), "nonsecret_controls_allowed": len(normal),
                          "over_budget_controls_rejected": len(budget_controls)},
              "limitations": ["Nineteen owned representations, not nineteen distinct vulnerability classes or a general secret-detector recall estimate.",
                              "Node's tolerant Base64/UTF-16 importer behavior is consumer compatibility, not canonical JWK syntax.",
                              "The RSA key is generated fresh for each run; every tested input has its own recorded SHA-256.",
                              "The separate over-budget control is genuinely recoverable but rejected as uninspected; it is excluded from the nineteen positive detections.",
                              "Consumer decoding and signing/decryption are actual operations; no REA or AI session is run here.",
                              "The gate refuses publication; already disclosed keys remain recoverable.",
                              "Fixture keys are public test material and must never be used in a product."]}
    text = json.dumps(report, indent=2) + "\n"
    with args.out.open("x", encoding="utf-8") as output:
        output.write(text)
    print(text, end="")


if __name__ == "__main__":
    main()
