"""Controlled client patch and receipt experiment for the generated ELF32 fixture."""

import base64
import hashlib
import json
from pathlib import Path
import secrets
import struct
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from releaseguard.capabilities import ReplayStore, issue_capability, run_authorized_operation
from releaseguard.core import GuardError


CONTEXT = dict(subject="fixture-customer", audience="fixture-service",
               product="fixture", operation="issue-receipt")
RECEIPT_DOMAIN = b"elf-symbols/fixture-receipt/v1\0"
PATCH = bytes.fromhex("b8 2a 00 00 00 c3")  # x86 mov eax,42; ret


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def serve(mode, pinned_key):
    """Separate process. The operator selects the policy before receiving requests."""
    issuer = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pinned_key))
    messages = json.load(sys.stdin)
    service = Ed25519PrivateKey.generate()
    store = ReplayStore.create(Path.cwd() / "replay.sqlite") if mode == "verified" else None
    calls = 0

    def issue_receipt(request):
        nonlocal calls
        calls += 1
        return base64.b64encode(service.sign(RECEIPT_DOMAIN + request)).decode("ascii")

    responses = []
    for message in messages:
        request = bytes.fromhex(message["request"])
        receipt = None
        if mode == "trust-client":
            if message["client_status"] == 42:
                receipt = issue_receipt(request)
        else:
            try:
                receipt = run_authorized_operation(message["grant"], issuer, store,
                                                   **CONTEXT, request=request, handler=issue_receipt)
            except GuardError:
                pass  # A refused request returns no receipt.
        responses.append(receipt)
    print(json.dumps({"service_public": service.public_key().public_bytes_raw().hex(),
                      "responses": responses, "handler_calls": calls}))


def probe_patch(public_elf: Path, observation: dict, work: Path, runner_prefix=()):
    """The analyzer supplies an address. Use only the harness's project-owned fixture."""
    binary = public_elf.read_bytes()
    original_hash = hashlib.sha256(binary).hexdigest()
    require(observation["public_name"] == "rg_public_entry"
            and observation["input_sha256"].lower() == original_hash, "Analyzer input/gate mismatch")
    require(binary[:7] == b"\x7fELF\x01\x01\x01" and struct.unpack_from("<HH", binary, 16) == (2, 3),
            "Expected the little-endian ELF32 x86 non-PIE test fixture")
    address = int(observation["public_entry"], 16)
    phoff, = struct.unpack_from("<I", binary, 28)
    entry_size, entries = struct.unpack_from("<HH", binary, 42)
    require(entry_size == 32, "Unexpected ELF program header size")
    offsets = []
    for i in range(entries):
        kind, offset, start, _, size, _, flags, _ = struct.unpack_from("<8I", binary, phoff + i * entry_size)
        if kind == 1 and flags & 1 and start <= address and address + len(PATCH) <= start + size:
            offsets.append(offset + address - start)
    require(len(offsets) == 1 and offsets[0] + len(PATCH) <= len(binary), "No unique file-backed gate")
    work.mkdir(parents=True, exist_ok=True)
    offset = offsets[0]
    patched = work / "patched-app"
    with patched.open("xb") as stream:
        stream.write(binary[:offset] + PATCH + binary[offset + len(PATCH):])
    patched.chmod(0o700)
    def client_status(path):
        return subprocess.run([*runner_prefix, str(path.resolve())], cwd=work, timeout=10,
                              capture_output=True, check=False).returncode
    ordinary, modified = client_status(public_elf), client_status(patched)
    require((ordinary, modified) == (39, 42), "Client gate patch did not change the decision")

    issuer = Ed25519PrivateKey.generate()
    request = secrets.token_bytes(32)
    attacker = Ed25519PrivateKey.generate()
    wrong = issue_capability(attacker, **CONTEXT, request=request)
    good = issue_capability(issuer, **CONTEXT, request=request)
    def message(status, grant=None, body=request):
        return {"client_status": status, "grant": grant, "request": body.hex()}
    outcomes = {}
    for mode, messages, expected in [
        ("trust-client", [message(ordinary), message(modified)], [False, True]),
        ("verified", [message(modified), message(modified, wrong), message(modified, good, request + b"!"),
                      message(modified, good), message(modified, good)], [False, False, False, True, False]),
    ]:
        folder = work / mode
        folder.mkdir()
        # Configure the trusted key at service startup. Message fields come entirely from the client.
        for msg in messages:
            msg["issuer_public"] = attacker.public_key().public_bytes_raw().hex()
        completed = subprocess.run([sys.executable, str(Path(__file__).resolve()), mode,
                                    issuer.public_key().public_bytes_raw().hex()], cwd=folder,
                                   input=json.dumps(messages), text=True, capture_output=True, timeout=20)
        require(completed.returncode == 0, "Fixture authority process failed: " + completed.stderr[-1200:])
        result = json.loads(completed.stdout)
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(result["service_public"]))
        actual = []
        require(len(result["responses"]) == len(messages), "Incomplete authority transcript")
        for msg, receipt in zip(messages, result["responses"]):
            if receipt is not None:
                public_key.verify(base64.b64decode(receipt, validate=True),
                                  RECEIPT_DOMAIN + bytes.fromhex(msg["request"]))
            actual.append(receipt is not None)
        require(actual == expected and result["handler_calls"] == sum(expected), "Unexpected service receipts")
        outcomes[mode] = {"receipts_verified": actual, "handler_calls": result["handler_calls"]}
    require(public_elf.read_bytes() == binary, "Original public ELF changed")
    return {
        "gate_address": hex(address), "gate_file_offset": offset,
        "public_elf_sha256": original_hash, "patched_elf_sha256": hashlib.sha256(patched.read_bytes()).hexdigest(),
        "client_exit_before_after": [ordinary, modified], "patch_hex": PATCH.hex(),
        "trust_client_order": ["original", "patched"], "trust_client": outcomes["trust-client"],
        "verified_order": ["patched_without_grant", "self_signed", "changed_request", "authorized", "replay"],
        "verified": outcomes["verified"],
    }


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("trust-client", "verified"):
        raise SystemExit("Run this fixture through native_symbol_controls.py")
    serve(*sys.argv[1:])
