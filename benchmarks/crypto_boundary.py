#!/usr/bin/env python3
"""Functional crypto controls on fresh, project-owned in-memory data.

No REA/provider/model is run. No arbitrary binaries are accepted. This checks
specific cryptographic boundaries, not decompilation or cracking resistance.
"""

import argparse
import json
import platform
import secrets
import time
from pathlib import Path

import cryptography
from releaseguard import __version__
from releaseguard.core import GuardError, canonical, write_new
from releaseguard.passwords import create_password_verifier, verify_password
from releaseguard.sealed import seal_asset, open_asset


def measure():
    started = time.perf_counter()
    password = secrets.token_hex(16).encode("ascii")
    mask = secrets.randbelow(255) + 1
    reversible = bytes(byte ^ mask for byte in password)
    restored = bytes(byte ^ mask for byte in reversible)
    hash_started = time.perf_counter()
    verifier = create_password_verifier(password)
    hash_ms = (time.perf_counter() - hash_started) * 1000
    one_way = {
        "correct_password_accepted": verify_password(password, verifier),
        "wrong_password_rejected": not verify_password(b"wrong-candidate", verifier),
        "plaintext_not_in_serialized_record": password not in canonical(verifier),
        "create_elapsed_ms": round(hash_ms, 3),
    }
    # Negative control: memory-hard hashing cannot rescue a tiny password set.
    dictionary = [b"synthetic-weak-choice-A", b"synthetic-weak-choice-B", b"synthetic-weak-choice-C"]
    weak = secrets.choice(dictionary)
    weak_record = create_password_verifier(weak)
    recovered = next((candidate for candidate in dictionary if verify_password(candidate, weak_record)), None)
    key = secrets.token_bytes(32)
    data = secrets.token_bytes(4096)
    context = ("synthetic-app", "1", "model", "model-main")
    envelope = seal_asset(data, key, *context)
    restored_asset = open_asset(envelope, key, *context)

    def rejected(doc, candidate_key, expected):
        try:
            open_asset(doc, candidate_key, *expected)
        except GuardError:
            return True
        return False

    ciphertext = envelope["ciphertext"]
    tampered = {**envelope, "ciphertext": ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]}
    checks = {
        "roundtrip_matches": restored_asset == data,
        "wrong_key_rejected": rejected(envelope, secrets.token_bytes(32), context),
        "tamper_rejected": rejected(tampered, key, context),
    }
    for index, name in enumerate(("product", "release", "purpose", "asset_id")):
        changed = list(context)
        changed[index] = "different"
        checks[f"wrong_{name}_rejected"] = rejected(envelope, key, changed)
    expected_pass = (restored == password and all(v for k, v in one_way.items() if k != "create_elapsed_ms")
                     and recovered == weak and all(checks.values()))
    return {
        "ok": expected_pass,
        "scope": "functional_crypto_boundary_controls_only",
        "releaseguard": __version__, "python": platform.python_version(),
        "cryptography": cryptography.__version__, "platform": platform.platform(),
        "rea_evaluated": False, "decompilation_resistance": "not_evaluated",
        "reversible_reference_control": {"reference_recovered": restored == password,
                                         "protection_goal": "failed_by_design"},
        "argon2id": one_way,
        "weak_password_negative_control": {"dictionary_size": len(dictionary),
                                             "password_recovered": recovered == weak},
        "sealed_asset": checks,
        "runtime_boundary": {"authorized_plaintext_available_in_memory": restored_asset == data,
                             "memory_dump_resistance": "not_provided"},
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        "notes": ["Only fresh synthetic values are used; passwords, keys and plaintext are not exported.",
                  "A missing plaintext substring is not evidence of cryptographic strength.",
                  "Correct AEAD requires external key custody; a client holding its key can read or forge assets.",
                  "Timing is one local observation, not a cracking-resistance score or confidence estimate."],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    report = measure()
    output = json.dumps(report, indent=2).encode("utf-8") + b"\n"
    if args.out:
        write_new(args.out, output)
    print(output.decode("utf-8"), end="")
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
