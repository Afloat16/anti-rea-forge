"""Create disposable, project-owned integration data; no private key is written."""

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard.core import create_manifest, issue_license, save_document


base = Path(sys.argv[1])
private = Ed25519PrivateKey.generate()
(base / "public.pem").write_bytes(private.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
))
save_document(base / "manifest.json", create_manifest(base / "dist", "--Demo 产品", "2.0", private))
save_document(base / "license.json", issue_license("--Demo 产品", "-customer", 1, ["export"], private))
