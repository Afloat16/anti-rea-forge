"""Create disposable, project-owned integration data; no private key is written."""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releaseguard.core import create_manifest, issue_license, save_document
from releaseguard.analysis import issue_analysis_grant


base = Path(sys.argv[1])
private = Ed25519PrivateKey.generate()
(base / "public.pem").write_bytes(private.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
))
manifest = create_manifest(base / "dist", "--Demo 产品", "2.0", private)
save_document(base / "manifest.json", manifest)
save_document(base / "license.json", issue_license("--Demo 产品", "-customer", 1, ["export"], private))
context = dict(product="--Demo 产品", release="2.0", subject="-customer", audience="analysis-service",
               operations=["inspect"])
save_document(base / "analysis-grant.json", issue_analysis_grant(private, manifest, **context))
save_document(base / "expired-grant.json", issue_analysis_grant(
    private, manifest, **context, now=datetime.now(timezone.utc) - timedelta(hours=2),
))
