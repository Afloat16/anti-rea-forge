"""Example host integration. Trusted key/product/release must come from the host.

This example is Python only. A user who controls the host can replace this code.
Keep logs/user data and license files outside the immutable release directory.
"""

import argparse
import sys

from releaseguard.core import load_public_key, read_document, verify_license, verify_manifest


def main():
    arguments = argparse.ArgumentParser()
    arguments.add_argument("--public", required=True, help="Previously trusted public key")
    arguments.add_argument("--root", required=True)
    arguments.add_argument("--manifest", required=True)
    arguments.add_argument("--license", required=True)
    arguments.add_argument("--product", required=True)
    arguments.add_argument("--release", required=True)
    args = arguments.parse_args()
    try:
        key = load_public_key(args.public)
        verify_manifest(read_document(args.manifest), args.root, key, args.product, args.release)
        claims = verify_license(read_document(args.license), key, args.product,
                                required_features=["export"])
    except (ValueError, OSError) as exc:
        print(f"Startup denied: {exc}", file=sys.stderr)
        return 2
    # The real application must place its feature entry points after verification.
    print(f"License accepted for {claims['subject']}; export feature may start.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
