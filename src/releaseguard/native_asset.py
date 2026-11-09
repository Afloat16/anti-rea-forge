"""Export a sealed data envelope as keyless C++17/OpenSSL build inputs."""

from __future__ import annotations

from contextlib import ExitStack
from importlib import resources
from pathlib import Path

from .core import GuardError, write_new
from .native_token import _new_path
from .sealed import _context, _envelope, _HKDF_INFO_PREFIX, SEALED_FORMAT


MAX_NATIVE_AAD_BYTES = 1024 - len(_HKDF_INFO_PREFIX)
_HELPER = "sealed_asset.hpp"


def _array(name: str, data: bytes) -> str:
    rows = [", ".join(f"0x{value:02x}" for value in data[i:i + 12])
            for i in range(0, len(data), 12)]
    return (f"inline constexpr std::array<unsigned char, {len(data)}> {name} = {{\n    "
            + ",\n    ".join(rows) + "\n};\n")


def export_native_asset(document: dict, public_dir: Path | str, product: str,
                        release: str, purpose: str, asset_id: str) -> dict:
    """Export validated ciphertext plus trusted caller-supplied context, without a key.

    The native opener authenticates the package. Export validates its structure
    only. Inputs and output parents must be trusted and stable during the build.
    """
    aad = _context(product, release, purpose, asset_id)
    if len(aad) > MAX_NATIVE_AAD_BYTES:
        raise GuardError("Native asset context exceeds the OpenSSL 1024-byte HKDF info profile")
    salt, nonce, ciphertext = _envelope(document)
    public = _new_path(public_dir)
    helper = (resources.files("releaseguard") / "data" / "include" / "releaseguard" / _HELPER).read_bytes()
    header = """// Generated sealed data. Supply the master key from outside the release.
#pragma once
#include "releaseguard/sealed_asset.hpp"

namespace releaseguard {
"""
    for name, data in (("embedded_asset_salt", salt), ("embedded_asset_nonce", nonce),
                       ("embedded_asset_ciphertext", ciphertext), ("embedded_asset_aad", aad)):
        header += _array(name, data)
    header += """
inline constexpr native_asset_view embedded_asset = {
    embedded_asset_salt, embedded_asset_nonce,
    embedded_asset_ciphertext.data(), embedded_asset_ciphertext.size(),
    embedded_asset_aad.data(), embedded_asset_aad.size()
};

inline bool open_embedded_asset(const native_asset_key& key, std::vector<unsigned char>& output) {
    return open_native_asset(key, embedded_asset, output);
}
}  // namespace releaseguard
"""
    with ExitStack() as rollback:
        public.mkdir(mode=0o755)
        rollback.callback(public.rmdir)
        includes = public / "releaseguard"
        includes.mkdir(mode=0o755)
        rollback.callback(includes.rmdir)
        for path, data in ((includes / _HELPER, helper),
                           (public / "releaseguard_asset.hpp", header.encode("ascii"))):
            write_new(path, data)
            rollback.callback(path.unlink)
        rollback.pop_all()
    return {"ok": True, "public_dir": str(public),
            "public_header": str(public / "releaseguard_asset.hpp"),
            "format": SEALED_FORMAT, "ciphertext_bytes": len(ciphertext),
            "authentication": "performed by the native opener with an external key"}
