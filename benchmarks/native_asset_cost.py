"""Measure in-process C++/OpenSSL opening of a synthetic 1 MiB sealed asset."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import secrets
import shutil
import statistics
import subprocess
import tempfile

from releaseguard import __version__
from releaseguard.core import write_new
from releaseguard.native_asset import export_native_asset
from releaseguard.sealed import seal_asset


PAYLOAD_BYTES = 1024 * 1024
WARMUPS = 5
ITERATIONS = 25
FLAGS = ["-std=c++17", "-O2", "-DNDEBUG", "-Wall", "-Wextra", "-Werror"]
DRIVER = r"""
#include "releaseguard_asset.hpp"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <openssl/opensslv.h>

int main() {
    releaseguard::native_asset_key key{};
    std::vector<unsigned char> expected(1024 * 1024);
    std::cin.read(reinterpret_cast<char*>(key.data()), key.size());
    if (std::cin.gcount() != 32) return 2;
    std::cin.read(reinterpret_cast<char*>(expected.data()), expected.size());
    if (std::cin.gcount() != static_cast<std::streamsize>(expected.size()) ||
        std::cin.peek() != std::char_traits<char>::eof() || std::cin.bad()) return 2;

    std::vector<unsigned char> output;
    std::array<double, 25> measured{};
    for (int index = 0; index < 30; ++index) {
        const auto start = std::chrono::steady_clock::now();
        const bool accepted = releaseguard::open_native_asset(key, releaseguard::embedded_asset, output);
        const auto end = std::chrono::steady_clock::now();
        // The reference comparison takes place after the timed operation.
        if (!accepted || output != expected) return 3;
        if (index >= 5) measured[index - 5] =
            std::chrono::duration<double, std::micro>(end - start).count();
    }
    OPENSSL_cleanse(key.data(), key.size());
    OPENSSL_cleanse(expected.data(), expected.size());
    OPENSSL_cleanse(output.data(), output.size());
    std::cout << OpenSSL_version(OPENSSL_VERSION) << "\n" << std::setprecision(12);
    for (double elapsed : measured) std::cout << elapsed << "\n";
    return std::cout ? 0 : 2;
}
"""


def observe():
    if os.name != "posix":
        raise RuntimeError("This cost fixture requires a POSIX C++17 toolchain and OpenSSL development files")
    compiler = shutil.which("c++")
    if not compiler:
        raise RuntimeError("A c++ compiler is required")
    env = dict(os.environ)
    for name in ("LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES"):
        env.pop(name, None)
    key, plaintext = secrets.token_bytes(32), secrets.token_bytes(PAYLOAD_BYTES)
    context = dict(product="cost-fixture", release="1", purpose="data", asset_id="one-mib")
    document = seal_asset(plaintext, key, **context)
    compiler_version = subprocess.check_output([compiler, "--version"], env=env, text=True,
                                               timeout=15).splitlines()[0]
    with tempfile.TemporaryDirectory(prefix="native-asset-cost-") as temporary:
        work = Path(temporary).resolve()
        include = work / "include"
        export_native_asset(document, include, **context)
        source, app = work / "cost.cpp", work / "cost"
        write_new(source, DRIVER.encode("ascii"))
        compiled = subprocess.run([compiler, *FLAGS, "-I", str(include), str(source),
                                   "-lcrypto", "-o", str(app)], env=env,
                                  capture_output=True, timeout=180)
        if compiled.returncode:
            raise RuntimeError("Could not compile the native asset cost fixture")
        result = subprocess.run([str(app)], input=key + plaintext, env=env,
                                capture_output=True, timeout=60)
        if result.returncode or result.stderr:
            raise RuntimeError("Native asset cost fixture failed its input or exact-output checks")
        rows = result.stdout.decode("ascii").splitlines()
        if len(rows) != ITERATIONS + 1 or not rows[0].startswith("OpenSSL "):
            raise RuntimeError("Incomplete native asset timing report")
        samples = [float(value) for value in rows[1:]]
        if any(not math.isfinite(value) or value <= 0 for value in samples):
            raise RuntimeError("Invalid measured duration")
        binary_size = app.stat().st_size
        helper_sha = hashlib.sha256((include / "releaseguard/sealed_asset.hpp").read_bytes()).hexdigest()
    return {
        "schema": "releaseguard/native-asset-cost/v1",
        "ok": True,
        "core_version": __version__,
        "payload_bytes": PAYLOAD_BYTES,
        "warmup_iterations": WARMUPS,
        "measured_iterations": ITERATIONS,
        "exact_plaintext_verified_each_iteration": True,
        "asset_open_microseconds": {
            "median": statistics.median(samples), "minimum": min(samples),
            "maximum": max(samples), "samples": samples,
        },
        "fixture_executable_bytes": binary_size,
        "native_helper_sha256": helper_sha,
        "compiler": compiler_version,
        "compiler_flags": FLAGS,
        "link_libraries": ["crypto"],
        "openssl": rows[0],
        "host": {"system": platform.system(), "release": platform.release(),
                 "machine": platform.machine(), "logical_cpus": os.cpu_count()},
        "scope": (
            "Synthetic within-process asset-open cost. Includes HKDF, AES-GCM, allocations "
            "and cleansing the previous output. Excludes process startup, external-key retrieval, "
            "stdin, compilation and exact-output comparison. The performance fixture receives "
            "the key and plaintext reference. This run is separate from adversarial analysis."
        ),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path, help="New synthetic timing report")
    args = parser.parse_args()
    report = observe()
    write_new(args.out, json.dumps(report, indent=2).encode("ascii") + b"\n")
    print(f"1 MiB native asset-open median {report['asset_open_microseconds']['median']:.3f} us "
          f"over {ITERATIONS} measured opens after {WARMUPS} warmups.")
