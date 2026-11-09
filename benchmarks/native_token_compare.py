"""Observe comparison operands on a wrong guess in two project-owned Linux ELFs.

Both programs accept the same newly issued random token. One uses the existing
RG_TEXT/strcmp fixture pattern; one uses the generated verification header.
Only private synthetic fixtures are compiled/executed. There is no external
target parameter. No bearer value, raw operand or diagnostic containing it is
written to the report. This comparison-boundary check is separate from Ghidra.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import tempfile

from releaseguard.core import write_new
from releaseguard.native import init_native
from releaseguard.native_token import issue_native_token
from runtime_boundary import PROBE_FLAGS, PROBE_SOURCE, SAMPLE_FLAGS


DRIVER = r'''
#include <cstdio>
#include <cstring>
#include <string_view>
@CHECK@
int main() {
    char input[70]{};
    if (!std::fgets(input, sizeof(input), stdin)) return 2;
    const auto n = std::strlen(input);
    if (!n || input[n-1] != '\n') return 2;
    input[n-1] = '\0';
    const bool ok = accept(input);
    std::puts(ok ? "ACCEPTED" : "DENIED");
    return ok ? 0 : 1;
}
'''
MASKED = r'''
#include "releaseguard_build.hpp"
#include "releaseguard/literal.hpp"
static bool accept(const char* input) {
    auto reference = RG_TEXT("@TOKEN@");
    return std::strcmp(input, reference.c_str()) == 0;
}
'''
VERIFIER = r'''
#include "releaseguard_token.hpp"
static bool accept(const char* input) {
    return releaseguard::verify_issued_token(std::string_view(input));
}
'''
# Add one binary-comparison observer to the existing scoped strcmp probe. Call
# the real libcrypto implementation first and preserve its result. Record only
# 32-byte calls originating in this run's own executable; never load in a user app.
DIGEST_PROBE = r'''
extern "C" int CRYPTO_memcmp(const void* left, const void* right, std::size_t count) {
    using fn = int (*)(const void*, const void*, std::size_t);
    auto next = reinterpret_cast<fn>(dlsym(RTLD_NEXT, "CRYPTO_memcmp"));
    if (!next) _exit(125);
    const int result = next(left, right, count);
    Dl_info caller{};
    if (count == 32 && dladdr(__builtin_return_address(0), &caller) &&
        same(caller.dli_fname, @SAMPLE_PATH@)) {
        const unsigned char* inputs[] = {
            static_cast<const unsigned char*>(left), static_cast<const unsigned char*>(right)
        };
        for (auto bytes : inputs) {
            char row[] = "RG_DIGEST_ARG_V1:0000000000000000000000000000000000000000000000000000000000000000\n";
            auto pos = sizeof("RG_DIGEST_ARG_V1:") - 1;
            const char hex[] = "0123456789abcdef";
            for (std::size_t i = 0; i < count; i++) {
                row[pos++] = hex[bytes[i] >> 4];
                row[pos++] = hex[bytes[i] & 15];
            }
            if (::write(STDERR_FILENO, row, sizeof(row)-1) != sizeof(row)-1) _exit(125);
        }
    }
    return result;
}
'''
TOKEN = re.compile(rb"rg1_[0-9a-f]{64}\Z")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def file_id(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make(compiler, flags, env):
    # Compiler diagnostics may quote the synthetic control's generated source.
    p = subprocess.run([compiler, *map(str, flags)], capture_output=True, timeout=90, env=env)
    require(p.returncode == 0, "could not compile a comparison fixture")


def call(program, candidate, env, probe=None):
    child = dict(env)
    if probe:
        child["LD_PRELOAD"] = str(probe)
    p = subprocess.run([str(program)], input=candidate + b"\n", env=child,
                       capture_output=True, timeout=15)
    require((p.returncode, p.stdout) in ((0, b"ACCEPTED\n"), (1, b"DENIED\n")),
            "fixture did not give a valid decision")
    return p.returncode == 0, p.stderr


def compare():
    require(platform.system() == "Linux", "Linux dynamic loading is required")
    compiler = shutil.which("g++")
    require(compiler, "g++ is required")
    env = dict(os.environ)
    for name in ("LD_AUDIT", "LD_PRELOAD"):
        env.pop(name, None)
    with tempfile.TemporaryDirectory(prefix="releaseguard-comparison-") as temporary:
        root = Path(temporary).resolve()
        private = root / "private"
        private.mkdir(mode=0o700)
        headers, token_file = root / "generated", private / "fixture.rg-token"
        issue_native_token(headers, token_file)
        token = token_file.read_bytes().rstrip(b"\n")
        wrong = b"rg1_" + secrets.token_hex(32).encode("ascii")
        require(TOKEN.fullmatch(token) and token != wrong, "invalid generated fixture")
        masks = root / "masks"
        init_native(masks)
        observations = {}
        for name, check in (("masked_reference", MASKED.replace("@TOKEN@", token.decode())),
                            ("public_verifier", VERIFIER)):
            exe = root / name
            source = root / (name + ".cpp")
            write_new(source, DRIVER.replace("@CHECK@", check).encode("ascii"), secret=True)
            make(compiler, [*SAMPLE_FLAGS, "-I", headers, "-I", masks,
                            "-I", masks / "include", source, "-o", exe, "-lcrypto"], env)
            before = file_id(exe)
            require(token not in exe.read_bytes(), "plain initialized token unexpectedly present")
            probe_source, probe = root / (name + "-probe.cpp"), root / (name + "-probe.so")
            quoted_path = '"' + "".join(f"\\{b:03o}" for b in os.fsencode(exe)) + '"'
            write_new(probe_source, (PROBE_SOURCE + DIGEST_PROBE).replace("@SAMPLE_PATH@", quoted_path).encode())
            make(compiler, [*PROBE_FLAGS, probe_source, "-ldl", "-o", probe], env)
            require(call(exe, token, env)[0] and not call(exe, wrong, env)[0],
                    "uninstrumented positive or negative control failed")
            accepted, raw = call(exe, wrong, env, probe)
            require(not accepted, "observer changed rejection semantics")
            strings = [bytes.fromhex(v.decode()) for v in re.findall(rb"^RG_BOUNDARY_ARG_V1:([0-9a-f]+)$", raw, re.M)]
            digests = [bytes.fromhex(v.decode()) for v in re.findall(rb"^RG_DIGEST_ARG_V1:([0-9a-f]{64})$", raw, re.M)]
            candidates = {v for v in strings if TOKEN.fullmatch(v)}
            candidates.update(b"rg1_" + d.hex().encode() for d in digests)
            if name == "masked_reference":
                require(set(strings) == {token, wrong} and not digests, "missing masked comparison operands")
            else:
                expected = {hashlib.sha256(b"OpenReleaseGuard/native-token/v1\0" + x).digest()
                            for x in (wrong, token)}
                require(len(digests) == 2 and set(digests) == expected, "missing or wrong digest operands")
                require(token not in strings, "reference token appeared at the comparison boundary")
            usable = {v for v in candidates if call(exe, v, env)[0]}
            require(usable == ({token} if name == "masked_reference" else set()), "unexpected replay result")
            require(file_id(exe) == before, "fixture executable changed during observation")
            observations[name] = {
                "elf_sha256": before, "correct_input_accepted": True, "wrong_input_rejected": True,
                "in_process_wrong_attempt_only": True, "plaintext_token_operands": sum(v == token for v in strings),
                "digest_operands": len(digests), "candidates_replayed_without_probe": len(candidates),
                "accepted_recovered_tokens": len(usable), "executable_unchanged": True,
            }
        return {"schema": "releaseguard/native-token-comparison/v1", "ok": True,
                "observations": observations,
                "scope": "Own Linux ELF, wrong input only: strcmp on an RG_TEXT reference vs CRYPTO_memcmp on SHA-256 digests. Not a heap scan, process isolation or patch-resistance test."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path, help="New synthetic JSON report")
    args = parser.parse_args()
    report = compare()
    write_new(args.out, json.dumps(report, indent=2).encode("ascii") + b"\n")
    print("Wrong-guess comparison: accepted recovered tokens 1/0 on unchanged ELFs.")
