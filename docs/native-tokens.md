# Native unlock tokens: ship a verifier, deliver the credential separately

Use this opt-in C++17 component when an application needs to accept an **issuer-generated random token** offline. A client that decodes the expected token and compares two strings makes the reusable answer available at the comparison. Here the compiler never needs that answer. The issuer gives the build a public verifier and gives the authorized holder the token through a separate private channel.

## Generate, build and try the example

Install this checkout with Python 3.10+. The following commands run from the repository root on Linux. The example requires a C++17 compiler and OpenSSL development headers and libcrypto (for example, `libssl-dev` on Ubuntu). Ghidra and Java are needed only to reproduce the research, not to build or use the verifier.

```sh
python -m pip install .
mkdir -m 700 ../myapp-issuer
python -m releaseguard native-token-issue --public-dir generated --secret-out ../myapp-issuer/demo.rg-token
c++ -std=c++17 -O2 -Igenerated examples/native-token/check.cpp -lcrypto -o check-token
./check-token < ../myapp-issuer/demo.rg-token
```

The final command prints `ACCEPTED`. Supply a different input and it prints `DENIED`. The [example](../examples/native-token/check.cpp) reads a bounded line on stdin; it never needs the token as a command-line argument.

| Output | Who gets it | Contents |
| --- | --- | --- |
| `generated/releaseguard_token.hpp` and `generated/releaseguard/token_verify.hpp` | Trusted build | A 32-byte public digest and the verifier; the headers are not needed at runtime after compilation |
| `../myapp-issuer/demo.rg-token` | Issuer and authorized holder only | One reusable bearer token followed by a line ending |

Both destinations must be **new**, with separate, existing, trusted parent directories. The CLI refuses to replace existing outputs. The secret file is created with POSIX permissions at most 0600; configure directory ACLs on Windows. Do not package the issuer directory, put the token in a filename, pass it in argv or log input. Treat a successful issuance as a pair: the verifier and token from different runs intentionally do not match.

In an existing program, include `releaseguard_token.hpp`, link OpenSSL's crypto library, and call:

```cpp
bool allowed = releaseguard::verify_issued_token(candidate); // candidate: std::string_view
```

For CMake, add the generated directory to the target's private include paths and link `OpenSSL::Crypto` after `find_package(OpenSSL REQUIRED COMPONENTS Crypto)`. If libcrypto is dynamically linked, ensure the correct library is installed or packaged for your deployment. Do not compile the token string into a wrapper, logging path, diagnostic function or fallback.

## What is public

The issuer samples 32 random bytes using Python's `secrets` module. The textual bearer is `rg1_` followed by 64 lowercase hex characters. Its verifier is SHA-256 over the ASCII string `OpenReleaseGuard/native-token/v1`, one NUL byte, and the **entire 68-byte ASCII bearer** (without the file's newline). The algorithm, format, code and digest are public. Passing the digest itself as a candidate hashes a different input.

The C++ verifier accepts only that exact format, checks OpenSSL return codes, and uses `CRYPTO_memcmp` for the fixed-size digest comparison. Only a developer-selected unlock check incurs hashing/comparison work. No background task, injection, debugger detection or runtime hook is added. There is no claim that adopting the verifier has zero cost or that an authorized user's input is invisible in memory.

The issuer does not accept a user-selected password. A fast hash would allow offline guessing of human passwords or short serials. For this reason, do not adapt the example by hashing an old weak secret. This is one bearer per generated verifier, not a per-user licensing or revocation service. Replacing the token requires distributing a new trusted verifier; old binaries still accept their old tokens. A user controlling the machine can copy a legitimately supplied token, change the public digest or patch a local acceptance branch. Protect valuable server operations at the trusted service.

## Catch a packaging mistake

Run the existing `check` / `scan-release` on the final staging directory. Portable policies now default `check_native_tokens` to true: full token-shaped values in inspected files and supported ZIP members produce `native_token_exposure`. It detects the format in UTF-8 and UTF-16/32 LE/BE, including across read boundaries. It does not distinguish a real token from a syntactically valid decoy. Reports can contain paths, member names and hashes, but findings do not include matched content. Split/encoded secrets, deployed services or unsupported containers are not covered by this format rule.

## Reproduce the controls

- [Ghidra benchmark](../benchmarks/ghidra_token/probe.py): supply the pinned official Ghidra 12.2 ZIP, JDK 25, g++, libcrypto and an installed Python environment. Run `python benchmarks/ghidra_token/probe.py --archive /path/to/ghidra_12.2_PUBLIC_20261016.zip --python /path/to/python --out ghidra-token.json` on Linux x86-64. The release archive is checked against the official SHA-256 before extraction. The benchmark builds its own fixtures; no third-party binary is accepted.
- [Wrong-input comparison benchmark](../benchmarks/native_token_compare.py): on Linux, run `python benchmarks/native_token_compare.py --out token-compare.json`. It observes the actual operands of `strcmp` in a reversible-mask control and `CRYPTO_memcmp` in a verifier build. Both real comparisons still reject the wrong input. Extracted candidate values are tried again without the observer on unchanged binaries. It never observes a correct-token entry; no broad process-memory protection is tested.
- [Threat model and success criteria](ghidra-native-threat-model.md): explains why finding a public digest or decompiling an admission branch differs from recovering a reusable token.

Use fresh output paths. Only aggregate observations, binary IDs and evidence hashes belong in shared reports. Never upload fixtures that deliberately embed a bearer, the issuer token file, raw comparison operands or unsanitized private analyzer output.
