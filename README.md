# Anti-REA Forge v0.8.0

[English](README.md) · [简体中文](README.zh-CN.md) · [MIT license](LICENSE)

**Ship the native unlock check without shipping the token that passes it.**

A binary that carries the correct answer can give that answer to an analyst. Anti-REA Forge issues a token with **256 random bits**, delivers it separately to its holder, and generates C++ headers containing only a public SHA-256 verifier. At unlock time the application hashes the supplied token and compares two fixed-size digests.

## What could Ghidra actually recover?

We ran official **Ghidra 12.2** on three project-owned Linux x86-64 ELFs. The same script decompiled the actual admission gate, extracted token-shaped candidates from the loaded image and selected functions' pseudocode, then a test driver replayed every candidate against the **unchanged** program.

| Program supplied to Ghidra | Distinct candidates extracted | Candidates that unlocked it |
| --- | ---: | ---: |
| Ordinary program with an embedded plaintext reference | 2 | **1** |
| Program containing only the public verifier | 1 | **0** |
| Same verifier, with the original token deliberately leaked in diagnostic data | 2 | **1** |

Decompilation succeeded on every run. All three programs accepted the legitimate token. In the middle case Ghidra found the invalid decoy and read the **actual referenced 32-byte digest**. Submitting that digest as a correctly shaped token still failed. Putting the plaintext back made recovery possible again. [Local evidence](benchmarks/ghidra_token/observation-2026-11-09.json) · [Independent CI observation](docs/results/ghidra-token-ci-2026-11-09.json) · [Reproduce the experiment](benchmarks/ghidra_token/README.md)

A separate wrong-input experiment observed the comparison calls. A reversibly masked reference passed to `strcmp` disclosed one reusable value; the verifier compared two digests, neither of which unlocked the unchanged program when replayed as a token. [Comparison observation](docs/results/native-token-comparison-2026-11-09.json)

**Scope: extracting and replaying the credential.** This is not a block on decompilation, local branch patching, or observing a legitimate user's input. The fast verifier is for issuer-generated random tokens, never human passwords or short serial numbers.

## Try it in a native application

This Linux example needs Python 3.10+, a C++17 compiler and the OpenSSL development library. Ghidra is needed only to reproduce the analysis.

```sh
git clone https://github.com/Afloat16/anti-rea-forge.git
cd anti-rea-forge
python -m pip install .
mkdir -m 700 ../myapp-issuer
python -m releaseguard native-token-issue --public-dir generated --secret-out ../myapp-issuer/demo.rg-token
c++ -std=c++17 -O2 -Igenerated examples/native-token/check.cpp -lcrypto -o check-token
./check-token < ../myapp-issuer/demo.rg-token
```

- **For the build:** use the headers in `generated/` and call `releaseguard::verify_issued_token(candidate)` at the unlock point. Only that explicit check hashes and compares the input. No background scanner or anti-debugger runs in your app.
- **For the authorized holder:** deliver the `.rg-token` file privately; never bundle it with the program. Release scanning flags complete token-shaped values in files and supported ZIP members by default. [Integration, rotation and boundaries](docs/native-tokens.md)

## Shipping JavaScript too?

`split-source-maps` keeps public JS byte-identical and separates external maps for private debugging. On the same minified fixture, Craft Anything restored **1 exact original** with the map, **0** from the public directory and **1** when the private map was supplied again. REA's map-backed original-source node count went from **1 to 0**. [Build command and evidence](docs/private-source-maps.md)

If this solves a release problem for your team, **star Anti-REA Forge**. Have a different extraction path to test? [Contribute a reproducible, project-owned fixture](CONTRIBUTING.en.md).
