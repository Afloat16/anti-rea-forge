# 🛡️ Anti-REA Forge

[English](README.md) · [简体中文](README.zh-CN.md)

![Anti-REA Forge banner](assets/anti-rea-forge.svg)

> **AI-assisted reverse engineering is advancing. Let’s make software protection a reproducible engineering challenge.**

Anti-REA Forge is an open research and engineering project exploring native software protection against analysis with tools such as **REA and Ghidra**. It provides CMake integration, C++ components, PE/ELF release gates, and reproducible experiments that make protection claims easier to inspect and challenge.

**Contributions are welcome. Our current anti-cracking goals remain unmet:** independent static and runtime analysis recovered test secrets from protected synthetic samples, and the original programs accepted the recovered values. We publish these failures to guide improvement and make no promise of unbreakable software.

**MIT · 0.4.0 / Alpha · C/C++ build integration · Python tooling · PE / ELF**

[Contribute (Chinese)](CONTRIBUTING.md) · [Community invitation](https://github.com/Afloat16/anti-rea-forge/issues/1) · [Challenges and roadmap (Chinese)](docs/ROADMAP.zh-CN.md) · [Test report (Chinese)](docs/testing-2026-10-15.zh-CN.md) · [Security model (Chinese)](SECURITY.md)

The tooling retains the **Open Release Guard** Python distribution name `open-release-guard`, CLI/import name `releaseguard`, and existing CMake interfaces. The project targets Windows EXE/DLL protection research and also supports Linux ELF validation. It is independently developed and is not affiliated with or endorsed by REA.

**New here?** Start with the [community guide and reproducible tasks](docs/community/README.md), read the [technical project story](docs/community/PROJECT_STORY.md), or use the [English/Chinese introductions](docs/community/SHARE_COPY.md) where community rules permit. [Outreach status](docs/community/OUTREACH.md) distinguishes submitted suggestions from unsubmitted drafts.

## New in v0.4: reduce runtime exposure and enforce requests outside the client

- **Native sensitive buffers:** the C++17 `releaseguard::secure_buffer` owns guarded, non-executable pages, checks memory locking, clears its allocation before release, and reports actual protection status. Linux can exclude these pages from core dumps. Windows reports no dump exclusion in this version. None of these measures stop a hook from observing data while it is used.
- **Request-bound server capabilities:** separate-domain Ed25519 signatures bind the authenticated subject, audience, product, operation and exact request bytes, with a maximum lifetime of 300 seconds. A persistent SQLite replay store atomically permits one consumption and rejects trusted-clock rollback. Issuer keys, verification, replay state and the protected operation belong in the trusted service.
- **REA-specific threat mapping:** we inspect REA's pinned 6.7.0 source and its Frida script bridge, and distinguish memory snapshots, live hooks, local branch replacement and replay. The research notes cover formal 2024–2026 security papers and mature secure-memory projects, with explicit limits on what has been implemented.

Read the [runtime integration guide](docs/runtime-protection.md), [中文说明](docs/runtime-protection.zh-CN.md) and [v0.4 validation](docs/testing-v0.4-2026-10-20.md). These components require application integration; the Python cryptographic APIs still return managed `bytes`, and this release does not deploy a hosted authorization service, TLS, authentication or a TEE. Single-use authorization is not exactly-once business execution. A stolen valid bearer capability can still be used first for its original request.

## v0.3: remove recoverable secrets and check the whole release

The supplied REA case study motivates three implemented improvements:

- **One-way password verification:** `password-create` / `password-check` use salted Argon2id with a fixed 64 MiB, 3-pass, 4-lane profile. Untrusted verifier parameters are rejected before expensive work. The original password is not encrypted into the verifier; weak passwords can still be guessed and local checks can be patched.
- **External-key data assets:** `asset-keygen` / `asset-seal` / `asset-open` combine a random external 256-bit master key, per-package HKDF-SHA256 key derivation and AES-256-GCM. Authentication binds trusted product, release, purpose and asset identity. Wrong keys, tampering and context swaps fail before plaintext output is created. Keep the key outside the client release; an authorized process holding its key or plaintext remains observable.
- **Whole-release exposure checks:** `gate --root` can reject source/backup path components, known old artifact SHA-256 digests, missing or additional files against an exact allowlist, and declared literals in every release file, under a byte budget. The [strict native-release policy](examples/policy-strict-release.json) is an editable example, not a universal secret scanner.

These are Python APIs and CLI/build tools. They do not add a native C/C++ verifier/decryptor SDK, executable virtualization, a server or a key service. A fully offline client cannot keep a permanent key secret from someone who controls it. For logic that must remain confidential, keep execution and authorization in a trusted service and expose only the required operation.

See the [English integration and threat mapping](docs/crypto-protection.md), [中文说明](docs/crypto-protection.zh-CN.md), [v0.3 validation](docs/testing-2026-10-20.md), and [functional crypto observations](docs/results/crypto-boundary-2026-10-20.json). The observations include successful recovery of a weak-password control and explicitly record that authorized plaintext is available in memory. They are not a completed REA cracking evaluation or a protection success rate.

## Evidence so far

| Evaluation | Observed result |
| --- | --- |
| v0.4 local functional/native integration | **331 run: 330 passed, 1 skipped**, on 2026-10-20; the skip is unavailable `/proc/self/smaps` inspection. [Detailed scope and Frida failure](docs/testing-v0.4-2026-10-20.md) |
| Local functional and real CMake integration tests | **176 passed, none skipped**, on 2026-10-15, including Windows timestamp compatibility and PE debug-entry classification regressions; see the [validation record (Chinese)](docs/validation.zh-CN.md) |
| GitHub CI | Linux and Windows/MSVC jobs have passed; see the [run history](https://github.com/Afloat16/anti-rea-forge/actions). These runs are separate from the local test count; Windows DLL ABI compatibility remains untested |
| Selected literal masking, release gates, signed manifests, offline license tools | Implemented within the boundaries described below |
| Independent Ghidra static analysis and independent runtime observation | Both recovered a synthetic sample’s test secret; the unmodified original accepted it. The anti-cracking goal failed |
| REA 6.5.0 integrated analysis | Blocked by the test host environment and not completed; this is **not** evidence of successful protection |

Passing tests or release gates does not measure resistance to cracking. REA’s integrated analysis was blocked by process inspection and temporary-directory limitations; standalone Ghidra successfully analyzed the protected sample. The [test report (Chinese)](docs/testing-2026-10-15.zh-CN.md) separates these outcomes and preserves the evidence. We have no credible “high probability of stopping REA” or general cracking-resistance rate.

## Help build and challenge it

- **Reverse engineering:** analyze project-owned or explicitly authorized samples; share reproducible steps, tool versions, and verifiable observations.
- **C/C++:** improve build integration, compatibility, and protection proposals while checking program output and public interfaces.
- **Python and testing:** strengthen PE/ELF checks, environment diagnostics, and experiments that distinguish recovery, timeout, and environmental failure.
- **Windows:** help validate MSVC, EXE/DLL behavior, and compatibility with callers. Existing CI coverage does not replace Windows DLL ABI or real application testing.
- **First contributions:** start with documentation, minimal reproductions, error messages, or test-environment instructions. Small PRs are welcome.

Use **Issues → New issue** for a bug, experiment, or proposal, or submit a PR. Read the [contribution guide (Chinese)](CONTRIBUTING.md) and [code of conduct (Chinese)](CODE_OF_CONDUCT.md). Use synthetic data in public reports; follow [SECURITY.md (Chinese)](SECURITY.md) for sensitive security issues. Fork, star, or share the project with people who want to test and improve it.

## What is implemented

| Component | Behavior |
| --- | --- |
| `native-init` + `releaseguard_protect(target POLICY ...)` | Generate CMake/C++ build assets, enable Release optimization and LTO, and fail the build when its artifact violates the policy |
| `RG_TEXT("...")` | Apply reversible compile-time masking to selected C++17 literals; decode into an object with a defined lifetime. Build seeds diversify the static payload |
| `releaseguard::secure_buffer` | Explicitly owned native pages with guards, checked locking, clearing and platform-specific dump status |
| `capability-issue / capability-consume / replay-store-init` | Server-side, short-lived, exact-request authorization with persistent atomic replay rejection |
| `gate` | Scan declared literals in five encodings, inspect debug/symbol metadata, reject forbidden sidecars, and require configured PE structural evidence |
| `gate --root` in v0.3 | Optional exact file allowlist, source/backup path rules, old artifact hash denylist, and bounded whole-release literal scans |
| `password-create / password-check` | Fixed-profile, salted Argon2id one-way verifiers with pre-KDF resource validation |
| `asset-keygen / asset-seal / asset-open` | External-key AES-256-GCM data assets with HKDF-SHA256 and trusted context binding |
| `audit` | Read-only inspection of PE32/PE32+ EXE/DLL files, CLR directories, ASLR/DEP/CFG flags and supporting structures, debug directories, and certificate tables |
| `keygen` | Generate a passphrase-encrypted Ed25519 private key and a distributable public key; refuse to overwrite existing files |
| `manifest-sign / manifest-verify` | Sign a complete release inventory; verify hashes, product, and version; reject missing, modified, or extra files |
| `license-issue / license-verify` | Issue and verify portable offline licenses, including product, subject, validity period, and feature permissions |
| `cmake/ReleaseGuard.cmake` | Integrate MSVC/Windows and GCC or Clang/Linux builds; retain the original MSVC `releaseguard_harden` interface |

Selected C++ literals must be marked with `RG_TEXT`. This version does not provide general code virtualization, automatic rewriting of every string, or a C/C++/.NET license runtime SDK. License checks must be integrated into business entry points or a trusted installation/update process. Build seeds are public diversification values, not secret encryption keys.

IDA, Ghidra, .NET decompilers, and other tools can analyze local programs. A person who controls the execution environment can patch client checks. Publishing this source does not disclose your issuer’s private keys; valid release and license signatures still depend on keeping those keys private, fixing a trusted public key, and preserving a trusted verifier. This project has not undergone an independent security audit.

## Build integration

After installation, include the module in your CMake project and call the function after creating the target:

```cmake
include("/path/to/anti-rea-forge/cmake/ReleaseGuard.cmake")
add_executable(myapp main.cpp)
releaseguard_protect(myapp POLICY "${CMAKE_CURRENT_SOURCE_DIR}/policy.json")
```

Use a named object for selected C++ literals. The build hook generates and force-includes the build seed header:

```cpp
#include <releaseguard/literal.hpp>
auto message = RG_TEXT("internal-feature-route-v1");
use(message.c_str()); // message must remain alive while its buffer is used
```

The [native integration guide (Chinese)](docs/native-build.zh-CN.md) covers policy files, generating modules from the installed package, and checking the final release directory. Pure C projects can use build hardening and gates; the literal component requires C++17. Other languages and build systems do not currently have automatic conversion backends.

## Install and inspect

Requires Python 3.10 or later. The Python signing tools support Windows, Linux, and macOS. The native build hook currently supports MSVC/Windows and GCC or Clang/Linux. `audit` inspects Windows PE; `gate` checks PE or ELF according to policy. Run these commands from the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
releaseguard --help
releaseguard audit C:\releases\MyApp\MyApp.exe
```

The activation command above is for Windows PowerShell. On Linux/macOS, use `source .venv/bin/activate`. If `releaseguard` is not on PATH, use `python -m releaseguard` in the same virtual environment.

`audit` reports static evidence without executing the inspected file. A certificate table does not establish Authenticode trust. Use Windows trust verification for code signatures, for example `signtool verify /pa /all /v MyApp.exe` after installing the Windows SDK. `policy_passed` means the audit found no warnings. With `--strict`, warnings produce exit code 3 and `ok: false`; tool errors produce exit code 2. The report’s `notes` still apply when the static checks pass.

## 1. Generate keys in the issuer’s environment

**Create a private directory outside both the source repository and the release directory.** Adjust the example paths for your machine:

```powershell
mkdir C:\ReleaseGuardKeys
releaseguard keygen --private C:\ReleaseGuardKeys\issuer-private.pem --public .\issuer-public.pem
```

An interactive terminal prompts for and confirms a passphrase of at least 12 UTF-8 bytes. The private key uses encrypted PKCS#8; POSIX creation permissions are 0600. On Windows, protect the directory with appropriate user ACLs and keep an encrypted backup. **Private keys belong only in the controlled issuer environment; never ship them to clients or publish them.** Do not upload passphrases or real customer licenses. Automation may inject `RELEASEGUARD_PASSPHRASE` from a secret manager; do not put the passphrase in scripts or command-line arguments.

Public keys may be public, but the verifier must **pin a trusted public key or its full SHA-256 fingerprint through a trusted channel**. A license or download must not choose its own trusted key. `--public` must point to a previously trusted configuration. If an attacker can replace it, they can issue a matching set of forged materials with their own key.

## 2. Sign and verify a release manifest

Complete the build, tests, and Authenticode signing before placing all distributable files in a clean release directory. Keep the private key outside that directory. The manifest must also remain outside it to avoid self-reference; public keys and licenses can be kept separately:

```powershell
releaseguard manifest-sign --root .\release\MyApp --private C:\ReleaseGuardKeys\issuer-private.pem --product MyApp --release 1.0.0 --out .\MyApp-1.0.0.manifest.json
releaseguard manifest-verify .\MyApp-1.0.0.manifest.json --root .\release\MyApp --public .\issuer-public.pem --product MyApp --release 1.0.0
```

A valid directory returns `"ok": true`. Modified files, missing DLLs, and additional unlisted files fail verification. Output files are created only at new paths; use a new filename for a new release. The complete directory is checked without an option to ignore extra DLLs. `--release` rejects a manifest with a different expected version; the expected version must itself come from a trusted update policy.

Manifest paths use Unicode NFC. The implementation rejects path traversal, absolute paths, Windows device names/ADS/path aliases, case collisions, symbolic links, and reparse points. Manifest creation also rejects common private-key filenames as an additional mistake-prevention measure; this is not a general secret scanner. Store mutable logs, caches, and user data elsewhere.

Signatures verify data; they do not encrypt code or establish that a file is the newest trusted release. Verification covers the bytes read at check time. Secure installation, loading, and update controls are still needed to handle replacement after verification and rollback.

## 3. Issue and verify offline licenses

```powershell
releaseguard license-issue --private C:\ReleaseGuardKeys\issuer-private.pem --product MyApp --subject customer-001 --days 365 --feature export --out .\customer-001.license.json
releaseguard license-verify .\customer-001.license.json --public .\issuer-public.pem --product MyApp --subject customer-001 --require-feature export
```

Manifests and licenses use separate signing domains and cannot substitute for one another. Production systems may also use separate keys for releases and licenses. License times are checked in UTC, with an exclusive expiry boundary. Licenses are readable signed data and **do not encrypt customer information**. This version permits copying licenses and has no device binding, online revocation, or reliable offline protection against clock rollback.

See [examples/verify_startup.py](examples/verify_startup.py) for Python integration. Native C++/C# applications can implement the [v1 format (Chinese)](docs/format-v1.md) using a maintained cryptographic library; this project does not yet supply a tested native verification SDK. Enforce authorization at actual business entry points and check each feature’s permissions. Keep signing private keys, service credentials, and any secrets that must remain confidential in controlled issuer/server environments. Permanent secrets embedded in offline clients are recoverable targets.

## Hardening and validation

Read the [native integration guide (Chinese)](docs/native-build.zh-CN.md), [Windows/.NET build notes (Chinese)](docs/build-hardening.zh-CN.md), and [security model (Chinese)](SECURITY.md). ASLR, DEP, and CFG mitigate exploitation; they do not prevent decompilation. Preserve PDBs in private symbol storage. Assess Native AOT compatibility per project; native analysis remains possible.

```powershell
python -m unittest discover -s tests -v
cmake -S examples -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The CMake commands above target Windows/MSVC. Linux GCC examples and integration tests are covered in the [contribution guide (Chinese)](CONTRIBUTING.md); set `RELEASEGUARD_CMAKE` if CMake is not on PATH. Local results and GitHub CI are recorded separately. CI has exercised Linux and Windows/MSVC builds, but Windows DLL ABI, real business applications, and Windows reverse-engineering resistance remain outside the completed validation.

On Linux, run `python benchmarks/native_compare.py --out comparison.json` for the project-owned ordinary/protected build comparison. Run `python benchmarks/runtime_boundary.py --out runtime-boundary.json` to reproduce plaintext recovery at a dynamic comparison boundary. For the latter, exit 0 means the experiment completed with successful recovery, so the protection goal failed. It generates and analyzes only its own temporary sample and accepts no external binary input. See the [validation record (Chinese)](docs/validation.zh-CN.md) and [full test report (Chinese)](docs/testing-2026-10-15.zh-CN.md) for evidence and limitations.

## Project and contributions

Started by [Afloat16](https://github.com/Afloat16), licensed under [MIT](LICENSE). Fork and submit a PR, or open an issue with experimental results and design suggestions. The [contribution guide (Chinese)](CONTRIBUTING.md) lists verification expectations and beginner-friendly tasks; the [roadmap (Chinese)](docs/ROADMAP.zh-CN.md) defines proposed work and acceptance criteria.

The tools, methods, and synthetic samples are open source. Your application source, production keys, and server implementation do not need to be published with them.

## References

- [cryptography: Ed25519 signing](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/)
- [Microsoft: PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Microsoft: Control Flow Guard](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard?view=msvc-170)
- [Microsoft: Native AOT deployment](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/)
