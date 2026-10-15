# 🛡️ Anti-REA Forge

[English](README.md) · [简体中文](README.zh-CN.md)

![Anti-REA Forge banner](assets/anti-rea-forge.svg)

> **AI-assisted reverse engineering is advancing. Let’s make software protection a reproducible engineering challenge.**

Anti-REA Forge is an open research and engineering project exploring native software protection against analysis with tools such as **REA and Ghidra**. It provides CMake integration, C++ components, PE/ELF release gates, and reproducible experiments that make protection claims easier to inspect and challenge.

**Contributions are welcome. Our current anti-cracking goals remain unmet:** independent static and runtime analysis recovered test secrets from protected synthetic samples, and the original programs accepted the recovered values. We publish these failures to guide improvement and make no promise of unbreakable software.

**MIT · 0.2.0 / Alpha · C/C++ build integration · Python tooling · PE / ELF**

[Contribute (Chinese)](CONTRIBUTING.md) · [Community invitation](https://github.com/Afloat16/anti-rea-forge/issues/1) · [Challenges and roadmap (Chinese)](docs/ROADMAP.zh-CN.md) · [Test report (Chinese)](docs/testing-2026-10-15.zh-CN.md) · [Security model (Chinese)](SECURITY.md)

The tooling retains the **Open Release Guard** Python distribution name `open-release-guard`, CLI/import name `releaseguard`, and existing CMake interfaces. The project targets Windows EXE/DLL protection research and also supports Linux ELF validation. It is independently developed and is not affiliated with or endorsed by REA.

## Evidence so far

| Evaluation | Observed result |
| --- | --- |
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
| `gate` | Scan declared literals in five encodings, inspect debug/symbol metadata, reject forbidden sidecars, and require configured PE structural evidence |
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
