# Anti-REA Forge 1.0

[![CI](https://github.com/Afloat16/anti-rea-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/Afloat16/anti-rea-forge/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Afloat16/anti-rea-forge)](https://github.com/Afloat16/anti-rea-forge/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-76d9cb.svg)](LICENSE)

[English](README.md) · [简体中文](README.zh-CN.md) · [Download v1.0.0](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.0.0) · [Upgrade guide](docs/releases/v1.0.0.md)

**Reduce what reverse-engineering tools can recover from a release. Keep private material outside it.**

Anti-REA Forge combines bounded release inspection, private debug/source-map separation, authenticated native data and trusted service authorization. It gives Python, CMake/C++ and JavaScript builds one set of release decisions, backed by reproducible positive and negative controls.

| Release gate | Native data experiment | JavaScript bridge |
| --- | --- | --- |
| **3 operating systems · 13 required CI jobs** | **0 exact recoveries from 18,024 / 18,121 candidates** | **0 npm runtime dependencies** |
| Linux, Windows and macOS; fresh wheel, source and SDK installs | External-key fixture; Ghidra 12.2 / IDA Freeware 5.0, historical paired control | Node.js 22+, isolated calls to the installed Python core |

The candidate counts above describe one 32-byte Linux i386 resource and the recorded extraction procedure, not an all-tools success rate. The plaintext and deliberately leaked-key controls both recover the resource. [Experiment data](docs/results/native-asset-controls.json) · [Release gate policy](release-policy.json) · [Live CI](https://github.com/Afloat16/anti-rea-forge/actions/workflows/ci.yml)

![Anti-REA Forge architecture: trusted build, public artifacts, authorized use and a separate private issuer](docs/images/architecture-en.svg)

## What is new in 1.0

- **Catch disclosures that ordinary stripping leaves behind.** ELF inspection detects CTF/BTF private type metadata. `split-elf-debug` preserves eligible non-allocated metadata privately, removes it from the public binary, and checks runtime segments and exported ABI. PE DWARF/STABS and thin/universal Mach-O checks cover the other native release paths.
- **Close packaging blind spots.** ZIP, packed ASAR and verified unpacked siblings share inspection budgets. Source-map detection follows bounded JSON content across supported encodings and nested containers. Recognized unsupported containers and debug formats explicitly block completion.
- **Keep the build gate attached to the real verifier.** CMake and the JavaScript SDK invoke the installed Python core in isolated mode. Whole-file inventory and external-key checks detect changed release inputs; final preparation rechecks the signed result.
- **Close native sealing output paths.** Complete function/global inventories and rejection of emission-capable LLVM metadata, attached data and assembly prevent known post-transform plaintext leftovers. Native VM instruction sealing remains experimental and has a narrow supported function/target set.
- **Check authorization at admission.** Capability expiry is rechecked after durable replay-state consumption; a live replay store rejects database-file replacement. Shared document readers reject special files, unsafe leaf links, oversized inputs and changing files.
- **Publish the bytes that passed installation.** The release pipeline requires every named main-branch CI job, installs wheel and source archives in fresh environments on all three operating systems, exercises the packed SDK, verifies archive SHA-256, and checks uploaded assets before publication.

[Audit, compatibility and evidence](docs/releases/v1.0.0.md) · [Portable release integration](docs/portable-release.md) · [Security boundaries](SECURITY.md)

## Evidence with controls

| Question | Measured result | Exact scope / record |
| --- | --- | --- |
| Can an analyzer recover an embedded plaintext resource? | **Yes**, with both tools | Positive control in the [paired Ghidra/IDA observation](docs/results/native-asset-controls.json) |
| Can the same procedure recover the encrypted resource without its external key? | **0 exact payload recoveries**; all 18,024 Ghidra and 18,121 IDA contiguous 32-byte candidates tested | Same owned i386 fixture; initialized analyzer bytes checked against input |
| Does accidentally shipping the real key defeat that boundary? | **Yes**: key recovered, replayed, exact resource read | Both analyzers; the production release gate also reports the leaked key |
| Does patching the local gate supply the missing encryption key? | Plaintext control recovers; encrypted control does not recover exact data | Actual gate patch and forced-GCM-success controls, [method](docs/native-assets.md) |
| What does opening a 1 MiB native asset cost? | **189.860 µs median**, 25 calls after 5 warmups; maximum 1,456.005 µs | Historical v0.10 run on one Linux x86-64 host; includes allocation/cleansing, excludes key delivery/startup. [All samples](docs/results/native-asset-cost.json) |
| What is validated for the downloadable release? | Exact commit, required CI job results, installed-package checks and archive hashes | `release-evidence.json`, `installation-report.json` and `SHA256SUMS` attached to the [Release](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.0.0) |

Ghidra, compiler, REA CLI/source-map, official ASAR, GNU binutils, macOS and MSVC controls run in CI. Historical observations stay dated and retain their failures. Ordinary and VM-only native samples were independently reconstructed across **1,081,924 hidden evaluations**; that failure motivated external-key instruction sealing. [Native code research and remaining validation](docs/native-code.md)

## Start with the release gate

Python 3.10+ is required. Install the wheel from [v1.0.0](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.0.0) into your chosen virtual environment, or run `python -m pip install .` from this checkout. The public command and import name remain `releaseguard`.

```sh
python -m pip install https://github.com/Afloat16/anti-rea-forge/releases/download/v1.0.0/open_release_guard-1.0.0-py3-none-any.whl
python -m releaseguard --version
python -m releaseguard project-init --root dist --product MyApp --out .releaseguard
python -m releaseguard check --config .releaseguard/project.json
```

Build your application into `dist`, review `.releaseguard/policy.json`, and keep private symbols, keys and signing material outside that directory. Add known external keys to `asset_key_files` in the saved project configuration. A failed check returns a nonzero exit code. `prepare` scans and signs an immutable staging directory and writes its evidence outside the release. [Complete workflow](docs/portable-release.md)

### JavaScript / TypeScript

```sh
npm install https://github.com/Afloat16/anti-rea-forge/releases/download/v1.0.0/anti-rea-forge-releaseguard-1.0.0.tgz
```

```js
import { createReleaseGuard } from "@anti-rea-forge/releaseguard";
const guard = createReleaseGuard({ python: process.env.RELEASEGUARD_PYTHON });
const report = await guard.checkProject({ config: ".releaseguard/project.json" });
process.exitCode = report.exitCode;
```

Set `RELEASEGUARD_PYTHON` to the absolute path of the installed virtual-environment interpreter. The SDK archive is distributed through GitHub Releases; no npm registry publication is implied. [SDK guide](packages/releaseguard/README.md)

## Choose the boundary you need

| Need | Integration | Status |
| --- | --- | --- |
| Detect accidental release disclosure and packaging ambiguity | [Portable release gate](docs/portable-release.md) | Cross-platform, policy-driven checks |
| Keep selected native data confidential without its external key | [Native assets](docs/native-assets.md) | C++17/OpenSSL; authenticated context binding |
| Keep private source maps and debug/type information off the client | [Source maps](docs/private-source-maps.md), [ELF symbols](docs/private-elf-debug.md) | Public/private split with controlled inputs |
| Enforce a sensitive operation in trusted code | [Service capabilities](docs/runtime-protection.md), [analysis gateway](docs/analysis-authorization.md) | Authenticated identity, fixed policy and replay storage required |
| Encrypt selected VM instruction storage | [Native code](docs/native-code.md) | **Experimental** LLVM 18 / Linux x86-64 scalar-integer subset |

## Trust and limits

A release scan checks configured rules on inspected bytes. It does not disable Ghidra, IDA, REA, Frida or another independent reader. Authorized process memory can hold keys and plaintext; distributed code and public helpers remain observable; a modified local client cannot be the authority for a server operation. Keep staging directories, interpreters, policies, keys and replay storage trusted. Unknown encodings and unsupported formats are not silently promoted to a resistance guarantee.

The 1.x series keeps existing v1 signed-document formats and the CLI/import names. It is not an independent security audit, and experimental native transformations are explicitly scoped. [Security policy](SECURITY.md) · [Upgrade notes](docs/releases/v1.0.0.md) · [Historical recovery failures](docs/testing-2026-10-15.zh-CN.md)

## Reproduce and contribute

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
npm test --prefix packages/releaseguard
# Set RELEASEGUARD_PYTHON to your installed interpreter before real CLI integration:
npm run test:integration --prefix packages/releaseguard
```

The CI workflow pins external compiler/analyzer inputs and marks required controls as mandatory. Missing local tools are reported as skips, not successes. Contributions with a small owned fixture and a reproducible failure are welcome. [Contributing](CONTRIBUTING.en.md) · [MIT license](LICENSE)
