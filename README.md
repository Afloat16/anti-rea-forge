# Anti-REA Forge 1.2

[![CI](https://github.com/Afloat16/anti-rea-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/Afloat16/anti-rea-forge/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Afloat16/anti-rea-forge)](https://github.com/Afloat16/anti-rea-forge/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-76d9cb.svg)](LICENSE)

[English](README.md) · [简体中文](README.zh-CN.md) · [Download v1.2.0](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.2.0) · [Upgrade guide](docs/releases/v1.2.0.md)

**Reduce what reverse-engineering tools can recover from a release. Keep private material outside it.**

Anti-REA Forge combines bounded release inspection, private debug/source-map separation, authenticated native data and trusted service authorization. It gives Python, CMake/C++ and JavaScript builds one set of release decisions, backed by reproducible positive and negative controls.

| Five WebAssembly programs | Four JavaScript builds | Release gate |
| --- | --- | --- |
| **26 → 0 → 26 private identifiers recovered** | **9 → 0 → 9 exact originals recovered** | **3 operating systems · 13 required CI jobs** |
| 43 numerical checks, 2 runtime traps and 1 host rejection preserved | 5 bundles; 16 functional inputs per side; generated JS unchanged | Published REA 6.9.0 and a separate pinned source build; fresh package installations |

Results are original → public → private-restored, for owned fixtures. WAT instructions and generated JavaScript remain analyzable. Incomplete analysis never establishes absence; rejected inputs and unavailable original text are reported separately. [Wasm evidence](docs/results/wasm-corpus-v1.2.0-rea-6.9.0.json) · [JavaScript evidence](docs/results/source-map-corpus-v1.2.0-rea-6.9.0.json) · [Full assessment](docs/rea-defense-v1.2.0.zh-CN.md) · [Release gate policy](release-policy.json)

![Anti-REA Forge architecture: trusted build, public artifacts, authorized use and a separate private issuer](docs/images/architecture-en.svg)

## What is new in 1.2

- **Test more than one program.** Five Wasm programs exercise helpers, imports, memory, globals, indirect calls and loops. Four JavaScript builds cover multiple sources/bundles, Unicode and partly missing original content. Each has original, public and private-restored measurements against both REA distributions. [Reproduction and results](docs/releases/v1.2.0.md)
- **Close the residual linker-symbol channel.** Actual v1.1 output can lose its `name` section while retaining a recoverable helper in `linking`. The gate and splitter now require final linking for recognized `linking` / `reloc.*` metadata. The unsupported input is rejected before either output is created. [Wasm integration](docs/private-wasm-debug.md)
- **Catch source disclosure even in incomplete maps.** An escaped `sourcesContent` key is still sensitive when `mappings` is absent or invalid: real REA can recover the original from a partial graph. The release gate now gives the decoded key the same conservative treatment as its literal spelling.
- **Follow actual key consumers.** Expanded, bounded recognition covers recoverable JWK spellings, integer-valued byte arrays and embedded byte windows, folded/mixed-case known keys, and supported JSON-encoded private DER. Real Node imports and cryptographic decryption/signing prove the disclosures before comparing v1.1 and v1.2. [Key evidence](docs/results/secret-representation-recovery-v1.2.0.json)
- **Make the new cases mandatory.** The expanded corpora run in required CI. Fresh wheel and source installations must reject encoded-key, incomplete-map and relocatable-Wasm fixtures. Existing native, authorization, SDK and package checks remain mandatory.

[Upgrade notes](docs/releases/v1.2.0.md) · [Portable release integration](docs/portable-release.md) · [Security boundaries](SECURITY.md)

## Evidence with controls

| Question | Measured result | Exact scope / record |
| --- | --- | --- |
| Can REA recover Wasm private names after separation? | **26 → 0 → 26** across 5 programs; 43 numerical checks and 3 failure controls preserved | [npm](docs/results/wasm-corpus-v1.2.0-rea-6.9.0.json) / [pinned source](docs/results/wasm-corpus-v1.2.0-rea-source.json); standard sections identical. Public logic remains readable. |
| Does withholding source maps remove the exact-original channel? | **9 → 0 → 9** across 4 builds / 5 bundles; generated JS unchanged | [npm](docs/results/source-map-corpus-v1.2.0-rea-6.9.0.json) / [pinned source](docs/results/source-map-corpus-v1.2.0-rea-source.json); one already-unavailable original is excluded |
| Can missing mappings or removed name sections leave disclosures? | **Yes**: 2 incomplete maps still reveal source; 1 linker-symbol fixture still reveals a helper | Actual v1.1 admits these inputs; v1.2 rejects them. Unsupported outputs are never scored as zero recovery. |
| Do the new encoded-key cases actually work after recovery? | **19 / 19** recovered keys decrypt or sign; v1.2 blocks all 19, while **2 / 2** nonsecret controls pass | Verified official v1.1 wheel comparison and nonsecret controls; [case-by-case evidence](docs/results/secret-representation-recovery-v1.2.0.json) |
| Can an analyzer recover an embedded plaintext resource? | **Yes**, with both tools | Positive control in the [paired Ghidra/IDA observation](docs/results/native-asset-controls.json) |
| Can the same procedure recover the encrypted resource without its external key? | **0 exact payload recoveries**; all 18,024 Ghidra and 18,121 IDA contiguous 32-byte candidates tested | Same owned i386 fixture; initialized analyzer bytes checked against input |
| Does accidentally shipping the real key defeat that boundary? | **Yes**: key recovered, replayed, exact resource read | Both analyzers; the production release gate also reports the leaked key |
| Does patching the local gate supply the missing encryption key? | Plaintext control recovers; encrypted control does not recover exact data | Actual gate patch and forced-GCM-success controls, [method](docs/native-assets.md) |
| What does opening a 1 MiB native asset cost? | **189.860 µs median**, 25 calls after 5 warmups; maximum 1,456.005 µs | Historical v0.10 run on one Linux x86-64 host; includes allocation/cleansing, excludes key delivery/startup. [All samples](docs/results/native-asset-cost.json) |
| What is validated for the downloadable release? | Exact commit, required CI job results, installed-package checks and archive hashes | `release-evidence.json`, `installation-report.json` and `SHA256SUMS` attached to the [Release](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.2.0) |

Ghidra, compiler, REA CLI/source-map, official ASAR, GNU binutils, macOS and MSVC controls run in CI. Historical observations stay dated and retain their failures. Ordinary and VM-only native samples were independently reconstructed across **1,081,924 hidden evaluations**; that failure motivated external-key instruction sealing. [Native code research and remaining validation](docs/native-code.md)

## Start with the release gate

Python 3.10+ is required. Install the wheel from [v1.2.0](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.2.0) into your chosen virtual environment, or run `python -m pip install .` from this checkout. The public command and import name remain `releaseguard`.

```sh
python -m pip install https://github.com/Afloat16/anti-rea-forge/releases/download/v1.2.0/open_release_guard-1.2.0-py3-none-any.whl
python -m releaseguard --version
python -m releaseguard project-init --root dist --product MyApp --out .releaseguard
python -m releaseguard check --config .releaseguard/project.json
```

Build your application into `dist`, review `.releaseguard/policy.json`, and keep private symbols, keys and signing material outside that directory. Add known external keys to `asset_key_files` in the saved project configuration. A failed check returns a nonzero exit code. `prepare` scans and signs an immutable staging directory and writes its evidence outside the release. [Complete workflow](docs/portable-release.md)

### JavaScript / TypeScript

```sh
npm install https://github.com/Afloat16/anti-rea-forge/releases/download/v1.2.0/anti-rea-forge-releaseguard-1.2.0.tgz
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
| Keep private source maps and debug/type information off the client | [Source maps](docs/private-source-maps.md), [ELF symbols](docs/private-elf-debug.md), [Wasm](docs/private-wasm-debug.md) | Public/private split with controlled inputs |
| Enforce a sensitive operation in trusted code | [Service capabilities](docs/runtime-protection.md), [analysis gateway](docs/analysis-authorization.md) | Authenticated identity, fixed policy and replay storage required |
| Encrypt selected VM instruction storage | [Native code](docs/native-code.md) | **Experimental** LLVM 18 / Linux x86-64 scalar-integer subset |

## Trust and limits

A release scan checks configured rules on inspected bytes. It does not disable Ghidra, IDA, REA, Frida or another independent reader. Authorized process memory can hold keys and plaintext; distributed code and public helpers remain observable; a modified local client cannot be the authority for a server operation. Keep staging directories, interpreters, policies, keys and replay storage trusted. Unknown encodings and unsupported formats are not silently promoted to a resistance guarantee.

The 1.x series keeps existing v1 signed-document formats and the CLI/import names. It is not an independent security audit, and experimental native transformations are explicitly scoped. [Security policy](SECURITY.md) · [Upgrade notes](docs/releases/v1.2.0.md) · [Historical recovery failures](docs/testing-2026-10-15.zh-CN.md)

## Reproduce and contribute

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
npm test --prefix packages/releaseguard
# Set RELEASEGUARD_PYTHON to your installed interpreter before real CLI integration:
npm run test:integration --prefix packages/releaseguard
```

The CI workflow pins external compiler/analyzer inputs and marks required controls as mandatory. Missing local tools are reported as skips, not successes. Contributions with a small owned fixture and a reproducible failure are welcome. [Contributing](CONTRIBUTING.en.md) · [MIT license](LICENSE)
