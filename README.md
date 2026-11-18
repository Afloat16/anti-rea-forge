# Anti-REA Forge 1.3

[![CI](https://github.com/Afloat16/anti-rea-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/Afloat16/anti-rea-forge/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Afloat16/anti-rea-forge)](https://github.com/Afloat16/anti-rea-forge/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-76d9cb.svg)](LICENSE)

[English](README.md) · [简体中文](README.zh-CN.md) · [Download v1.3.0](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.3.0) · [Upgrade guide](docs/releases/v1.3.0.md)

**Reduce what reverse-engineering tools can recover from a release. Keep private material outside it.**

Anti-REA Forge combines bounded release inspection, private debug/source-map separation, authenticated native data and trusted service authorization. It gives Python, CMake/C++ and JavaScript builds one set of release decisions, backed by reproducible positive and negative controls.

| Python integer keys | Wrapped signing keys | Private compiler / service inputs |
| --- | --- | --- |
| **12 / 12 real REA recoveries blocked before release** | **8 / 8 actual signing-key disclosures detected** | **Embedded LLVM IR separated · exact private copies rejected** |
| Official v1.2 allowed all 12; v1.3 rejects standalone PYC and executable ZIP apps | Official v1.2 allowed all 8; 2 nonsecret controls still pass | Native instructions and runtime results retained; live source references rechecked through signing |

These are owned fixtures and specific publication controls. REA still reads ordinary client code; refusing a release does not make an already disclosed key unreadable. Positive findings, unsupported formats and exhausted budgets are recorded separately. **3 operating systems · 13 required CI jobs**, with published REA 6.9.0 and a separate pinned source build. [Python evidence](docs/results/python-key-recovery-v1.3.0-rea-6.9.0.json) · [PEM evidence](docs/results/encoded-pem-recovery-v1.3.0.json) · [Full assessment](docs/rea-defense-v1.3.0.zh-CN.md) · [Release gate policy](release-policy.json)

![Anti-REA Forge architecture: trusted build, public artifacts, authorized use and a separate private issuer](docs/images/architecture-en.svg)

## What is new in 1.3

- **Catch keys stored as Python integers.** Real REA exposes constants that reconstruct an exact 32-byte asset key. The bounded PYC profile now checks configured keys in canonical marshal integers, including signed/endian variants and reference forms. Twelve owned representations decrypt successfully before both PYC and ZIP-app publication are refused. [Python evidence](docs/results/python-key-recovery-v1.3.0-rea-source.json)
- **Separate embedded LLVM IR.** Removing ordinary symbols can leave the compiler's private names, source path and arithmetic in `.llvmbc`. The ELF splitter now preserves eligible compiler sections privately and verifies unchanged runtime segments. ELF, PE and Mach-O audits report canonical compiler sections; raw/wrapped bitcode is explicitly unsupported. [Actual Clang / llvm-dis control](docs/results/llvm-metadata-recovery-v1.3.0.json)
- **Keep current private files out of the client.** Declare `private_input_files` once; checks snapshot their current bytes and reject exact copies on disk or inside inspected ZIP/ASAR files. `prepare` rechecks these inputs through signing and final verification. A reusable [public-client / private-service example](examples/private_service) uses the existing scoped authorization API.
- **Recognize PEM inside one outer encoding.** Hex/Base64 wrappers, leading notes and consumer-compatible spellings no longer hide supported private-key markers in JSON. Eight actual signing recoveries are positively detected; two recoverable over-budget cases are separately refused as incomplete. [Consumer evidence](docs/results/encoded-pem-recovery-v1.3.0.json)
- **Require the behavior in installed packages.** New real-tool controls join the existing Wasm, source-map, native, authorization and SDK gates. Fresh wheel, source archive and packed SDK installations exercise the new boundaries before the release publisher accepts their evidence.

[Upgrade notes](docs/releases/v1.3.0.md) · [Portable release integration](docs/portable-release.md) · [Security boundaries](SECURITY.md)

## Evidence with controls

| Question | Measured result | Exact scope / record |
| --- | --- | --- |
| Can an integer constant expose a configured asset key? | **12 / 12** real REA recoveries authenticate and decrypt; v1.2 allows all, v1.3 blocks all | [npm](docs/results/python-key-recovery-v1.3.0-rea-6.9.0.json) / [source](docs/results/python-key-recovery-v1.3.0-rea-source.json); PYC and executable ZIP-app gates; unconfigured/short keys are separate boundaries |
| Can a stripped native program still carry private compiler IR? | **Yes**: `llvm-dis` recovers 4 names, a source path and arithmetic from v1.2 output | [Clang control](docs/results/llvm-metadata-recovery-v1.3.0.json); v1.3 removes that IR channel, preserves its private bytes, `.text`, dynamic symbols and 3 runtime results |
| Does a changed private source evade an old manual digest? | **Yes**; live file references reject the updated exact copy | [REA layout control](docs/results/private-input-controls-v1.3.0-rea-source.json): private-source nodes **1 → 0 → 1**, all graphs complete; this is file absence, not algorithm secrecy |
| Does wrapping a PEM key preserve its signing power? | **8 / 8** actual signatures verified; v1.3 detects all 8 and permits 2 normal controls | [Standard consumers](docs/results/encoded-pem-recovery-v1.3.0.json); 2 recoverable budget rejections excluded from the detection count |
| Can REA recover Wasm private names after separation? | **26 → 0 → 26** across 5 programs; 43 numerical checks and 3 failure controls preserved | [npm](docs/results/wasm-corpus-v1.2.0-rea-6.9.0.json) / [pinned source](docs/results/wasm-corpus-v1.2.0-rea-source.json); standard sections identical. Public logic remains readable. |
| Does withholding source maps remove the exact-original channel? | **9 → 0 → 9** across 4 builds / 5 bundles; generated JS unchanged | [npm](docs/results/source-map-corpus-v1.2.0-rea-6.9.0.json) / [pinned source](docs/results/source-map-corpus-v1.2.0-rea-source.json); one already-unavailable original is excluded |
| Can missing mappings or removed name sections leave disclosures? | **Yes**: 2 incomplete maps still reveal source; 1 linker-symbol fixture still reveals a helper | Actual v1.1 admits these inputs; v1.2 rejects them. Unsupported outputs are never scored as zero recovery. |
| Do the new encoded-key cases actually work after recovery? | **19 / 19** recovered keys decrypt or sign; v1.2 blocks all 19, while **2 / 2** nonsecret controls pass | Verified official v1.1 wheel comparison and nonsecret controls; [case-by-case evidence](docs/results/secret-representation-recovery-v1.2.0.json) |
| Can an analyzer recover an embedded plaintext resource? | **Yes**, with both tools | Positive control in the [paired Ghidra/IDA observation](docs/results/native-asset-controls.json) |
| Can the same procedure recover the encrypted resource without its external key? | **0 exact payload recoveries**; all 18,024 Ghidra and 18,121 IDA contiguous 32-byte candidates tested | Same owned i386 fixture; initialized analyzer bytes checked against input |
| Does accidentally shipping the real key defeat that boundary? | **Yes**: key recovered, replayed, exact resource read | Both analyzers; the production release gate also reports the leaked key |
| Does patching the local gate supply the missing encryption key? | Plaintext control recovers; encrypted control does not recover exact data | Actual gate patch and forced-GCM-success controls, [method](docs/native-assets.md) |
| What does opening a 1 MiB native asset cost? | **189.860 µs median**, 25 calls after 5 warmups; maximum 1,456.005 µs | Historical v0.10 run on one Linux x86-64 host; includes allocation/cleansing, excludes key delivery/startup. [All samples](docs/results/native-asset-cost.json) |
| What is validated for the downloadable release? | Exact commit, required CI job results, installed-package checks and archive hashes | `release-evidence.json`, `installation-report.json` and `SHA256SUMS` attached to the [Release](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.3.0) |

Ghidra, compiler, REA CLI/source-map, official ASAR, GNU binutils, macOS and MSVC controls run in CI. Historical observations stay dated and retain their failures. Ordinary and VM-only native samples were independently reconstructed across **1,081,924 hidden evaluations**; that failure motivated external-key instruction sealing. [Native code research and remaining validation](docs/native-code.md)

## Start with the release gate

Python 3.10+ is required. Install the wheel from [v1.3.0](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.3.0) into your chosen virtual environment, or run `python -m pip install .` from this checkout. The public command and import name remain `releaseguard`.

```sh
python -m pip install https://github.com/Afloat16/anti-rea-forge/releases/download/v1.3.0/open_release_guard-1.3.0-py3-none-any.whl
python -m releaseguard --version
python -m releaseguard project-init --root dist --product MyApp --out .releaseguard
python -m releaseguard check --config .releaseguard/project.json
```

Build your application into `dist`, review `.releaseguard/policy.json`, and keep private symbols, keys and signing material outside that directory. Add known external keys to `asset_key_files` and private source/config references to `private_input_files` in the saved project configuration. A failed check returns a nonzero exit code. `prepare` scans and signs an immutable staging directory and writes its evidence outside the release. [Complete workflow](docs/portable-release.md)

### JavaScript / TypeScript

```sh
npm install https://github.com/Afloat16/anti-rea-forge/releases/download/v1.3.0/anti-rea-forge-releaseguard-1.3.0.tgz
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
| Keep declared private service source/config out of the client | [Private-service example](examples/private_service) | Current exact-file references; scan-to-sign rechecks |
| Keep selected native data confidential without its external key | [Native assets](docs/native-assets.md) | C++17/OpenSSL; authenticated context binding |
| Keep private source maps and debug/type information off the client | [Source maps](docs/private-source-maps.md), [ELF symbols](docs/private-elf-debug.md), [Wasm](docs/private-wasm-debug.md) | Public/private split with controlled inputs |
| Enforce a sensitive operation in trusted code | [Service capabilities](docs/runtime-protection.md), [analysis gateway](docs/analysis-authorization.md) | Authenticated identity, fixed policy and replay storage required |
| Encrypt selected VM instruction storage | [Native code](docs/native-code.md) | **Experimental** LLVM 18 / Linux x86-64 scalar-integer subset |

## Trust and limits

A release scan checks configured rules on inspected bytes. It does not disable Ghidra, IDA, REA, Frida or another independent reader. Authorized process memory can hold keys and plaintext; distributed code and public helpers remain observable; a modified local client cannot be the authority for a server operation. Keep staging directories, interpreters, policies, keys and replay storage trusted. Unknown encodings and unsupported formats are not silently promoted to a resistance guarantee.

The 1.x series keeps existing v1 signed-document formats and the CLI/import names. It is not an independent security audit, and experimental native transformations are explicitly scoped. [Security policy](SECURITY.md) · [Upgrade notes](docs/releases/v1.3.0.md) · [Historical recovery failures](docs/testing-2026-10-15.zh-CN.md)

## Reproduce and contribute

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
npm test --prefix packages/releaseguard
# Set RELEASEGUARD_PYTHON to your installed interpreter before real CLI integration:
npm run test:integration --prefix packages/releaseguard
```

The CI workflow pins external compiler/analyzer inputs and marks required controls as mandatory. Missing local tools are reported as skips, not successes. Contributions with a small owned fixture and a reproducible failure are welcome. [Contributing](CONTRIBUTING.en.md) · [MIT license](LICENSE)
