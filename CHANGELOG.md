# Changelog

## 0.8.0 — 2026-11-09

- Add `native-token-issue`: issue an external 256-bit random bearer and generate public C++17/OpenSSL verifier headers without putting its usable value in build inputs.
- Check portable release contents and supported ZIP members for the native token format, across chunks and five encodings. Ordinary reports identify the location without echoing matched contents.
- Add a native example, independent wrong-input comparison controls and a pinned official Ghidra decompilation/extraction/replay benchmark on project-owned Linux ELFs. See [integration and reproduction](docs/native-tokens.md).

## 0.7.0 — 2026-11-09

- Add the build-only `split-source-maps` command. Create an unchanged public JavaScript release and a separate private external-map directory, failing on recognized residual disclosure or unsupported inputs. The local JavaScript SDK API remains unchanged.
- Add paired, version-pinned experiments with Craft Anything, REA and trace-mapping on one project-owned Terser build. See the [integration guide and precise evidence boundary](docs/private-source-maps.md).

## 0.6.0 — 2026-11-05

- Add `project-init`, `check` and `prepare` for editable build configuration and scan-then-sign release sidecars. Resolve paths relative to configuration, refuse overwrites, reject output/private keys in the release, and compare scanned and signed inventories before publication. Never rewrite or execute release files.
- Add separate-domain Ed25519 analysis grants bound to one complete signed manifest, product/release, authenticated subject, gateway audience, independent `inspect` / `decompile` / `instrument` scopes and a validity interval of at most 24 hours. Denied grants skip target hashing; allowed grants recheck the release and clock without caching an allow result.
- Add JavaScript/TypeScript `checkProject`, `checkAnalysis` and `withAnalysisAuthorization`. The last invokes a fixed handler only after a consistent allow report and a final validity/cancellation check. Denials, subprocess/protocol errors and expired reports prevent the call.
- Handle failed subprocess starts without stdout/stderr streams as classified failures, retaining the spawn error listener.
- Generate public English/Chinese analysis notices, document trusted deployment inputs and provide a runnable fixed-handler example. Notices are unsigned information and do not override licenses or model instructions.
- Review REA's existing untrusted-target-content handling at `92f332652d352e60b550567adf2399d83d8ebe78` (source version 6.8.0); record synthetic unchanged-file, authorization and build-cost evidence.

See [integration](docs/analysis-authorization.md), [source research](docs/rea-agent-authorization-2026-11-05.zh-CN.md) and [validation](docs/testing-v0.6-2026-11-05.md). The new functionality runs outside the protected application's execution path. It does not control independent REA instances, force model refusals, authenticate callers, provide online revocation or prevent check-to-use replacement.

## 0.5.0 — 2026-11-04

- Add `scan-release` and the Python `scan_release` API for release directories from any language, without requiring a PE/ELF entry artifact. Preserve existing native gates and cryptographic formats.
- Check configured literals in five encodings, private-key PEM markers, source-map markers, forbidden paths/extensions, denied hashes and optional exact file inventories. Reports identify rules without echoing matched contents.
- Inspect ZIP-family package members without extraction, with bounded input/expanded bytes, nesting and entry counts. Reject malformed, encrypted, unsupported or unsafe ZIP content instead of reporting a partial pass.
- Add a dependency-free JavaScript ESM bridge with TypeScript declarations, isolated Python invocation, bounded subprocess output, cancellation and timeouts. It reuses the Python core and is not a new cryptographic implementation or a published npm release.
- Add English/Chinese contribution paths, portable integration examples, regression tests and JavaScript CI. Review REA source at pinned commit `89317a39fab23df81efa4331311d09d2110377bd` (source version 6.8.0).

See [portable release integration](docs/portable-release.md), [REA source review](docs/rea-source-review-2026-11-04.zh-CN.md) and [validation](docs/testing-v0.5-2026-11-04.md). These are release-exposure checks and integration improvements, not an end-to-end REA resistance result.

## 0.4.0 — 2026-10-20

- Add a C++17 sensitive buffer with guarded non-executable pages, checked page locking, full owned-page clearing and explicit dump-exclusion status. Linux supports `MADV_DONTDUMP`; Windows does not claim dump exclusion.
- Add separate-domain, short-lived Ed25519 request capabilities and server-only CLI commands. Bind trusted subject, audience, product, operation and exact request bytes; do not distribute the signing key to clients.
- Add a durable SQLite replay store with atomic single-use consumption, trusted-clock rollback rejection, capacity limits and fail-closed handling of missing or invalid state. This is not exactly-once business execution or rollback-proof storage.
- Add independent server-boundary controls and native memory tests, include the new C++ component in generated/package assets, and exercise it in native CMake/CI builds.
- Map runtime threats to pinned REA 6.7.0 source and primary research from 2024–2026. Memory hygiene does not stop in-process hooks, and no general REA resistance probability is claimed.

See [runtime integration](docs/runtime-protection.md) and [validation](docs/testing-v0.4-2026-10-20.md). Existing offline license and sealed-asset semantics remain unchanged.

## 0.3.0 — 2026-10-20

- Add bounded, fixed-profile Argon2id password verifiers and CLI commands; store no recoverable reference password.
- Add external-key AES-256-GCM data assets with per-package HKDF-SHA256 keys, strict encoding and trusted four-part context binding. Authenticate before returning or writing plaintext.
- Extend release-root gates with exact file allowlists, forbidden path components, known-old SHA-256 values and aggregate-budget whole-release literal scans. Keep v1 policies that omit these fields compatible.
- Reject FIFO substitutions during gate reads and account for Windows path-stat/file-stat timestamp differences when loading asset keys.
- Add reproducible crypto controls, including weak-password and runtime-plaintext negative controls, and run the functional controls in Linux/Windows CI.
- Record 259 passing local tests, package-content verification, and a fresh successful recovery of the original native masked-secret fixture. These are implementation results; no general decompilation, memory-dump or REA resistance rate is claimed.

See [validation](docs/testing-2026-10-20.md), [integration](docs/crypto-protection.md) and [security boundaries](SECURITY.md). This release adds Python APIs/CLI/build tools, not a native verifier SDK, server key service or executable virtualizer.
