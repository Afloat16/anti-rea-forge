# Changelog

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
