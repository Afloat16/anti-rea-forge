# Changelog

## 0.3.0 — 2026-10-20

- Add bounded, fixed-profile Argon2id password verifiers and CLI commands; store no recoverable reference password.
- Add external-key AES-256-GCM data assets with per-package HKDF-SHA256 keys, strict encoding and trusted four-part context binding. Authenticate before returning or writing plaintext.
- Extend release-root gates with exact file allowlists, forbidden path components, known-old SHA-256 values and aggregate-budget whole-release literal scans. Keep v1 policies that omit these fields compatible.
- Reject FIFO substitutions during gate reads and account for Windows path-stat/file-stat timestamp differences when loading asset keys.
- Add reproducible crypto controls, including weak-password and runtime-plaintext negative controls, and run the functional controls in Linux/Windows CI.
- Record 259 passing local tests, package-content verification, and a fresh successful recovery of the original native masked-secret fixture. These are implementation results; no general decompilation, memory-dump or REA resistance rate is claimed.

See [validation](docs/testing-2026-10-20.md), [integration](docs/crypto-protection.md) and [security boundaries](SECURITY.md). This release adds Python APIs/CLI/build tools, not a native verifier SDK, server key service or executable virtualizer.
