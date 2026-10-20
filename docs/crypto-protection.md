# Cryptographic boundaries in v0.3.0

[English](crypto-protection.md) · [简体中文](crypto-protection.zh-CN.md)

Anti-REA Forge v0.3.0 adds password verifiers, externally keyed sealed data assets, and stricter release-directory gates. These address specific failures of reversible literal masking. They do not make native programs unbreakable, stop memory inspection, or establish successful protection against REA.

The Python distribution remains `open-release-guard`; the CLI and import package remain `releaseguard`. The asset API handles data, not executable loading, EXE/DLL packing, or a native application SDK. Existing CMake hardening and `RG_TEXT` remain separate components; see the [native build guide (Chinese)](native-build.zh-CN.md).

### Cryptographic choices

This version implements established AES-256-GCM with HKDF and Argon2id, rather than custom RC4/XTEA schemes or a code virtual machine. [AES-GCM-SIV (RFC 8452)](https://www.rfc-editor.org/rfc/rfc8452.html) addresses nonce misuse; [HPKE (RFC 9180)](https://www.rfc-editor.org/rfc/rfc9180.html) addresses hybrid public-key encryption. TEE/KMS architectures and post-quantum key establishment address other trust or key-distribution questions. These are subjects for separate evaluation, not implemented features. Neither those labels nor FHE justify a blanket claim that local plaintext dumps become impossible. Changing the primitive does not repair a client trust boundary once that client legitimately holds the decryption key or plaintext; partitioning genuinely confidential work onto a controlled server still matters.

## Relating the supplied scenario to actual changes

The article pasted by the user describes several recovery rounds and their durations. No independently verifiable author URL or publication time was supplied. We treat those details as a **user-provided scenario**, not independently measured REA results, benchmark timings, or a protection probability. The implementation changes below do not validate those reported durations.

| Scenario | Concrete improvement | Remaining boundary |
| --- | --- | --- |
| Recover a static reversible key or decoded password from code/constants | For password checking, store an Argon2id verifier instead of an `RG_TEXT`-masked answer. For data assets, use a random external master key and authenticated encryption | `RG_TEXT` remains reversible. A verifier permits offline guessing; an asset key embedded in the client restores the original key-recovery problem |
| Dump memory or observe a comparison/decryption boundary | The data asset cannot be opened without the external key and expected context | Once a controlled client receives the key or plaintext, it can be observed or copied. Python does not guarantee zeroization of keys, passwords, or plaintext buffers |
| Find an answer in old source, sidecars, or accidentally shipped files | Scan the entire selected release root, reject known old file hashes and forbidden path components, and enforce an exact file allowlist | Known-byte/hash rules are not a semantic secret detector. Re-encoding or changing an old file changes its hash; previously published secrets still require rotation |
| Recreate the program’s behavior or patch its authorization branch | Keep release identity in a signed manifest; keep genuinely confidential computation and credentials on a controlled server | Signatures do not stop a local patch or an independently written compatible implementation. Data encryption does not hide every native algorithm |

The official REA source inspected for this revision identifies itself as **6.7.0** at commit `f93a0335a8c1a60bbf6debdca16675ba303e4422` and documents Frida instrumentation. This is a statement about that source tree, **not a claim that 6.7.0 is an npm release or that v0.3.0 has defeated REA/Frida**. See the fixed [REA README](https://github.com/morluto/rea/blob/f93a0335a8c1a60bbf6debdca16675ba303e4422/README.md), [Frida documentation](https://github.com/morluto/rea/blob/f93a0335a8c1a60bbf6debdca16675ba303e4422/docs/frida-instrumentation.md), and [analysis skill](https://github.com/morluto/rea/blob/f93a0335a8c1a60bbf6debdca16675ba303e4422/.agents/skills/reverse-engineer-anything/SKILL.md).

## 1. Store a password verifier, not a recoverable answer

`releaseguard.passwords.create_password_verifier(password_bytes)` returns exactly `{format, phc}`, with format `open-release-guard-password/v1`. `verify_password(candidate_bytes, document)` checks the candidate. No reversible password is stored in the record.

The fixed Argon2id profile matches RFC 9106’s **second recommended option**:

| Parameter | Value |
| --- | --- |
| Memory | 65,536 KiB / 64 MiB |
| Passes | 3 |
| Lanes | 4 |
| Random salt | 16 bytes |
| Derived verifier | 32 bytes |

Creation accepts 12–1,024 password bytes; verification accepts candidates up to 1,024 bytes. A length floor does not guarantee entropy. The API treats passwords as opaque bytes; the CLI encodes input as UTF-8 without performing text normalization.

The verifier parser accepts only the exact canonical fixed profile. It rejects hostile cost parameters before constructing a KDF, rather than passing arbitrary PHC parameters to an expensive backend. This bounds one operation; callers still need rate and concurrency limits. An unavailable Argon2id backend fails rather than silently selecting a cheaper algorithm.

Create the release directories first, then run in an interactive terminal:

```bash
releaseguard password-create --out release/App/password-verifier.json
releaseguard password-check release/App/password-verifier.json
```

The CLI uses `getpass`, or `RELEASEGUARD_USER_PASSWORD` supplied by a trusted secret-management process for automation. It has no plaintext password command-line option. Do not put real passwords into shell commands, logs, or committed scripts. This variable is separate from `RELEASEGUARD_PASSPHRASE`, which unlocks issuer signing keys. The Argon2id implementation is a Python API/CLI; a native verification SDK has not been implemented.

A mismatch returns exit code 3; invalid input or an unsupported backend is a tool error. Output files must be new. Protect verifier integrity: replacing the verifier can change which password is accepted. The record’s salt and verifier are not secret keys, but possession enables offline guesses. Even a strong password remains guessable in principle, and a local attacker can patch the check. These commands do not automatically insert password enforcement into a C/C++ application or derive an asset key from the user password.

## 2. Seal data with an external random key

Run these examples from a separate packaging workspace outside the source checkout. Prepare trusted directories outside Git and the distributable release for keys and plaintext work files. The following directory layout is illustrative; `work/model.bin` must contain your own data, at most **1 MiB**:

```bash
mkdir -p external work release/App
releaseguard asset-keygen --out external/asset.key
releaseguard asset-seal work/model.bin --key-file external/asset.key --product App --release 1 --purpose model --asset-id model-main --out release/App/model.sealed.json
releaseguard asset-open release/App/model.sealed.json --key-file external/asset.key --product App --release 1 --purpose model --asset-id model-main --out work/model-opened.bin
```

`external/asset.key` is a **raw 32-byte random binary file**, not Base64, a password, a PEM signing key, or the public CMake build seed. Keep it outside the repository and release bundle. Key generation refuses existing files; its parent directory must already exist and be trusted. Use suitable directory permissions and Windows ACLs. The API rejects linked or changed key files, but those checks do not replace control of the surrounding directories.

Python entry points are `releaseguard.sealed.seal_asset(plaintext, key, product, release, purpose, asset_id)` and `open_asset(document, key, product, release, purpose, asset_id)`. They accept bytes and a 32-byte master key; this is a bounded in-memory data API, not a streaming model loader.

Each sealing operation generates a 32-byte salt, derives a 32-byte per-asset key with HKDF-SHA256, and generates a 12-byte AES-256-GCM nonce. The full 16-byte tag is appended to the ciphertext. Random values are generated internally, not supplied by the caller. The JSON envelope contains exactly:

```text
format, salt, nonce, ciphertext
```

`format` is `open-release-guard-sealed-asset/v1`. Binary values use canonical padded standard Base64; `ciphertext` includes the authentication tag. The envelope does not contain the master key or define its own trusted product/version identity.

All four context values—`product`, `release`, `purpose`, and `asset_id`—must come from trusted caller expectations and must be supplied again when opening. They are bound into both key derivation and authenticated associated data. Do not read an attacker-controlled package or download response and adopt its advertised context as the expected identity. The implementation validates bounded NFC identifiers; use the same exact values at both ends.

Authentication failure returns no plaintext from `open_asset`. The CLI authenticates the entire bounded asset before creating the new plaintext output and refuses to overwrite an existing path. Opening deliberately creates a plaintext file; keep that output outside the published release. No asset is executed.

These protections apply while the master key remains outside an attacker’s reach. They do not prevent a key holder from opening or creating assets, a controlled process from observing decrypted bytes, or replay of another valid asset under an identical trusted context. An expected release value needs a separate trusted update/freshness policy. Python and its cryptographic buffers have no memory-erasure guarantee.

## 3. Gate the final release directory

The artifact argument remains a PE or ELF file. `--root` selects the final distributable directory and must contain that artifact. A strict example is provided in [policy-strict-release.json](../examples/policy-strict-release.json); adapt its filenames and rules to your own build:

```bash
releaseguard gate release/App/App.exe --policy /path/to/anti-rea-forge/examples/policy-strict-release.json --root release/App
```

| New policy field | Meaning |
| --- | --- |
| `forbid_path_components` | Reject exact, case-insensitive path-component names, including forbidden directory names; these are not globs |
| `forbid_file_sha256` | Reject known whole-file SHA-256 values, written as 64 lowercase hexadecimal characters |
| `allowed_release_files` | Require the exact set of release-relative file paths: both missing and extra files fail |
| `scan_release_literals` | When true, scan every release file for `forbid_literals`, not only the main artifact |
| `max_release_scan_bytes` | Bound aggregate bytes read for release-wide literal/hash scans; default 64 MiB, accepted range 1–536,870,912 bytes |

**Explicitly including any of these five fields requires `--root`, even if its value is `false` or an empty list.** A CMake post-build gate that does not pass `--root` is not a substitute for this final-directory step. `allowed_release_files` must be nonempty when supplied. Unknown fields are rejected.

The supplied example fixes `allowed_release_files` to `["MyApp.exe", "model.sealed.json"]`; these filenames must be replaced with your exact real inventory. It does not learn an allowlist automatically. For the illustrated layout, replace that field with `"allowed_release_files": ["App.exe", "model.sealed.json", "password-verifier.json"]`. The old-file hash list starts empty: populate `forbid_file_sha256` from trusted known-old files when applicable. Do not invent hashes or assume the example already excludes every historical artifact.

Release-wide scans cover UTF-8, UTF-16 LE/BE, and UTF-32 LE/BE. Exceeding the read budget fails the check; a large or unreadable file is not silently accepted. An exact SHA-256 rule catches only the same bytes, and literal rules catch only declared byte encodings. The gate does not decompress archives, prove that source code is absent, or identify every secret. Use a clean staging directory and a deliberate allowlist; do not include key files, original source/answers, plaintext asset copies, or old debugging artifacts. Keep the policy itself outside the exact allowlisted release unless it is intentionally included.

The release root and its ancestor directories must remain under trusted builder control and must not be modified concurrently with scanning. Existing `lstat`/`fstat` and inventory checks detect ordinary changes; they are not an atomic filesystem snapshot or a guarantee that malicious parent-directory races can never cause reads outside the root. A gate also cannot prevent replacement after checking. Pair it with a signed manifest and trusted installation/loading controls; it does not lock down an arbitrary hostile filesystem.

## 4. Pair encryption with a signed manifest

AES-GCM authentication is symmetric: **anyone with the AES master key can construct an authenticated asset for the same context**. It does not identify your publisher independently of that shared key. Use a separate issuer-held Ed25519 key and a pinned trusted public key for release identity.

After the native build and Authenticode signing, finish the sealed files and verifier records, run the release-root gate, and sign the final byte inventory:

```bash
releaseguard manifest-sign --root release/App --private external/issuer-private.pem --product App --release 1 --out App-1.manifest.json
releaseguard manifest-verify App-1.manifest.json --root release/App --public issuer-public.pem --product App --release 1
```

Create issuer keys with the existing `keygen` workflow; an asset master key is not an Ed25519 key. Keep the signing private key and its passphrase only in the controlled issuer environment. Pin the trusted verification public key or fingerprint independently of the downloaded bundle. Keep the manifest outside the inventoried root. Any later file change requires a new manifest; neither a manifest nor GCM supplies reliable offline revocation, trusted time, or rollback prevention by itself.

## Verification and scope

The [crypto boundary experiment](../benchmarks/crypto_boundary.py) is an implementation-verification entry point; consult the [2026-10-20 generated record](results/crypto-boundary-2026-10-20.json) for observed results. This document does not assert a test count, recovery duration, or new REA resistance score. Existing [v0.2 recovery evidence (Chinese)](testing-2026-10-15.zh-CN.md) remains a failure result for the earlier synthetic sample.

The useful changes are avoiding a recoverable stored password, separating an asset key from published code/data, authenticating trusted asset identity, and excluding known unwanted release contents. They do not automatically alter every business application, prevent credential observation at input, or stop functional reimplementation. If the core requirement is to keep an algorithm or permanent credential confidential from a machine owner, keep that capability on a controlled server and enforce authorization there. Review the [security model (Chinese)](../SECURITY.md) before deployment.

## Primary references

- [cryptography 50.0.2: Argon2id and HKDF](https://cryptography.io/en/50.0.2/hazmat/primitives/key-derivation-functions/): different KDFs serve password verification and derivation from a random master key; HKDF is not a password-storage function.
- [cryptography 50.0.2: authenticated encryption](https://cryptography.io/en/50.0.2/hazmat/primitives/aead/): AESGCM nonce requirements, full tags, and authentication failure behavior.
- [RFC 9106, section 4](https://www.rfc-editor.org/rfc/rfc9106.html#section-4): the selected second recommended Argon2id profile.
- The fixed official REA source links above describe the analysis threat model; source review is not an end-to-end experiment against this release.
