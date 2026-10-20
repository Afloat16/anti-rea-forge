# Making software-protection claims reproducible

**Publication status:** project-owned repository material. No external submission is recorded here. Reuse only where current community rules permit author self-promotion and AI-assisted content.

**Disclosure:** Anti-REA Forge is maintained by [Afloat16](https://github.com/Afloat16). This write-up was prepared with AI assistance from the project's source and validation records. It describes **v0.4.0**, with CI evidence at commit `d3195d4`.

AI-assisted reverse engineering combines decompilers, scripts, runtime observations and repeated verification. A useful protection experiment should make its assumptions and failures equally easy to inspect.

Anti-REA Forge is an MIT-licensed alpha project for native release hardening and software-protection research. Its C++ components, Python tooling and synthetic experiments are public, including successful recovery of test secrets from earlier protected samples.

Those failures shaped the project. A reversible literal mask can remove an obvious static string while leaving the decoder and runtime value observable. Publishing the source makes that limitation especially clear. The work now focuses on specific exposure paths and authorization boundaries, with explicit checks for what each component actually does.

## Start with the release directory

A release can disclose more than its executable. Debug metadata, internal symbols, backup files, old artifacts and source fragments can provide an easier route than analyzing the latest binary.

Anti-REA Forge includes configurable PE/ELF release gates and CMake integration. A policy can reject declared literals in several encodings, forbidden sidecars or paths, known old file hashes, and unexpected files against an exact inventory. These checks are bounded and configured by the application owner. They are useful release hygiene; passing them does not measure resistance to decompilation.

The Python tools also provide issuer-signed inventories and offline licenses, salted Argon2id password verifiers, and external-key AES-256-GCM data assets. A distributed client holding a decryption key and plaintext remains an observation target. The external-key requirement matters when deciding where the application should hold its secrets.

## Keep owned native memory under explicit control

Version 0.4 adds `releaseguard::secure_buffer`, a C++17 allocation with guard pages, checked page locking and clearing before release. Linux can exclude its pages from ordinary core dumps. The API reports actual protection status and rejects failure of a required protection.

The scope is precise. Guard pages surround a page-rounded allocation, so they do not catch every small overflow. Clearing covers owned pages, including padding, but not registers, caller copies or library-internal buffers. Windows dump exclusion is not implemented. A live function hook can still observe data during legitimate use. Copying a Python `bytes` value into this buffer also leaves the original managed copy to its own lifetime.

## Authorize the actual request on a trusted service

A local “authorized” boolean can be changed in a controlled client. The capability API is designed for a service that independently verifies and performs the restricted operation.

Ed25519 signatures bind the expected subject, audience, product, operation and exact request bytes. Capabilities have a maximum lifetime of 300 seconds. A persistent SQLite store atomically consumes the identifier once and checks a persisted trusted-clock floor. The issuer key, verifier, replay state and handler must remain outside the untrusted client.

This supplies at-most-once authorization consumption. It does not make business side effects exactly once: a crash after consumption can spend the authorization before the work completes. TLS, login, issuance policy and durable business transactions remain integration responsibilities. A stolen valid bearer capability can also win the race for its original permitted request. Restoring old replay state can undermine consumption guarantees.

## Separate verification from resistance claims

The local v0.4 record contains **331 tests: 330 passed and one mapping-inspection check skipped**. [Linux and Windows/MSVC CI](https://github.com/Afloat16/anti-rea-forge/actions/runs/39365796755) passed for the published commit. A synthetic same-token test allowed one consumption across 32 threads; a separate six-process probe allowed one authorization and rejected five replays.

These are functional checks. [Earlier native secret-recovery failures](../testing-2026-10-15.zh-CN.md) remain valid. A [real Frida experiment](../results/frida-buffer-2026-10-20.json) compiled and ran its own control fixture, but spawn and attach failed before any observation completed. Its protection outcome is unassessed. The project has no credible probability of stopping REA.

The [runtime guide](../runtime-protection.md) maps the reviewed REA 6.7.0 source to concrete threats and links five formal 2024–2026 security papers. It distinguishes their design lessons from systems implemented or evaluated here.

## Try a project-owned fixture

The distribution is named `open-release-guard`; its CLI and import package are `releaseguard`. Python 3.10 or later is required.

```bash
git clone https://github.com/Afloat16/anti-rea-forge.git
cd anti-rea-forge
python -m pip install -e .
python -m unittest discover -s tests -v
python benchmarks/dynamic_boundary.py --out dynamic-boundary.json
```

Native checks need an appropriate compiler and CMake; the [validation record](../testing-v0.4-2026-10-20.md) explains platform coverage and skips. The benchmark creates its own temporary synthetic credentials and state. The output path must be new.

Reproducible challenges are welcome, especially a working REA/Frida evaluation environment, Windows DLL compatibility tests, native failure-path review and real service integration feedback. Please use owned or authorized samples and synthetic data. A report that recovers a secret or disproves a claim is a useful contribution.

Start with the [contribution guide](../../CONTRIBUTING.md) and [security model](../../SECURITY.md). Include tool versions, commands, the expected result and a check of the actual outcome. Keep real issuer keys, tokens and customer data out of public reports.
