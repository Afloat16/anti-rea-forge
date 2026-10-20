# Prepared submission: [Open Source] Anti-REA Forge — native release hardening

**Status: NOT SUBMITTED.** Previous submission attempt returned HTTP 403. Recheck access, destination rules and duplicates before submitting. This notice is not part of the proposed post.

Suggested issue title: [Open Source] Anti-REA Forge — native release hardening

---

### Project URL

https://github.com/Afloat16/anti-rea-forge

### Category

Python

### Project Title

Native release hardening in one toolkit

### Project Description

An MIT toolkit for hardening native software releases. It combines configurable PE/ELF checks, guarded C++ memory and signed request authorization, giving developers reusable components and runnable examples in one project.

### Highlights

- Bring release protection into the build: CMake integration applies native build options and enforces configurable PE/ELF artifact policies.
- Inspect the complete release package: check declared literals, metadata, sidecar files, expected file inventories and known artifact hashes according to an explicit policy.
- Give sensitive native data an owned lifecycle with C++17 guarded buffers, checked locking, clearing and Linux core-dump exclusion.
- Add cryptographic building blocks: signed release manifests, Argon2id password verifiers, external-key AES-GCM assets and exact-request Ed25519 capabilities with durable replay rejection for trusted services.
- Start from runnable examples and bilingual documentation. MIT licensing makes the code straightforward to inspect, adapt and extend with the community.
- Current version: v0.4.0 alpha. Python 3.10+; native components target Linux and Windows/MSVC with C++17/CMake.

### Example Code

```bash
git clone https://github.com/Afloat16/anti-rea-forge.git
cd anti-rea-forge
python -m pip install -e .
python -m releaseguard native-init --out generated
```

### Screenshots or Demo Videos

Official repository banner:
https://raw.githubusercontent.com/Afloat16/anti-rea-forge/d3195d4a7cf6fce0861e2149b0cb2949b2dc90d1/assets/anti-rea-forge.svg

Runtime design and examples:
https://github.com/Afloat16/anti-rea-forge/blob/main/docs/runtime-protection.md

Maintainer submission: I maintain Anti-REA Forge and welcome contributors working on native development, release engineering and security research.
