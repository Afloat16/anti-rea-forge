# Prepared submission: [Open Source] Anti-REA Forge — native hardening experiments

**Status: NOT SUBMITTED.** The GitHub integration returned HTTP 403. No public issue was created. This file is a reviewable draft, not evidence of publication. Recheck rules and duplicates before submitting through an authorized account.

Suggested issue title: [Open Source] Anti-REA Forge — native hardening experiments

---

### Project URL
https://github.com/Afloat16/anti-rea-forge

### Category
Python

### Project Title
Native hardening with testable boundaries

### Project Description
An MIT alpha toolkit for native release hardening and runtime-boundary research. It combines CMake/PE/ELF gates, guarded buffers and one-use server capabilities, with reproducible tests and published failures. It is not unbreakable DRM.

### Highlights
- CMake/C++17 integration and configurable read-only PE/ELF release gates, alongside cryptographic release and authorization tools.
- v0.4 adds an explicitly owned sensitive buffer and exact-request Ed25519 server capabilities with durable atomic replay rejection.
- The project publishes failed protection experiments, including recovery of its own synthetic masked secret. It separates a blocked experiment from a protection result.
- Local implementation record: 331 tests run, 330 passed, one mapping-inspection skip. Linux and Windows/MSVC CI passed at the linked commit. Synthetic 32-thread and six-process replay probes each allowed one consumption. These are functional checks, not a cracking-resistance rate.
- MIT alpha, Python 3.10+, native components for Linux/Windows with C++17/CMake. Server authorization requires actual service integration. Live client plaintext remains observable. Frida instrumentation and the complete REA workflow have not been completed in the test environment.

### Example Code
```bash
git clone https://github.com/Afloat16/anti-rea-forge.git
cd anti-rea-forge
python -m pip install -e .
python benchmarks/dynamic_boundary.py --out dynamic-boundary.json
```

### Screenshots or Demo Videos
Official repository banner (not an execution screenshot):
https://raw.githubusercontent.com/Afloat16/anti-rea-forge/d3195d4a7cf6fce0861e2149b0cb2949b2dc90d1/assets/anti-rea-forge.svg

Validation: https://github.com/Afloat16/anti-rea-forge/blob/main/docs/testing-v0.4-2026-10-20.md

Disclosure: I maintain the project; this original submission was prepared with AI assistance. Exact-name GitHub submission and public-index searches found no existing recommendation; the website's dynamic search result could not be fully verified. Inclusion remains for editorial review.
