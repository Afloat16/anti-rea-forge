# Prepared submission: [addtool] Anti-REA Forge

**Status: NOT SUBMITTED.** Previous submission attempt returned HTTP 403. Recheck access, destination rules and duplicates before submitting. This notice is not part of the proposed post.

Suggested issue title: [addtool] Anti-REA Forge

---

Link to the tool (official project repository):
[link]https://github.com/Afloat16/anti-rea-forge[/link]

List of tags separated by comma:
[tags]reverse-engineering,security-auditing,hardening[/tags]

Short description:
[short_descr]Native release hardening, guarded memory and signed request authorization in one toolkit.[/short_descr]

A bigger description:
[long_descr]Anti-REA Forge brings native software release hardening and reusable protection components into one MIT-licensed project. Developers can integrate its CMake functions into an existing build, enforce configurable PE/ELF release policies and inspect the files shipped with an application.

The release gates check declared literals, debug and symbol metadata, sidecar files, release inventories and configured artifact hashes. C++17 sensitive buffers add guarded pages, checked memory locking, explicit clearing and Linux core-dump exclusion. Cryptographic tools provide signed release manifests, Argon2id password verifiers and external-key AES-GCM data assets. Request-bound Ed25519 capabilities with persistent atomic replay rejection support authorization inside a trusted service.

The project includes runnable examples, bilingual design notes and reproducible experiments, making it useful for release engineers, native application developers and software-protection researchers. Its modular Python APIs, CLI and CMake integration offer practical starting points for application-specific protection workflows.

Current version: v0.4.0 alpha. Tooling requires Python 3.10+. Native build and memory components target Linux and Windows/MSVC with C++17 and CMake. Submitted by the project maintainer.[/long_descr]

Repository banner:
[image]https://raw.githubusercontent.com/Afloat16/anti-rea-forge/d3195d4a7cf6fce0861e2149b0cb2949b2dc90d1/assets/anti-rea-forge.svg[/image]
