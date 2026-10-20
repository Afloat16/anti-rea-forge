# Prepared submission: [addtool] Anti-REA Forge

**Status: NOT SUBMITTED.** The GitHub integration returned HTTP 403. No public issue was created. This file is a reviewable draft, not evidence of publication. Recheck rules and duplicates before submitting through an authorized account.

Suggested issue title: [addtool] Anti-REA Forge

---

Link to the tool (official project repository):
[link]https://github.com/Afloat16/anti-rea-forge[/link]

List of tags separated by comma:
[tags]reverse-engineering,security-auditing,hardening[/tags]

Short description:
[short_descr]Native release hardening and reproducible software-protection boundary experiments.[/short_descr]

A bigger description:
[long_descr]Anti-REA Forge is an MIT-licensed alpha toolkit and experiment lab for native software release hardening. Its CMake integration and read-only PE/ELF gates check declared literals, debug/symbol metadata and configured release files. Additional components provide C++17 guarded sensitive buffers with checked locking and clearing, Argon2id password verifiers, external-key AES-GCM data assets, signed release manifests and request-bound Ed25519 server capabilities with persistent atomic replay rejection.

The differentiating material is its reproducible boundary controls and public failure evidence, including successful secret recovery from its own masked sample. It is intended to help developers and security reviewers test what these mechanisms actually establish. It is not a packer, executable virtualizer or demonstrated way to defeat REA/Frida; integrated REA evaluation remains incomplete.

Tooling requires Python 3.10+. Native build/memory components support Linux and Windows/MSVC with C++17/CMake. Server capabilities require integration into a trusted service. Permanent secrets and active plaintext in an attacker-controlled client remain observable.

Disclosure: submitted by the project's maintainer, with AI-assisted preparation. The image is the official repository banner, not a screenshot or evidence of protection.[/long_descr]

Repository image:
[image]https://raw.githubusercontent.com/Afloat16/anti-rea-forge/d3195d4a7cf6fce0861e2149b0cb2949b2dc90d1/assets/anti-rea-forge.svg[/image]
