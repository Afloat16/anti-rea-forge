# Put software protection into your engineering workflow

**Anti-REA Forge combines native release hardening, sensitive-memory management and request authorization in one MIT-licensed open-source toolkit.** It is maintained by [Afloat16](https://github.com/Afloat16) and welcomes developers and researchers who want practical software-protection components they can inspect, integrate and extend.

As AI-assisted reverse-engineering workflows become easier to use, software developers need equally accessible ways to improve their own release process and protection architecture. Anti-REA Forge brings that work into familiar tools: CMake, C++17, Python, PE/ELF inspection and established cryptography.

## Make release policy part of the build

Release quality involves the complete package: executable files, supporting assets and everything shipped alongside them. Anti-REA Forge lets teams turn concrete release requirements into checks that run before distribution.

Its CMake integration enables Release optimization and LTO, while configurable PE/ELF gates inspect declared literals, debug/symbol metadata and forbidden sidecars. Whole-release policies can check exact file inventories, source/backup path components and known old artifact hashes. The result is a repeatable build step that gives developers actionable findings before they ship.

This makes the toolkit useful for native application developers, release engineers and teams that want a consistent review of their EXE, DLL or ELF artifacts.

## Give sensitive native data an explicit lifetime

The C++17 `releaseguard::secure_buffer` provides a dedicated allocation for sensitive data. It brings guarded pages, checked memory locking and clearing before release into an object with clear ownership. Linux deployments can also request core-dump exclusion for those pages.

Applications choose which OS protections are required and can inspect the actual status. This supports direct integration into native code that handles keys, authorization material or other short-lived sensitive data. Produce data directly into the owned buffer where practical, use it within the intended operation and let the object's lifetime handle cleanup.

The [runtime guide](../runtime-protection.md) covers the API, supported platforms and application integration.

## Bind authorization to the real request

Some protection decisions belong in a trusted service. Anti-REA Forge provides a capability API for that architecture: Ed25519 signatures bind a subject, audience, product, operation and the exact request bytes, with a configurable lifetime of up to 300 seconds.

A persistent SQLite replay store atomically consumes each authorization once and maintains trusted-clock state. The issuer key, replay authority and protected operation are integrated into the service, giving developers a focused building block for constrained actions and one-use request permissions.

CLI commands support issuing capabilities, initializing replay state and consuming a request authorization. The same functionality is available through Python APIs for integration with an application's authentication and business logic.

## Add practical cryptographic building blocks

The toolkit also includes fixed-profile Argon2id password verifiers, external-key AES-256-GCM asset sealing, Ed25519-signed release manifests and portable offline licenses.

These components address distinct engineering tasks: storing password verifiers, authenticating data assets, checking a release's inventory and issuing signed permissions. Keeping them together with build integration and runnable examples gives developers a convenient starting point for a broader software-protection workflow.

## Try it in a few commands

Python 3.10 or later is required. The distribution is named `open-release-guard`; the CLI and import package are `releaseguard`.

```bash
git clone https://github.com/Afloat16/anti-rea-forge.git
cd anti-rea-forge
python -m pip install -e .
python benchmarks/dynamic_boundary.py --out dynamic-boundary.json
```

The benchmark creates its own temporary credentials and replay state. Use a new output path for each run. Native build examples additionally need a supported C++17 compiler and CMake.

Explore the [native integration guide](../native-build.zh-CN.md), [runtime design](../runtime-protection.md) and [Chinese runtime guide](../runtime-protection.zh-CN.md) to choose the components that fit your application. Linux and Windows/MSVC CI exercise the project's implementation and native build paths.

## Build the next release with us

Anti-REA Forge is designed to be worked on in public. C++ developers can improve memory components and build integration. Python contributors can refine APIs and CLI workflows. Windows users can strengthen native interoperability. Reverse-engineering researchers can contribute new specimens, experiments and protection ideas.

Small contributions are welcome: improve an example, make one integration easier, review a focused component or propose a concrete feature. Start with the [community guide](README.md), [contribution guide](../../CONTRIBUTING.md) or [community discussion](https://github.com/Afloat16/anti-rea-forge/issues/1).

**Fork the project, try a component and help shape a practical open-source software-protection toolkit.**
