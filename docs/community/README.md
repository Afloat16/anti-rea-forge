# Build stronger native releases with Anti-REA Forge

Anti-REA Forge brings **native release hardening, sensitive-memory management and request authorization into one MIT-licensed toolkit**. It combines CMake/C++17 components, PE/ELF release gates, cryptographic tools and runnable samples. Developers and reverse-engineering researchers are welcome to integrate a component, improve an example or help shape the next release.

Use it to check your release package before shipping, give sensitive native data a clear lifetime, or add exact-request permissions to a trusted service. Python APIs, CLI commands and build hooks make it possible to adopt the components that fit your application. The current implementation is **v0.4.0**.

## Start with a runnable example

```bash
git clone https://github.com/Afloat16/anti-rea-forge.git
cd anti-rea-forge
python -m pip install -e .
python benchmarks/dynamic_boundary.py --out dynamic-boundary.json
```

Python 3.10+ is required. Native examples additionally need a supported C++17 compiler and CMake. The benchmark creates temporary credentials and replay state, demonstrating request binding and one-use authorization. Choose a new output path for each run.

| Contribution | Useful first result |
| --- | --- |
| REA / Frida experiments | Add a project-owned sample and reproducible workflow with tool versions, commands and a verifiable result |
| Windows DLL compatibility | A minimal owned DLL and caller demonstrating exports, calling convention and unchanged behavior before/after build integration |
| Native memory review | Improve allocation ownership, cleanup paths, platform support or a focused lifetime regression |
| Trusted-service integration | Review authenticated request binding, durable replay authority and business-transaction behavior; keep production credentials out of reports |
| Documentation | Improve one runnable command, translation or platform requirement and record how you checked it |

Use the [community issue](https://github.com/Afloat16/anti-rea-forge/issues/1) to find collaborators, or open an experiment/proposal through [the repository's templates](https://github.com/Afloat16/anti-rea-forge/issues/new/choose). Small PRs are welcome. Private security issues follow [SECURITY.md](../../SECURITY.md).

## Read, reproduce and share

- [Project story](PROJECT_STORY.md): put release checks, sensitive-memory components and request authorization into your workflow.
- [English and Chinese introductions](SHARE_COPY.md): project highlights and short social copy for relevant communities.
- [Outreach record](OUTREACH.md): published submissions and channel status.
- [Runtime design and research](../runtime-protection.md) · [中文运行时设计](../runtime-protection.zh-CN.md).
- [v0.4 validation](../testing-v0.4-2026-10-20.md) · [passing implementation CI](https://github.com/Afloat16/anti-rea-forge/actions/runs/39365796755).
- [Contribution guide（中文）](../../CONTRIBUTING.md) · [roadmap（中文）](../ROADMAP.zh-CN.md).

欢迎 Star、Fork，把项目分享给关注原生开发、发布工程和软件保护的人。分享时请遵守目标社区的自荐与内容规则，并保留维护者关联；一个有用的示例或一次聚焦的小 PR 都能帮助项目向前发展。
