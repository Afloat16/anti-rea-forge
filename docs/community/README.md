# Build and challenge Anti-REA Forge

Anti-REA Forge is an **MIT alpha lab for native release hardening and software-protection boundary experiments**. It combines CMake/C++17 components, PE/ELF release gates, cryptographic release tools and project-owned reproducible samples. We welcome developers and reverse-engineering researchers who can improve an implementation or disprove a protection claim with evidence.

The current implementation is v0.4.0. Earlier static and runtime analysis recovered its synthetic test secrets; those failures remain public. A blocked Frida experiment is not a protection pass. No general cracking-resistance probability is available.

## Start with one reproducible task

```bash
git clone https://github.com/Afloat16/anti-rea-forge.git
cd anti-rea-forge
python -m pip install -e .
python benchmarks/dynamic_boundary.py --out dynamic-boundary.json
```

Python 3.10+ is required. Native examples additionally need a supported C++17 compiler and CMake. The benchmark creates its own synthetic credentials and temporary state; its successful result is a functional check, not a REA resistance score.

| Contribution | Useful first result |
| --- | --- |
| REA / Frida reproduction | Record the exact versions, owned sample hash, initial information, commands, blocked stage or verified recovery; never count an environment error as protection |
| Windows DLL compatibility | A minimal owned DLL and caller demonstrating exports, calling convention and unchanged behavior before/after build integration |
| Native memory review | A reproducible failure-path or lifetime regression; verify owned memory before release, never read freed storage |
| Trusted-service integration | Review authenticated request binding, durable replay authority and business-transaction behavior; keep production credentials out of reports |
| Documentation | Improve one runnable command, translation or platform requirement and record how you checked it |

Use the [community issue](https://github.com/Afloat16/anti-rea-forge/issues/1) to find collaborators, or open an experiment/proposal through [the repository's templates](https://github.com/Afloat16/anti-rea-forge/issues/new/choose). Small PRs are welcome. Private security issues follow [SECURITY.md](../../SECURITY.md).

## Read, reproduce and share

- [Technical project story](PROJECT_STORY.md): why release hygiene, memory ownership and server authority are separate boundaries.
- [Reusable English and Chinese introductions](SHARE_COPY.md): author/AI disclosures and limitations included; use only where the destination permits the content.
- [Outreach status and channel rules](OUTREACH.md): actual submissions, blocked actions and unsubmitted opportunities are recorded separately.
- [Runtime design and research](../runtime-protection.md) · [中文运行时设计](../runtime-protection.zh-CN.md).
- [v0.4 validation](../testing-v0.4-2026-10-20.md) · [passing implementation CI](https://github.com/Afloat16/anti-rea-forge/actions/runs/39365796755).
- [Contribution guide（中文）](../../CONTRIBUTING.md) · [roadmap（中文）](../ROADMAP.zh-CN.md).

分享时请保留真实边界与作者关联，在允许自荐及 AI 辅助内容的区域发布。不要把材料复制到禁止 AI 投稿的社区，也不要到无关 Issue、评论或私信中散发广告。欢迎有证据的质疑和恢复成功的报告。
