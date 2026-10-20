# Reusable project introductions

**Publication status:** repository copy only; these texts have not been submitted to external communities. Reuse only where current rules permit creator self-promotion and AI-assisted content. Confirm the destination's rules and keep the affiliation and AI disclosure accurate when adapting a version.

The facts below describe **v0.4.0 / commit `d3195d4`**. Update version, evidence and limitations before using them for a later revision. These introductions do not claim that Anti-REA Forge defeats REA or makes software uncrackable.

## English project introduction

Disclosure: I maintain Anti-REA Forge. This introduction was prepared with AI assistance from the project's code and test records.

Anti-REA Forge is an MIT-licensed alpha project for native release hardening and reproducible software-protection research. It combines CMake/C++17 components, configurable PE/ELF release checks, cryptographic release tools and project-owned synthetic experiments.

Version 0.4 adds an owned sensitive buffer with guarded pages, checked locking, clearing and Linux core-dump exclusion. It also adds service-side Ed25519 capabilities bound to exact requests, with persistent atomic replay rejection. These components require application integration. Live client plaintext remains observable, and single-use authorization is not exactly-once business execution.

The repository publishes successful recovery of earlier synthetic test secrets. Its current Frida attempt was blocked before observation, so no REA resistance rate is claimed. Local implementation checks recorded 330 passes and one skip; Linux and Windows/MSVC CI passed.

Contributors are welcome for runnable REA/Frida evaluations, Windows DLL compatibility, native failure-path review and trusted-service integration. Reproducible failures are useful contributions.

[Repository](https://github.com/Afloat16/anti-rea-forge) · [Design and research sources](../runtime-protection.md) · [Validation](../testing-v0.4-2026-10-20.md)

## 中文项目介绍

作者说明：我是 Anti-REA Forge 的维护者；本文案由 AI 根据项目代码与测试记录辅助整理。

Anti-REA Forge 是面向 REA 等 AI 辅助逆向工具的软件保护实验工程，MIT 开源，目前为 v0.4.0 alpha。欢迎 C/C++、Python、Windows 和逆向研究方向的朋友一起参与。

现有内容包括 CMake 构建接入、PE/ELF 发布门禁、签名清单与离线授权、Argon2id 单向口令校验，以及外部密钥 AES-256-GCM 数据资产。

v0.4 新增两项运行时组件：C++17 敏感缓冲区提供守卫页、受检锁页、释放前清理及 Linux core dump 排除；服务端一次性能力凭证用 Ed25519 绑定主体、audience、产品、操作和实际请求字节，结合持久 SQLite 状态原子拒绝重放。它们需要接入具体业务。

我们也公开失败：此前 Ghidra 静态分析和运行时观察都恢复了自有样本的测试口令；本轮 Frida 因环境问题未完成插桩，没有防 REA 成功率。运行期间的本地明文仍可能被 hook 读取，服务端授权也需要真实认证、签发策略和业务事务。

本地 331 项测试中 330 项通过、1 项跳过；Linux 与 Windows/MSVC CI 已通过。32 线程、6 进程争用同一凭证的合成实验均只有一次获准。这些是功能与边界验证，不是破解抵抗率。

希望一起补齐可用的 REA/Frida 完整评测环境、Windows DLL 调用兼容、原生内存异常路径，以及真实服务端接入。欢迎在自己的或获授权的样本上复现，提交带工具版本、步骤和功能验证的 Issue/PR。恢复成功的证据同样有价值；请勿上传真实密钥、token 或客户数据。

[项目](https://github.com/Afloat16/anti-rea-forge) · [中文运行时设计](../runtime-protection.zh-CN.md) · [验证记录](../testing-v0.4-2026-10-20.md)

## Short English social copy

I maintain Anti-REA Forge (MIT alpha): C++ memory hygiene, release gates and request-bound server authorization, with reproducible failure logs. Live client plaintext remains observable. Contributors welcome. AI-assisted copy.

https://github.com/Afloat16/anti-rea-forge

## 中文社交短文案

我维护的 Anti-REA Forge 已开源：C++ 内存清理、PE/ELF 发布门禁、服务端请求绑定与防重放。MIT alpha，公开失败记录，欢迎一起复现和改进。本地明文仍可被观察。本条由 AI 辅助整理。

https://github.com/Afloat16/anti-rea-forge

## Evidence to retain when sharing

- [Exact passing CI run](https://github.com/Afloat16/anti-rea-forge/actions/runs/39365796755): implementation/build checks, separate from reverse-engineering resistance.
- [v0.4 validation](../testing-v0.4-2026-10-20.md): local counts, concurrency probes and blocked Frida observation.
- [Security model](../../SECURITY.md): controlled-client, memory-copy, replay-state and service-integration limits.
- [Project story](PROJECT_STORY.md): a technical account of the decisions and remaining work.
