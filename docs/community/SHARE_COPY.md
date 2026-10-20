# Anti-REA Forge: project introductions

Reusable copy for project showcases, software directories and developer communities. Check the destination's current submission rules and use the disclosure it requires. Project facts refer to **v0.4.0**.

## English project introduction

**Anti-REA Forge puts native release hardening, sensitive-memory management and request authorization in one open toolkit.**

The MIT-licensed project helps C/C++ and Python developers bring software-protection checks into everyday engineering. Integrate CMake build components, inspect PE/ELF artifacts, enforce a release policy, manage sensitive C++ allocations and add request-bound authorization to a trusted service.

- **Catch avoidable release exposure:** check declared literals, debug/symbol metadata, sidecar files and the exact release inventory before shipping.
- **Control sensitive native memory:** C++17 buffers provide guarded pages, checked locking, clearing before release and Linux core-dump exclusion.
- **Authorize the actual operation:** short-lived Ed25519 capabilities bind the subject, audience, product, operation and exact request bytes; persistent SQLite state provides atomic one-use consumption.
- **Use established cryptography:** Argon2id password verifiers, external-key AES-256-GCM assets and signed release manifests give developers practical building blocks.
- **Explore and extend:** public examples, reproducible experiments, English/Chinese guides and Linux/Windows CI make the implementation easy to inspect and contribute to.

I maintain the project and welcome contributors in C++, Python, Windows, build engineering and reverse-engineering research. Try an example, improve an integration or bring a focused idea for the next release.

[Repository](https://github.com/Afloat16/anti-rea-forge) · [Get started](README.md) · [Runtime design](../runtime-protection.md) · [Join the community](https://github.com/Afloat16/anti-rea-forge/issues/1)

## 中文项目介绍

**逆向工具在进化，软件保护也值得拥有一套开源工程工具链。**

Anti-REA Forge 将原生发布加固、敏感内存管理、密码学工具和服务端请求授权集中到同一个项目，帮助 C/C++ 与 Python 开发者把保护措施接入构建和业务流程。项目采用 MIT 协议，提供中英文指南、示例和可复现实验，欢迎一起开发。

- **发布前把关：** CMake 接入与 PE/ELF 门禁检查声明文字、调试/符号信息、旁文件和完整发布目录，让发布策略进入构建流程。
- **管理敏感内存：** C++17 缓冲区支持守卫页、受检锁页、释放前清理及 Linux core dump 排除。
- **让授权绑定实际操作：** Ed25519 短期能力凭证绑定主体、产品、操作及请求字节，配合持久 SQLite 状态原子消费一次性授权，接入可信服务端。
- **现成密码学组件：** Argon2id 单向口令校验、外部密钥 AES-256-GCM 资产封装，以及签名发布清单与离线许可证。
- **方便学习与二次开发：** Python CLI、C++ 组件、真实构建示例及 Linux/Windows CI，适合开发者接入，也适合研究者扩展和验证新想法。

我是项目维护者，欢迎 C/C++、Python、Windows、构建工程和逆向研究方向的朋友参与。从跑一个示例、改一处文档或提交一个小 PR 开始，一起把开源软件保护工具做得更实用。

[项目仓库](https://github.com/Afloat16/anti-rea-forge) · [共建入口](README.md) · [中文运行时设计](../runtime-protection.zh-CN.md) · [参与讨论](https://github.com/Afloat16/anti-rea-forge/issues/1)

## Short English social copy

Anti-REA Forge brings C++ memory hygiene, PE/ELF release gates and request-bound server authorization into one MIT open-source toolkit. Built for developers who want software protection in their engineering workflow. Contributors welcome!

https://github.com/Afloat16/anti-rea-forge

## 中文社交短文案

Anti-REA Forge 开源共建：把 C++ 敏感内存、PE/ELF 发布门禁、密码学组件和服务端一次性授权接入工程流程。MIT 协议，中英文指南，欢迎开发者与研究者一起开发！

https://github.com/Afloat16/anti-rea-forge

## Software-directory description

Native release hardening, sensitive-memory tools and request-bound server authorization.

## Developer-resource collection pitch

Explore native software-protection techniques through project-owned C++ samples, configurable PE/ELF release checks and runnable request-authorization experiments. Anti-REA Forge combines practical code, documented cryptographic building blocks and English/Chinese integration guides in an MIT-licensed toolkit.

## More about the project

[Project story](PROJECT_STORY.md) · [Runtime guide and research references](../runtime-protection.md) · [Contribution guide](../../CONTRIBUTING.md)
