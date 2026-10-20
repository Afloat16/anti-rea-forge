# Prepared submission: 【开源自荐】Anti-REA Forge：把原生软件防护接入构建与服务端

**Status: NOT SUBMITTED.** Previous submission attempt returned HTTP 403. Recheck access, destination rules and duplicates before submitting. This notice is not part of the proposed post.

Suggested issue title: 【开源自荐】Anti-REA Forge：把原生软件防护接入构建与服务端

---

项目：Anti-REA Forge

仓库：https://github.com/Afloat16/anti-rea-forge

English summary: An MIT toolkit combining native release hardening, guarded C++ memory and request-bound server authorization.

Anti-REA Forge 把原生软件发布加固、敏感数据管理和服务端授权组件放进了同一个开源工具箱，适合 C/C++ 开发者、发布工程师和软件保护研究者接入自己的工作流。

它的实用之处是可以逐层采用：

- **接入现有构建：** 通过 CMake 函数为目标启用构建选项，并按策略检查 PE/ELF 产物。
- **检查完整发布包：** 对声明文字、调试/符号元数据、旁文件、目录清单和已知制品哈希进行配置化检查。
- **明确管理敏感内存：** C++17 缓冲区提供守卫页、受检锁页、清理与 Linux core dump 排除。
- **复用密码学组件：** 签名发布清单、Argon2id 口令校验、外部密钥 AES-GCM 资产，以及在可信服务端使用的请求绑定 Ed25519 一次性授权与持久防重放。

项目提供 CLI、Python API、CMake 组件、可运行示例和中英文设计说明。MIT 许可便于审阅、定制和共同扩展；既能作为原生软件发布流程的工具，也能作为研究保护机制的实验起点。

当前版本为 v0.4.0 alpha。工具链要求 Python 3.10+；原生组件面向 Linux 与 Windows/MSVC，使用 C++17/CMake。

中文接入：https://github.com/Afloat16/anti-rea-forge/blob/main/docs/runtime-protection.zh-CN.md

共建入口：https://github.com/Afloat16/anti-rea-forge/issues/1

作者关联：本人是项目维护者，欢迎开发者和安全研究者一起完善接入、平台兼容和保护组件。
