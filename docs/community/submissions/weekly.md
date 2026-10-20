# Prepared submission: 【开源自荐】Anti-REA Forge：可复现的软件保护边界实验与发布加固

**Status: NOT SUBMITTED.** The GitHub integration returned HTTP 403. No public issue was created. This file is a reviewable draft, not evidence of publication. Recheck rules and duplicates before submitting through an authorized account.

Suggested issue title: 【开源自荐】Anti-REA Forge：可复现的软件保护边界实验与发布加固

---

项目：Anti-REA Forge
仓库：https://github.com/Afloat16/anti-rea-forge

English summary: An MIT alpha lab for native release hardening and reproducible software-protection boundary experiments.

这是我维护的开源软件保护实验工具，面向 AI 辅助逆向下可验证的防护边界。它提供 CMake/C++17 构建组件、PE/ELF 发布检查、敏感缓冲区和绑定实际请求的一次性服务端授权。

项目公开失败记录：自有样本的测试口令曾被静态和运行时分析恢复；Frida 插桩受测试环境阻塞，尚无完整 REA 评测或防破解成功率。v0.4 本地 331 项检查中 330 通过、1 跳过，Linux 和 Windows/MSVC CI 通过；32 线程和 6 进程的合成重放实验均只有一次获准。这些是功能验证，不能外推为抵抗率。

中文设计：https://github.com/Afloat16/anti-rea-forge/blob/main/docs/runtime-protection.zh-CN.md
验证：https://github.com/Afloat16/anti-rea-forge/blob/main/docs/testing-v0.4-2026-10-20.md
CI：https://github.com/Afloat16/anti-rea-forge/actions/runs/39365796755

欢迎 C++、Python、Windows 与逆向研究者复现和改进。当前为 alpha，需要业务集成。
关联披露：本人是维护者，本投稿由 AI 辅助整理，供编辑判断是否适合收录。
