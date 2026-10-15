# GitHub 首发内容

以下是仓库创建与首发时使用的具体文案，创建与推送成功后以 GitHub 页面状态为准。本文件不表示仓库已经发布。

| 项目 | 内容 |
| --- | --- |
| 所属账号 | Afloat16 |
| 仓库名 | `anti-rea-forge` |
| 可见性 | Public |
| 展示名 | Anti-REA Forge｜反逆向共建计划 |
| 口号 | 逆向有 AI，防护也要进化。 |
| 许可 | MIT |
| 初始分支 | `main` |

## About 简介

🛡️ 面向 REA 等 AI 逆向工具的软件防护共建工程：C/C++ 编译加固、PE/ELF 发布门禁与可复现对抗实验。公开失败，欢迎一起开发、验证与改进。

## 建议 Topics

`software-protection`、`reverse-engineering`、`anti-reverse-engineering`、`rea`、`ghidra`、`cpp`、`cmake`、`windows`、`security-research`、`open-source`

## 共建招募 Issue 草稿

标题：**🛠️ 共建招募｜一起给 REA 出一道更难的公开考题**

逆向有 AI，防护也要进化。

我发起 Anti-REA Forge，希望和大家一起把面向 REA 等 AI 辅助逆向工具的软件保护做成一个可验证、可复现的开源工程。

目前已有 C/C++ 编译接入、文字静态掩码、PE/ELF 发布门禁、签名发布清单和离线授权工具。本地 155 项功能与集成测试通过；同时，我们的自有样本已被独立 Ghidra 和运行时观察成功恢复测试口令。这些失败证据也在仓库里，欢迎复现和挑战。REA 整合分析受测试宿主环境阻塞，尚未完成；我们没有“不可破解”或防破解概率承诺。

第一批希望一起做的事：

- 跑通完整 REA/Ghidra 实验，保留可复现证据。
- 补齐 Windows/MSVC EXE/DLL 与调用方兼容性测试。
- 讨论并验证新的防护设计，同时检查功能、性能和恢复成本。
- 改善文档、错误提示和新手接入流程。

会开发、会逆向、会测试或愿意帮忙复现，都欢迎加入。Fork 后提交一个小 PR，或通过 Issue 模板告诉我你想做什么。请先读 [贡献指南](../CONTRIBUTING.md) 和 [路线图](ROADMAP.zh-CN.md)，只使用自己拥有或明确获授权的样本。

欢迎 Star、Fork，也欢迎把有证据的质疑留下来。希望和你一起把下一次实验做得更好。

此草稿若发布为仓库根层级 Issue，应将上面两个相对链接改为对应 GitHub `blob/main/` 绝对链接。公开 Issue 不接收生产私钥、客户资料或未协调披露的敏感安全细节，安全问题请按 [SECURITY.md](../SECURITY.md) 处理。
