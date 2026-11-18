# Anti-REA Forge 1.4

[![CI](https://github.com/Afloat16/anti-rea-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/Afloat16/anti-rea-forge/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Afloat16/anti-rea-forge)](https://github.com/Afloat16/anti-rea-forge/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-76d9cb.svg)](LICENSE)

[English](README.md) · [简体中文](README.zh-CN.md) · [下载 v1.4.0](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.4.0) · [升级说明](docs/releases/v1.4.0.md)

**减少逆向工具能从发布物中直接恢复的信息，把私有资料留在发布物之外。**

Anti-REA Forge 将有界发布检查、私有符号/source map 分离、原生数据认证加密与可信服务授权组合起来。Python、CMake/C++ 和 JavaScript 构建复用同一套发布决策，每项保护都配有可复现的正反对照。

| bundle 中的私有内容 | JSON 字符串里的密钥 | 更容易正确接入 |
| --- | --- | --- |
| **3 / 3 种过去放行的源码包装被拦截** | **6 / 6 种实际签名或解密的泄漏被检出** | **初始化即保存引用 · 报告直接给修复动作** |
| 官方 v1.3 放行前缀、后缀与串接；两套真实 REA 仍能读取源码 | 官方 v1.3 全放行；6 个正常对照通过；另 6 个可恢复边界明确拒绝、单独计数 | 验证并保存相对路径，移动项目仍可用；默认 JSON 与 SDK 判定协议保持 |

以上均为自有样本与明确的发布检查。REA 仍可读取普通客户端代码，拒绝发布也不会让已泄漏的密钥变得不可读。正面检出、未支持格式和预算不足分别记录。**3 个操作系统 · 13 个必需 CI 作业**，npm REA 6.9.0 与固定源码分别运行。[内容数据](docs/results/private-content-controls-v1.4.0-rea-6.9.0.json) · [密钥数据](docs/results/stringified-key-recovery-v1.4.0-local.json) · [完整核查](docs/rea-defense-v1.4.0.zh-CN.md) · [发布门禁配置](release-policy.json)

![Anti-REA Forge 原理：可信构建、公开分发、授权使用与独立私有签发方](docs/images/architecture-zh-CN.svg)

## 1.4 的亮点

- **完整私有内容藏进更大的文件也检查。** 添加构建头、尾部换行或串接 bundle，不再绕过已登记的私有文件引用。定位候选后验证整个原始内容，统一覆盖磁盘及已展开 ZIP/ASAR；短引用也不会被跳过。[范围与预算](docs/private-input-content.md)
- **检查再次序列化进 JSON 字符串的密钥。** 沿每条嵌套路径最多额外解析两层容器，再检查受支持的私有 JWK 和已知密钥数组。6 个自有样本经 Node 实际签名或解密，全部正面检出；深度、字节预算与歧义输入另列未完成结果。[消费者实测](docs/results/stringified-key-recovery-v1.4.0-local.json)
- **初始化时就启用所需保护。** `project-init --private-input-file`、`--asset-key-file` 可重复指定，先验证输入再保存正确的相对配置路径。以后 CLI 和 SDK 自动使用这些引用；初始化失败不留下新配置目录。
- **看得懂状态，也知道下一步。** `scan-release`、`check`、`prepare --format text` 展示引用数量、检查完成状态、公开位置和修复动作。零引用明确显示未配置；默认 JSON、退出码和签名旁文件格式保持。[工作流实测](docs/results/usability-controls-v1.4.0-local.json)
- **安装后的新行为也成为发布条件。** wheel、源码包和 SDK 都必须验证包含检查与保存的引用；Python 安装还必须验证字符串密钥拦截和文本报告。既有 Wasm、source map、LLVM、原生工具、授权与 REA 对照继续保留。

[升级说明](docs/releases/v1.4.0.md) · [便携发布接入](docs/portable-release.md) · [安全边界](SECURITY.md)

## 用实测数据说明效果

| 问题 | 实测结果 | 范围与证据 |
| --- | --- | --- |
| 加头、加尾或串接能绕过私有引用吗？ | 官方 v1.3 放行 **3 / 3**；v1.4 以完整内容命中拒绝 **3 / 3** | [npm](docs/results/private-content-controls-v1.4.0-rea-6.9.0.json) / [源码版](docs/results/private-content-controls-v1.4.0-rea-source.json)；实际 REA 读取自有函数，Node 结果一致；等价改写仍单列边界 |
| JSON 字符串中的密钥还可使用吗？ | **6 / 6** 实际签名或解密，全部拒绝；**6 / 6** 正常对照通过 | [官方 v1.3 对照](docs/results/stringified-key-recovery-v1.4.0-local.json)；另 6 个可恢复但未完成检查的拒绝不计入正向检出 |
| 保存保护引用还需手工编辑配置吗？ | **手工编辑配置 0 次**；整体移动后 CLI、SDK 仍执行两类引用检查 | [工作流测量](docs/results/usability-controls-v1.4.0-local.json)；同一条问题 **74 行 JSON → 23 行文本**，含位置和修复动作；这是单样本输出长度，不是扫描提速 |
| 整数常量能暴露已配置资产密钥吗？ | **12 / 12** 经真实 REA 恢复并完成认证解密；v1.2 全放行，v1.3 全拦截 | [npm](docs/results/python-key-recovery-v1.3.0-rea-6.9.0.json) / [源码版](docs/results/python-key-recovery-v1.3.0-rea-source.json)；独立 PYC 与可执行 ZIP 应用均检查；未配置密钥/短整数另列边界 |
| 已去符号的原生程序还会携带私有 IR 吗？ | **会**：`llvm-dis` 从 v1.2 产物恢复 4 个名称、源码路径和算术实现 | [Clang 对照](docs/results/llvm-metadata-recovery-v1.3.0.json)；v1.3 移除该 IR 通道，私有字节、`.text`、动态符号与 3 组运行结果均保留 |
| 私有源码更新后，旧手填摘要会漏检吗？ | **会**；直接引用当前私有文件后，新完整副本被拒绝 | [REA 布局对照](docs/results/private-input-controls-v1.3.0-rea-source.json)：私有源码节点 **1 → 0 → 1**，各侧分析完整；这是文件未下发，不是算法无法推断 |
| PEM 再编码后还能实际签名吗？ | **8 / 8** 签名验证成功；v1.3 全检出，2 个正常对照通过 | [标准消费者](docs/results/encoded-pem-recovery-v1.3.0.json)；另 2 个可恢复的超预算拒绝不计入检出数 |
| 分离后，REA 还能恢复 Wasm 私有名称吗？ | 5 个程序共 **26 → 0 → 26**；43 个数值检查与 3 个失败行为保留 | [npm](docs/results/wasm-corpus-v1.2.0-rea-6.9.0.json) / [固定源码](docs/results/wasm-corpus-v1.2.0-rea-source.json)；标准段字节一致，公开逻辑仍可读取 |
| 不发 source map，精确原文入口是否消失？ | 4 组构建、5 个 bundle 共 **9 → 0 → 9**；生成 JS 字节不变 | [npm](docs/results/source-map-corpus-v1.2.0-rea-6.9.0.json) / [固定源码](docs/results/source-map-corpus-v1.2.0-rea-source.json)；1 份原本就缺失的原文不计入恢复数 |
| 缺失 mappings、移除 name 后还会泄漏吗？ | **会**：2 个不完整 map 仍暴露原文，1 个链接符号样本仍暴露 helper | 实际 v1.1 放行，v1.2 拒绝；没有输出的样本不会被计成“恢复 0 次” |
| 新增的编码密钥恢复后真的有效吗？ | **19 / 19** 可实际解密或签名，v1.2 全部正面识别并拒绝；**2 / 2** 正常对照允许 | 核验官方 v1.1 wheel 的对照与非秘密样本；[逐项数据](docs/results/secret-representation-recovery-v1.2.0.json) |
| 直接嵌入的明文资源能被恢复吗？ | **能**，两款工具均成功 | [Ghidra/IDA 配对实验](docs/results/native-asset-controls.json)中的正对照 |
| 同一流程能恢复外部密钥加密的资源吗？ | **精确恢复 0 次**；逐一测试 Ghidra 的 18,024 个、IDA 的 18,121 个连续 32 字节候选 | 相同自有 i386 样本，分析器已初始化字节与原文件核对 |
| 不小心把真实密钥发出去会怎样？ | **密钥被提取并重放，原始资源成功恢复** | 两款工具均成功；生产发布检查也报告密钥泄露 |
| 修改本地 gate 能补上缺失的密钥吗？ | 明文对照可恢复；加密对照未恢复精确数据 | 真实 gate 补丁和强制 GCM 返回成功的对照，[方法](docs/native-assets.md) |
| 打开 1 MiB 原生资产的耗时？ | **中位数 189.860 微秒**；预热 5 次后测量 25 次；最大值 1,456.005 微秒 | 历史 v0.10、单台 Linux x86-64；含分配/清理，不含密钥交付和进程启动。[全部样本](docs/results/native-asset-cost.json) |
| 下载的 1.4 安装包验证了什么？ | 精确提交、必需 CI 作业、安装包行为和资产哈希 | [Release](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.4.0) 附带 `release-evidence.json`、`installation-report.json` 和 `SHA256SUMS` |

CI 实际执行 Ghidra、编译器、REA CLI/source map、官方 ASAR、GNU binutils、macOS 与 MSVC 对照。历史结果保留日期与失败记录：普通、混淆及仅 VM 的原生样本曾被独立重建，并匹配 **1,081,924 次隐藏求值**；这个失败推动了外部密钥指令封装。[原生代码研究与待验证边界](docs/native-code.zh-CN.md)

## 从发布门禁开始

需要 Python 3.10+。将 [v1.4.0](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.4.0) 的 wheel 安装进选定的虚拟环境，也可在仓库内运行 `python -m pip install .`。命令与 Python 导入名继续保持 `releaseguard`。

```sh
python -m pip install https://github.com/Afloat16/anti-rea-forge/releases/download/v1.4.0/open_release_guard-1.4.0-py3-none-any.whl
python -m releaseguard --version
python -m releaseguard project-init --root dist --product MyApp --out .releaseguard
python -m releaseguard check --config .releaseguard/project.json --format text
```

把应用构建到 `dist`，审阅 `.releaseguard/policy.json`，将私有符号、密钥和签名材料保存在该目录之外。需要保护现有私有输入时，在初始化命令追加 `--private-input-file service/private_quote.py` 和/或 `--asset-key-file issuer/asset.key`，引用文件须已存在；未配置引用会明确显示。检查失败返回非零退出码；`prepare` 扫描并签名不可变的暂存目录，将证据写到发布目录外。[完整流程](docs/portable-release.md)

### JavaScript / TypeScript

```sh
npm install https://github.com/Afloat16/anti-rea-forge/releases/download/v1.4.0/anti-rea-forge-releaseguard-1.4.0.tgz
```

```js
import { createReleaseGuard } from "@anti-rea-forge/releaseguard";
const guard = createReleaseGuard({ python: process.env.RELEASEGUARD_PYTHON });
const report = await guard.checkProject({ config: ".releaseguard/project.json" });
process.exitCode = report.exitCode;
```

`RELEASEGUARD_PYTHON` 应指向已安装内核的虚拟环境解释器绝对路径。SDK 压缩包通过 GitHub Release 分发，不表示已发布到 npm registry。[SDK 指南](packages/releaseguard/README.zh-CN.md)

## 按保护目标选择接入方式

| 目标 | 接入 | 状态 |
| --- | --- | --- |
| 检测发布泄露与打包歧义 | [便携发布门禁](docs/portable-release.md) | 跨平台、由明确策略控制 |
| 防止声明的私有服务源码/配置误发给客户端 | [私有服务示例](examples/private_service) | 完整内容包含检查，扫描至签名复核 |
| 没有外部密钥时保护选定的原生数据 | [原生资产](docs/native-assets.md) | C++17/OpenSSL，认证上下文绑定 |
| 不向客户端交付私有 source map 与调试/类型信息 | [Source map](docs/private-source-maps.md)、[ELF 符号](docs/private-elf-debug.md)、[Wasm](docs/private-wasm-debug.md) | 受控输入的公开/私有分离 |
| 在可信代码中执行敏感操作 | [服务端能力凭证](docs/runtime-protection.zh-CN.md)、[分析网关](docs/analysis-authorization.md) | 需要已认证身份、固定策略与重放存储 |
| 加密选定的 VM 指令存储 | [原生代码](docs/native-code.zh-CN.md) | **实验性** LLVM 18 / Linux x86-64 标量整数子集 |

## 信任边界

发布扫描核对被检查字节是否满足配置规则，不会让 Ghidra、IDA、REA、Frida 或独立文件读取器失效。合法运行期间，进程可能持有密钥与明文；分发的代码和公开 helper 仍可观察；被修改的本地客户端不能决定服务端权限。发布目录、解释器、策略、密钥和重放状态必须可信。未知编码、未支持格式也不能被解释成通用防破解保证。

1.x 保持已有 v1 签名文档格式，以及 CLI/导入名。它尚未经过独立安全审计；实验性原生转换有明确范围。[安全政策](SECURITY.md) · [升级说明](docs/releases/v1.4.0.md) · [历史恢复失败记录](docs/testing-2026-10-15.zh-CN.md)

## 复现与贡献

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
npm test --prefix packages/releaseguard
# 先设置 RELEASEGUARD_PYTHON 为已安装内核的解释器，再运行真实 CLI 集成：
npm run test:integration --prefix packages/releaseguard
```

CI 固定外部编译器/分析器输入，并将关键对照设为必需。缺失的本地工具会记为跳过，不算执行成功。欢迎提交附带小型自有样本和复现步骤的改进。[贡献指南](CONTRIBUTING.md) · [MIT 许可证](LICENSE)
