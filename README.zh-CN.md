# Anti-REA Forge 1.3

[![CI](https://github.com/Afloat16/anti-rea-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/Afloat16/anti-rea-forge/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Afloat16/anti-rea-forge)](https://github.com/Afloat16/anti-rea-forge/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-76d9cb.svg)](LICENSE)

[English](README.md) · [简体中文](README.zh-CN.md) · [下载 v1.3.0](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.3.0) · [升级说明](docs/releases/v1.3.0.md)

**减少逆向工具能从发布物中直接恢复的信息，把私有资料留在发布物之外。**

Anti-REA Forge 将有界发布检查、私有符号/source map 分离、原生数据认证加密与可信服务授权组合起来。Python、CMake/C++ 和 JavaScript 构建复用同一套发布决策，每项保护都配有可复现的正反对照。

| Python 整数密钥 | 再编码的签名私钥 | 私有编译与服务输入 |
| --- | --- | --- |
| **12 / 12 种 REA 可恢复表示被门禁拦截** | **8 / 8 种真实签名私钥泄漏被检出** | **分离嵌入 LLVM IR · 拒绝私有文件副本** |
| 官方 v1.2 全部放行；v1.3 同时拒绝独立 PYC 和可执行 ZIP 应用 | 官方 v1.2 全部放行；2 个非秘密对照仍通过 | 保留原生指令和运行结果；私有输入从扫描到签名持续复核 |

以上均为自有样本与明确的发布检查。REA 仍可读取普通客户端代码，拒绝发布也不会让已泄漏的密钥变得不可读。正面检出、未支持格式和预算不足分别记录。**3 个操作系统 · 13 个必需 CI 作业**，npm REA 6.9.0 与固定源码分别运行。[Python 数据](docs/results/python-key-recovery-v1.3.0-rea-6.9.0.json) · [PEM 数据](docs/results/encoded-pem-recovery-v1.3.0.json) · [完整核查](docs/rea-defense-v1.3.0.zh-CN.md) · [发布门禁配置](release-policy.json)

![Anti-REA Forge 原理：可信构建、公开分发、授权使用与独立私有签发方](docs/images/architecture-zh-CN.svg)

## 1.3 的亮点

- **识别藏在 Python 整数里的已知密钥。** 真实 REA 暴露的常量可还原完整 32 字节资产密钥。新 PYC 有界检查覆盖规范 marshal 整数的有符号/无符号、大小端和引用形式。12 种自有表示均先成功解密，再验证独立 PYC 与 ZIP 应用的发布被拒绝。[Python 实测](docs/results/python-key-recovery-v1.3.0-rea-source.json)
- **清除普通 strip 遗留的 LLVM IR。** `.llvmbc` 仍可能携带私有名称、源码路径和算术实现。ELF 分离器现将符合条件的编译段完整留在私有侧，并核验运行段未变；ELF、PE、Mach-O 审计单列编译元数据，原始/包装 bitcode 明确记为未支持。[真实 Clang / llvm-dis 对照](docs/results/llvm-metadata-recovery-v1.3.0.json)
- **把当前私有源码留在客户端之外。** 配置 `private_input_files` 后，每次读取当前内容指纹，拒绝磁盘或受检 ZIP/ASAR 中的完整副本；`prepare` 在签名和最终检查期间复核输入。新增可接入现有授权 API 的[公开客户端／私有服务示例](examples/private_service)。
- **PEM 外面再包一层编码也检查。** JSON 中的十六进制/Base64、前导说明和真实消费者兼容写法，不再隐藏受支持的私钥标记。8 种表示均完成实际签名并被正面检出；另外 2 个可恢复但超预算的样本明确拒绝，单独计数。[消费者实测](docs/results/encoded-pem-recovery-v1.3.0.json)
- **把新行为落实到安装包门禁。** 新增真实工具对照进入必需 CI；wheel、源码包和打包 SDK 独立安装后验证新边界。Wasm、source map、原生工具、授权与 SDK 既有回归继续保留。

[升级说明](docs/releases/v1.3.0.md) · [便携发布接入](docs/portable-release.md) · [安全边界](SECURITY.md)

## 用实测数据说明效果

| 问题 | 实测结果 | 范围与证据 |
| --- | --- | --- |
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
| 下载的 1.3 安装包验证了什么？ | 精确提交、必需 CI 作业、安装包行为和资产哈希 | [Release](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.3.0) 附带 `release-evidence.json`、`installation-report.json` 和 `SHA256SUMS` |

CI 实际执行 Ghidra、编译器、REA CLI/source map、官方 ASAR、GNU binutils、macOS 与 MSVC 对照。历史结果保留日期与失败记录：普通、混淆及仅 VM 的原生样本曾被独立重建，并匹配 **1,081,924 次隐藏求值**；这个失败推动了外部密钥指令封装。[原生代码研究与待验证边界](docs/native-code.zh-CN.md)

## 从发布门禁开始

需要 Python 3.10+。将 [v1.3.0](https://github.com/Afloat16/anti-rea-forge/releases/tag/v1.3.0) 的 wheel 安装进选定的虚拟环境，也可在仓库内运行 `python -m pip install .`。命令与 Python 导入名继续保持 `releaseguard`。

```sh
python -m pip install https://github.com/Afloat16/anti-rea-forge/releases/download/v1.3.0/open_release_guard-1.3.0-py3-none-any.whl
python -m releaseguard --version
python -m releaseguard project-init --root dist --product MyApp --out .releaseguard
python -m releaseguard check --config .releaseguard/project.json
```

把应用构建到 `dist`，审阅 `.releaseguard/policy.json`，将私有符号、密钥和签名材料保存在该目录之外。已知外部密钥配置到 `asset_key_files`，私有源码/配置引用放进 `private_input_files`。检查失败返回非零退出码；`prepare` 扫描并签名不可变的暂存目录，将证据写到发布目录外。[完整流程](docs/portable-release.md)

### JavaScript / TypeScript

```sh
npm install https://github.com/Afloat16/anti-rea-forge/releases/download/v1.3.0/anti-rea-forge-releaseguard-1.3.0.tgz
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
| 防止声明的私有服务源码/配置误发给客户端 | [私有服务示例](examples/private_service) | 当前完整文件指纹，扫描至签名复核 |
| 没有外部密钥时保护选定的原生数据 | [原生资产](docs/native-assets.md) | C++17/OpenSSL，认证上下文绑定 |
| 不向客户端交付私有 source map 与调试/类型信息 | [Source map](docs/private-source-maps.md)、[ELF 符号](docs/private-elf-debug.md)、[Wasm](docs/private-wasm-debug.md) | 受控输入的公开/私有分离 |
| 在可信代码中执行敏感操作 | [服务端能力凭证](docs/runtime-protection.zh-CN.md)、[分析网关](docs/analysis-authorization.md) | 需要已认证身份、固定策略与重放存储 |
| 加密选定的 VM 指令存储 | [原生代码](docs/native-code.zh-CN.md) | **实验性** LLVM 18 / Linux x86-64 标量整数子集 |

## 信任边界

发布扫描核对被检查字节是否满足配置规则，不会让 Ghidra、IDA、REA、Frida 或独立文件读取器失效。合法运行期间，进程可能持有密钥与明文；分发的代码和公开 helper 仍可观察；被修改的本地客户端不能决定服务端权限。发布目录、解释器、策略、密钥和重放状态必须可信。未知编码、未支持格式也不能被解释成通用防破解保证。

1.x 保持已有 v1 签名文档格式，以及 CLI/导入名。它尚未经过独立安全审计；实验性原生转换有明确范围。[安全政策](SECURITY.md) · [升级说明](docs/releases/v1.3.0.md) · [历史恢复失败记录](docs/testing-2026-10-15.zh-CN.md)

## 复现与贡献

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
npm test --prefix packages/releaseguard
# 先设置 RELEASEGUARD_PYTHON 为已安装内核的解释器，再运行真实 CLI 集成：
npm run test:integration --prefix packages/releaseguard
```

CI 固定外部编译器/分析器输入，并将关键对照设为必需。缺失的本地工具会记为跳过，不算执行成功。欢迎提交附带小型自有样本和复现步骤的改进。[贡献指南](CONTRIBUTING.md) · [MIT 许可证](LICENSE)
