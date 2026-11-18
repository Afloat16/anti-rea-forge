# v1.1：针对 REA 的可验证防线

日期：2026-11-18。目标是减少别人从公开发布物中直接取得的私有资料，并用同一分析器的
正反对照验证结果。检查通过不代表整个客户端算法无法重建；本轮也保留分析器仍能读取
公开指令的结果。

## 固定对象

| 对象 | 身份 | 证据性质 |
| --- | --- | --- |
| REA 源码构建与运行 | [`c338e54c33213ca8dd157d30fbc922b65a04c49b`](https://github.com/morluto/rea/tree/c338e54c33213ca8dd157d30fbc922b65a04c49b) | 固定源码、干净 tracked tree、显式构建，真实执行两项三组对照 |
| 真实 npm CLI | `rea-agents@6.9.0`，完整 SHA-512 integrity 见锁文件和报告 | 实际执行，不以工具缺失或错误计成功 |
| npm provenance 声明 | [`d74549e495c58eb4a560279fd9f05508401ea0a0`](https://github.com/morluto/rea/tree/d74549e495c58eb4a560279fd9f05508401ea0a0) | registry attestation 的 source commit 声明；未独立验证 Sigstore 签名链 |
| WABT | 官方 Linux x64 `1.0.42`，资产和四个可执行文件均核对 SHA-256 | 真实编译、校验与反汇编 |
| 修复前发布包 | 官方 `open_release_guard-1.0.0-py3-none-any.whl` | SHA-256 `d49b525b889bfd930f0c242a2afdb4240d06f5471a7e1b0c308241a9ef44e970`，独立环境安装 |

审阅快照与 npm 6.9.0 不是同一个源码提交；Wasm 路径中存在实际变更，因此不能仅凭包版本
相同便声称“最新源码已经实测”。本轮另外构建了 c338，并真实执行两项对照；每份报告
分别记录实际执行的分发形式、版本和摘要。源码构建输出 3,454 个文件、62,317,909 字节，
整个 `dist` 清单、文件长度和内容摘要在实验前后保持一致。

## 从能力到措施

| REA 入口与固定源码 | 可以直接获得的内容 | 本项目措施与真实边界 |
| --- | --- | --- |
| [WABT provider](https://github.com/morluto/rea/blob/c338e54c33213ca8dd157d30fbc922b65a04c49b/src/wasm/WabtArtifactProvider.ts) | Wasm 名称、接口、段、WAT 指令 | **本轮新增**私有调试段扫描与分离；代码、数据和公开接口仍然可读 |
| [JavaScript reconstruction](https://github.com/morluto/rea/blob/c338e54c33213ca8dd157d30fbc922b65a04c49b/src/application/javascript/JavaScriptArtifactReconstruction.ts) | map 原始文本及生成 JS 的结构 | 私有 map 分离；真实 REA 原始/公开/恢复私有 map 对照。生成 JS 仍可分析 |
| [Python PYC parser](https://github.com/morluto/rea/blob/c338e54c33213ca8dd157d30fbc922b65a04c49b/src/python/PythonPycParser.ts) | 支持版本的字节码、常量、名字、文件名和嵌套 code object | PYC 不是密文；本版没有 Python 字节码加密/转换 backend |
| [Managed static provider](https://github.com/morluto/rea/blob/c338e54c33213ca8dd157d30fbc922b65a04c49b/src/dotnet/ManagedStaticProvider.ts) | 托管成员、CIL 和用户字符串 | 普通 .NET 客户端仍可分析；PE 检查不是 CIL 保密转换 |
| [Go provider](https://github.com/morluto/rea/blob/c338e54c33213ca8dd157d30fbc922b65a04c49b/src/go/GoBinaryProvider.ts) | 构建资料与静态字符串候选 | 原生调试检查覆盖其明确支持的格式；没有新增 Go 元数据自动私有化 |

上述最后三项是明确保留的缺口，不能计入“已防住”。本版没有让第三方操作者强制执行我们的
分析授权流程，也不依赖目标 README 或 agent 提示改变其权限。

## 两项实质修复

### 1. Wasm 私有调试资料

v1.0 的便携扫描不识别 Wasm。一个合法、可运行的自有模块即使保留私有 `name` 或调试
custom section，也可通过默认门禁；真实 REA/WABT 可以直接恢复名称。

v1.1 按 magic 识别有界 core-v1 section envelope，对支持的私有自定义段给出拒绝结论。
新分离器保留每个未移除段的字节和顺序，将完整原件放入私有位置；两输出写后校验，失败
回滚。改名与受支持 ZIP/ASAR 嵌套同样检查。详见 [Wasm 接入](private-wasm-debug.md)。

### 2. 标准解码即可恢复的密钥

v1.0 的字节标记检查漏过了五个自有实例：全 Unicode 转义的资产密钥十六进制、32 整数
字节数组、转义 PEM、Ed25519 JWK、PKCS8 DER。恢复后的资产密钥成功解密原始明文；恢复
后的签发私钥产生了可由原公钥验证的签名。这是发布泄漏，不是签名算法被攻破。

v1.1 对 JSON 做一次有界解析后检查解码字符串、根字符串、属性名、配置密钥的字节数组
与支持的 JWK 私有材料；公开字段缺失或错误不会掩盖可直接恢复的私有字段。独立未加密
DER 经 128 字节前缀筛选，最多读取 64 KiB 再识别。公开 JWK、公钥 DER 与证书保留兼容性。
报告只给固定类型/配置索引，不输出秘密值或 JSON 属性名。

JSON 文件上限 8 MiB，节点与深度受限；已识别但超限/无法完成的结构会产生
`structured_secret_unverifiable` 并将完成标记设为 false。Wasm 检查不执行模块；密钥检查
不执行 JavaScript、不搜索任意偏移处的 DER，也不声称可解出所有自定义编码和分片密钥。

## 已记录的数据

| 对照 | 原始/旧版 | 公开/新版 | 私有恢复/正常对照 |
| --- | --- | --- | --- |
| REA 6.9.0 + WABT 私有名称 | 恢复 3 个 | 恢复 0 个 | 放回私有原件后恢复 3 个 |
| 固定 c338 源码构建 + WABT 私有名称 | 恢复 3 个 | 恢复 0 个 | 放回私有原件后恢复 3 个 |
| Wasm 功能与字节 | 255 字节；9 个输入 | 134 字节；9 个结果一致 | 可执行段摘要相同，公开 notice 自定义段保留 |
| REA 6.9.0 + trace-mapping 原文 | 精确恢复 1 份 | 精确恢复 0 份 | 放回 map 后精确恢复 1 份 |
| 固定 c338 源码构建 + trace-mapping 原文 | 精确恢复 1 份 | 精确恢复 0 份 | 放回 map 后精确恢复 1 份 |
| 标准库密钥恢复 | 5/5 有效；v1.0 门禁 5/5 允许 | v1.1 门禁 5/5 正面识别并拒绝 | 公有 JWK、仅外部密钥密文 2/2 允许 |

Wasm 与 source map 各是一个自有样本，密钥是五种明确表示；不把这些分母扩成一般软件的
安全概率。三组 Wasm 的 WAT 算术都可读取，因此“等价逻辑无法重建”不是这轮结论。

- [Wasm 原始 JSON](results/wasm-recovery-v1.1.0-rea-6.9.0.json)
- [固定源码 Wasm 原始 JSON](results/wasm-recovery-v1.1.0-rea-source.json)
- [Source map 原始 JSON](results/source-map-recovery-v1.1.0-rea-6.9.0.json)
- [固定源码 source map 原始 JSON](results/source-map-recovery-v1.1.0-rea-source.json)
- [密钥恢复原始 JSON](results/structured-secret-recovery-v1.1.0.json)
- [脚本与固定依赖](../benchmarks/recovery-tools/package-lock.json)

## 发布要求

新增功能进入三平台回归和 wheel/源码包的实际安装测试。发布仍要求 main 精确提交上的
13 个指定 CI 作业全部成功，资产安装报告绑定同一提交，再核验上传后的大小和 SHA-256。
最终结果以 Release 的 `release-evidence.json`、`installation-report.json` 和 `SHA256SUMS`
为准；本页的源码审阅不替代这些执行记录。
