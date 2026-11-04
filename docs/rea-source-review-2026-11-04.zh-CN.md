# REA 源码审阅与跨语言防护取舍（2026-11-04）

本轮选择 **Python 作为检查与安全逻辑的主实现，JavaScript ESM 配合 TypeScript 类型声明作为 Node.js 接入层，C++ 保留在需要直接管理原生内存的组件中**。防护更新首先覆盖不同语言的发布目录及 ZIP 系发行包，减少源映射、调试资料、私钥和已声明敏感文字的误发布；关键权限判断继续由受信服务执行。

这是对指定源码入口的只读审阅和实现决策记录，**不是整个 REA 仓库的完整审计，也不是一次已完成的 REA 对抗实验**。本文没有运行 REA 的 agent/model/provider 全链路，没有产生新的防破解成功率。已有 [2026-10-15 逆向测试](testing-2026-10-15.zh-CN.md) 中的成功恢复，以及 [v0.4 的 Frida 环境失败](testing-v0.4-2026-10-20.md)，仍应按原记录解读。

## 1. 固定研究对象

| 对象 | 本次采用的身份 | 意义 |
| --- | --- | --- |
| REA 上游 | [`morluto/rea`](https://github.com/morluto/rea)，提交 [`89317a39fab23df81efa4331311d09d2110377bd`](https://github.com/morluto/rea/tree/89317a39fab23df81efa4331311d09d2110377bd) | 2026-11-04 读取 `main` 时得到的快照；下文源码链接均固定到此提交 |
| 源码包版本 | [`package.json:4`](https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/package.json#L4)：`6.8.0` | 仅陈述源码中的版本字段，没有验证 npm 已发布相同字节 |
| Frida 依赖 | [`package.json:432–434`](https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/package.json#L432-L434)：可选依赖 `17.23.2` | 声明依赖不等于当前环境已安装，或所有平台都能成功注入 |
| 之前的 v0.4 审阅 | [`d72021b0dabedcc6fbc7bc6e0286fd359c604271`](https://github.com/morluto/rea/tree/d72021b0dabedcc6fbc7bc6e0286fd359c604271)，源码包版本 `6.7.0` | 见 [运行时保护说明](runtime-protection.zh-CN.md)；本轮对关键文件作定点比较 |
| Anti-REA Forge 基线 | [`91c07c52250bc8bfa18796cb351f105e8edb5865`](https://github.com/Afloat16/anti-rea-forge/tree/91c07c52250bc8bfa18796cb351f105e8edb5865) | 本轮修改前的工程基线，已包含 Python 密码学工具、PE/ELF gate 和 C++ 原生组件 |

REA 会继续变化。复现实验应使用完整提交和实际工具版本，不应把本文的快照描述直接套在之后的 `main` 或某个 `latest` 包上。

## 2. 实际审读的关键代码

下表给出本轮重点读取的函数、范围和可核验结论。能力声明与实现路径分开列出，避免仅根据 README 推测实现。行号对应上述固定提交。

| 源码入口 | 实际观察 | 对本项目的含义 |
| --- | --- | --- |
| [`fridaToolContracts.ts:101–168`][rea-frida-contract]，`start_frida_session` / `load_frida_script` | 合同允许 attach 或 spawn；脚本来源可为内联 JavaScript 或文件，脚本能够影响目标进程状态 | 威胁模型必须包括进程内观察与修改，不能只考虑磁盘字符串搜索 |
| [`FridaInstrumentationManager.ts:303–366`][rea-frida-start]，`#startSession` | 调用所选设备的 `spawn`、`attach`，记录目标 PID 和会话状态 | 延后启动、初始化时检查等本地时序不能自动建立受信边界 |
| [`FridaInstrumentationManager.ts:419–561`][rea-frida-load]，`#loadScript` | 读取内联/文件源码、计算源码摘要、调用 `createScript` 与 `load`，并连接消息回调 | 只隐藏脚本文件名或客户端函数名不能阻止脚本读取已定位的数据 |
| [`FridaInstrumentationManager.ts:1052–1109`][rea-frida-capture]，`#recordMessage` | 对回传消息、二进制数据和远端连接凭据做预算与脱敏处理 | 消息保留预算是 REA 的资源边界，不能当作目标进程无法被读取的证明 |
| [`registerFridaTools.ts:18–166`][rea-frida-register]，`registerFridaTools` | MCP 输入被转换为服务调用；脚本执行结果进入 Evidence 返回路径 | agent 可以通过标准工具接口组织运行时观察，不要求单一固定模型 |
| [`GhidraProviderCapabilities.ts:48–52,118–209`][rea-ghidra-capabilities]，`limitationsFor` | 字符串库存、加载后字节、引用、汇编和反编译伪代码具有不同覆盖范围；空库存不证明原文件没有文字 | 删除符号和字面量只减少部分线索。静态加载内存也不能混称为实时进程内存 dump |
| [`GhidraProviderClient.ts:899–1023`][rea-ghidra-client]，`execute` | 校验操作与参数，启动分析会话，调用 bridge，再解析结果并保留空引用等限制；还可补充 NativeAOT 元数据 | 分析器错误、未解析引用和未知项需要如实保留；不能计作本项目防护成功 |
| [`SourceMapFormat.ts:293–368`][rea-map-format]，`inspectSourceMap` / `inspectSourceMapValue` | 解析普通和 indexed map，遍历内嵌 section，并保留源路径、`sourcesContent` 和 source index | 只禁用 `.map` 后缀不足以覆盖原始源码泄露；源映射内容也有独立价值 |
| [`WebSourceMapFetcher.ts:648–823`][rea-map-fetcher]，`normalizeSourceMap` | 读取源映射中的内嵌原始文本，建立文本 artifact、位置映射和原始模块关系 | 发布包中的 `sourcesContent` 可以直接提供源码，不需要先还原混淆代码 |
| [`SourceMapDecoder.ts:70–121`][rea-map-decoder]，`#trace` | 校验输入和字节预算后交给独立解码进程 | 有预算的分析失败只说明该次操作不完整，不能推出别的工具或预算也会失败 |
| [`ZipArtifactReader.ts:151–272`][rea-zip]，构造器 / `entries` / `open` | 逐成员建立库存、核对元数据和文件身份、限制展开字节，返回成员读取流；加密项返回不支持错误 | 普通压缩包装不消除包内源码和密钥的暴露；本项目门禁应检查成员内容，并对不可检查项明确失败 |
| [`InvestigationWorkflows.ts:65–122,190–251`][rea-workflows]，`buildCallPathEvidence` / `correlateStaticAndRuntimeEvidence` | 用已有证据构建调用路径、关联静态与动态结果，并保留未知项与推断属性 | 降低单一线索的可见性不能替代完整的权限与数据边界 |
| [`EvidenceLedger.ts:91–113`][rea-ledger]，`record` | 校验证据、处理重复记录并执行存储预算检查 | 分析结果可以被结构化保存和复用，测试应保留具体证据而非只记录模型自述 |

另对照阅读了 [Frida 接入说明][rea-frida-guide]、[网站源码位置说明][rea-map-guide]、[Ghidra 字面量过滤实现][rea-literal-filter] 和 [REA agent 指引的入口部分][rea-agent-guide]。上游指引作为研究材料读取，没有作为本仓库操作指令执行。

### 与 6.7.0 快照的比较

本轮比较的是相同关键路径在两个提交中的内容，不是完整的上游 release diff：

- **源映射能力在 6.7.0 已经存在。** 旧版 [`SourceMapFormat.ts`][old-map-format] 已处理 `sourcesContent` 和 indexed map。新版对 section 分类、边界及结构验证作了调整。本项目扩展这部分防护，是补齐之前的覆盖面，不能宣传成针对 6.8.0 新增能力的专用补丁。
- **Frida 的基本威胁没有改变。** 旧版 [`FridaInstrumentationManager.ts`][old-frida] 已有 attach/spawn 和脚本加载。新版仍保留这些路径，并完善清理资源、失败诊断和受限消息捕获。清理或环境出错与“客户端秘密不可恢复”是两回事。
- **新版 Ghidra 接口更细致地报告未知项。** 对照 [`GhidraProviderCapabilities.ts` 的旧版][old-ghidra]，当前版本增加了已有工程的分析历史限制和空引用结果提示。新增的 [`GhidraLiteralSearch.ts`][rea-literal-filter] 还统一了 Node 侧的字面量匹配处理；这些变化不等于旧版只能搜索 ASCII，也不证明任意文字都可恢复。

## 3. 实用防护的优先顺序

以下顺序是根据上述源码入口和本项目现有能力作出的工程判断。

### 第一优先：减少发布时直接交出的资料

把发布检查从“必须先选中一个 PE/ELF 文件”扩展为独立发布目录入口，让 Python、JavaScript/TypeScript、Java、Go、Rust、C/C++ 等项目都能在构建末尾使用同一个检查器。原有 [`native.py` 基线][forge-native-base] 的 `gate` 同时承担 PE/ELF 格式检查与目录扫描；新的通用入口应与原生格式检查分别使用，并保持原 CLI 兼容。

主要检查对象是声明的敏感字面量、私钥 PEM 标记、源映射标记、私有调试资料、备份/源码目录和预期文件集合。ZIP/JAR/WHL 成员应在资源预算内读取，不能因内容压缩后暂时没有明文匹配就直接通过。

源映射规则的依据不止是文件扩展名。[ECMA-426 §9、§10、§11](https://tc39.es/ecma426/) 定义了内嵌原始内容、indexed sections、代码中的 `sourceMappingURL`、data URI 和 HTTP `sourcemap` 头。因此，本地门禁应同时考虑文件名和内容标记；部署后的 HTTP 响应头以及远端可下载文件仍需要单独检查。

这些规则用于减少可避免的暴露。字节标记可能命中文档或公开调试包，需按发行策略调整；它们不解析所有语言语义，也不保证发现任意编码、加密或分片的秘密。公开源码项目可以主动允许源码发布，但生产发行私钥仍应单独管理。报告应只提供规则、路径和必要定位，不回显命中的秘密。

### 第二优先：在受信服务执行实际受限操作

Frida 的官方 [JavaScript API](https://frida.re/docs/javascript-api/) 提供进程内读写和函数参数/返回值观察能力。因此，把长期秘密或最终授权决定留在受控客户端内，无法靠换语言、字符串掩码或本地验签建立相同于服务器的信任边界。

继续使用现有 [请求绑定 capability](runtime-protection.zh-CN.md)：服务端独立确定身份、audience、产品、操作和实际请求字节，验证短时签名并原子消费防重放状态后，由服务本身执行受限操作。不能将客户端返回的“验签成功”作为业务授权。服务还需自己的认证、TLS、速率限制、持久状态和异常处理；本轮没有新增托管授权服务。

[RFC 9700 §2.2、§2.3、§4.10](https://www.rfc-editor.org/rfc/rfc9700.html) 支持限制 token 受众、权限和发送者的方向，也指出同时取得 token 与密钥的攻击者会削弱发送者约束。本项目现有 capability 是可被先用的 bearer 凭据，不是 DPoP/OAuth 实现。新增绑定协议应先解决认证来源、密钥保管、重放状态和跨副本一致性，不能仅加一个客户端字段就宣称防止 token 窃取。

### 第三优先：缩短必要明文的存在时间并保留可验证边界

现有 C++ `secure_buffer` 继续服务于明确拥有的原生内存：检查锁页结果、适用平台的 dump 排除状态和销毁清理。它不能清除其他副本，也不能排除数据被合法使用时的进程内读取。详见 [运行时保护范围](runtime-protection.zh-CN.md)。

构建优化、内部符号控制、选定字面量掩码和发布完整性检查可以继续使用，但应分别验证功能、ABI、发布暴露和信任链。通过功能测试不能换算为逆向成本或破解成功率。

## 4. 编程语言和贡献入口

| 层次 | 本轮选择 | 选择理由及边界 |
| --- | --- | --- |
| 检查规则、策略、CLI、密码学与服务端辅助 API | Python | 复用已有实现、错误行为和测试；普通检查贡献不要求 C++ 编译器，也避免在多个语言里维护同一签名/密钥协议 |
| Node.js 构建接入 | JavaScript ESM + `.d.ts` | JavaScript 可直接运行，TypeScript 可获得类型提示；通过有界、无 shell 的子进程桥接 Python CLI 的只读检查，不重新实现密码学，也不包含发行私钥 |
| 内存页、显式清理、CMake 原生接入 | C++17 | 这些功能直接依赖操作系统内存 API 和指针生命周期；在 Python/JavaScript 托管对象中同名重写不会得到相同内存保证 |
| 后续独立二进制需求 | 按具体需求评估 Go/Rust 等 | 若以后测得 Python 启动、部署或吞吐成为问题，再用实际工作负载决定；本轮没有足够证据支持全仓重写的成本 |

这是针对本仓库的维护性取舍，不是语言流行度排名。编程语言决定贡献方式和部署成本，不自行决定客户端秘密能否保密。Node 接入层是构建工具，需要受信 Python 解释器与已安装的本项目，不是在浏览器里执行的 SDK，也不是独立的原生安全运行时。

贡献者可以从单条 Python 检查规则、一个合成回归样例、JavaScript 调用示例或一段中英文说明开始。与实现有关的输入/输出类型、退出码、资源预算和测试应当放在同一变更中，让贡献可直接运行和审阅。

## 5. 本轮没有采用的方向

| 方向 | 本轮没有实施的原因 | 更适合的验证方式 |
| --- | --- | --- |
| 将整个项目改写为另一种编译语言 | 不能消除进程内观察，且会重新引入协议、路径、Unicode 和平台兼容回归 | 先测量部署/性能瓶颈，再决定是否需要独立实现 |
| 增加调试器检测、时间检查作为主要防护 | 检测逻辑本身位于同一客户端，无法替代服务端授权或私钥隔离 | 对自有样例测量可用性、误判和实际绕过成本，不赋予其信任边界地位 |
| 自定义加密算法、将永久密钥藏进构建种子 | 分发给客户端的解密所需材料仍属于可观察对象 | 保持受维护密码库、外部密钥和可信服务边界 |
| TEE、远程证明和新 token 协议 | 需要具体平台、认证与部署模型；本轮没有相应实现或验证基础 | 单独设计协议、信任根、回滚处理和端到端测试 |
| 提示注入、畸形文件诱导分析器出错 | 不能作为稳定的软件保护机制，也会混淆错误与安全结论 | 保留格式合规样例，按明确授权和固定预算做可复现测试 |

## 6. 新增功能的验收要求

通用扫描器应在可核验范围内失败关闭：字节/文件/成员预算超限、被拒绝的包格式、无法检查的加密项、路径冲突、符号链接或扫描中变化不能报告成完整通过。压缩检查需要单独控制压缩输入、展开内容、成员数量和嵌套深度；不能解包到用户目录，也不能执行目标代码。支持格式和失败范围以 [跨语言发布扫描说明](portable-release.md) 和实际测试为准。

| 要验证的风险 | 有意义的回归样例 |
| --- | --- |
| 只扫二进制或文件后缀造成漏检 | 只有 JS/HTML/Python 文件的发布目录，独立源映射、内联源映射、无 `.map` 后缀的内容标记 |
| 压缩遮住发布秘密 | ZIP/JAR/WHL 成员内的合成私钥/源映射；加密、损坏、重复名称、路径逃逸和超预算成员 |
| 分块与编码边界 | 跨读取块的完整标记，UTF-8/UTF-16/UTF-32 字面量与私钥标记 |
| 检查过程泄密或失去文件身份 | 报告不含秘密原文；读取过程中替换、增长或删除文件时拒绝完整通过 |
| JavaScript 桥接改变行为 | 带空格及 shell 元字符的路径、错误退出码、无效 JSON、输出预算、超时和解释器不可用 |
| 破坏已有用户接入 | 原 `gate`、`native-init`、签名/授权 CLI 和 CMake 回归仍通过；通用扫描与原生结构审计各自保留清晰范围 |

上述是验收要求，**不是本文已经完成的测试计数**。本轮实际测试命令、结果、平台和跳过原因由对应验证记录提供。要评估“是否增加 REA 的破解成本”，仍需按 [既有评估协议](rea-threat-model.zh-CN.md#可复现的-rea-评估协议)，在自有样例上固定工具、模型、预算和独立判据，分别记录恢复成功、失败、超时与环境阻断。

[rea-frida-contract]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/src/contracts/fridaToolContracts.ts#L101-L168
[rea-frida-start]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/src/frida/FridaInstrumentationManager.ts#L303-L366
[rea-frida-load]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/src/frida/FridaInstrumentationManager.ts#L419-L561
[rea-frida-capture]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/src/frida/FridaInstrumentationManager.ts#L1052-L1109
[rea-frida-register]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/src/server/registerFridaTools.ts#L18-L166
[rea-ghidra-capabilities]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/src/ghidra/GhidraProviderCapabilities.ts#L48-L209
[rea-ghidra-client]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/src/ghidra/GhidraProviderClient.ts#L899-L1023
[rea-map-format]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/src/javascript/sourceMaps/SourceMapFormat.ts#L293-L368
[rea-map-fetcher]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/src/browser/WebSourceMapFetcher.ts#L648-L823
[rea-map-decoder]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/src/javascript/sourceMaps/SourceMapDecoder.ts#L70-L121
[rea-zip]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/src/artifacts/ZipArtifactReader.ts#L151-L272
[rea-workflows]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/src/application/investigation/InvestigationWorkflows.ts#L65-L251
[rea-ledger]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/src/application/investigation/EvidenceLedger.ts#L91-L113
[rea-frida-guide]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/docs/frida-instrumentation.md
[rea-map-guide]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/docs/web-source-location.md
[rea-literal-filter]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/src/ghidra/GhidraLiteralSearch.ts#L1-L72
[rea-agent-guide]: https://github.com/morluto/rea/blob/89317a39fab23df81efa4331311d09d2110377bd/.agents/skills/reverse-engineer-anything/SKILL.md#L1-L92
[old-frida]: https://github.com/morluto/rea/blob/d72021b0dabedcc6fbc7bc6e0286fd359c604271/src/frida/FridaInstrumentationManager.ts
[old-map-format]: https://github.com/morluto/rea/blob/d72021b0dabedcc6fbc7bc6e0286fd359c604271/src/javascript/sourceMaps/SourceMapFormat.ts
[old-ghidra]: https://github.com/morluto/rea/blob/d72021b0dabedcc6fbc7bc6e0286fd359c604271/src/ghidra/GhidraProviderCapabilities.ts
[forge-native-base]: https://github.com/Afloat16/anti-rea-forge/blob/91c07c52250bc8bfa18796cb351f105e8edb5865/src/releaseguard/native.py
