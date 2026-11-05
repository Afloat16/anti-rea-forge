# REA 的 AI 操作边界与协作式分析授权（2026-11-05）

**本轮采用模型之外的授权检查：在已经接入本项目的分析工作流中，先验证签名、发行文件身份、请求方和操作范围，再调用固定的分析处理函数。** 把一段“禁止分析”文字放入程序，不能可靠地迫使第三方 AI 拒绝任务。REA 本身还明确把分析目标中的文字当作不可信数据，要求 agent 不执行其中的指令。

这个区别决定 v0.6 的实现范围。发布者可以提供透明的授权说明；协作方可以把签名授权检查放在自己的工具入口；不受发布者控制的客户端仍然可以直接运行 REA、反编译器或其他工具。本轮不修改第三方 REA，不替换原软件许可证，不在目标程序中注入运行模块，也不宣称获得模型级“禁止逆向”能力。

本文是固定源码入口的审阅与设计记录，**没有完成 REA、模型、provider 和客户端的端到端对抗实验**。下面的源码事实、工程判断和待验证条件分别标明；测试计数以本版本的实际验证记录为准。

## 1. 研究对象与证据范围

| 对象 | 固定身份 | 解释 |
| --- | --- | --- |
| REA 上游 | [`morluto/rea`，`92f332652d352e60b550567adf2399d83d8ebe78`][rea-tree] | 2026-11-05 读取 `main` 得到的快照；本文 REA 源码链接均固定到这个提交 |
| 源码包版本 | [`package.json`][rea-package] 中的 `rea-agents` / `6.8.0` | 仅确认源码字段，没有核对 npm 发布包与此提交的字节等价性 |
| 前一次 REA 快照 | [`89317a39fab23df81efa4331311d09d2110377bd`][rea-previous] | [上次审阅](rea-source-review-2026-11-04.zh-CN.md) 主要检查 Frida、Ghidra、源映射和归档读取 |
| 本项目修改基线 | [`32c7fefd6ae492d86de391875512c6d4870866dd`][forge-base] | v0.5 发布目录扫描与 JavaScript / TypeScript 接入版本 |

两个 REA 快照之间的 [GitHub 比较][rea-compare] 显示 47 个后续提交。下面的目标文字不可信机制并非本轮才出现：`toolResultEncoding.ts`、`serverInstructions.ts` 和 `promptContracts.ts` 没有出现在这次比较的变更文件中；`toolEffects.ts` 的变化是 `inspect_macho` 的文件系统影响标记。本轮补充研读已有机制，不能把它描述为上游在 2026-11-05 新增的防护。

上游 skill、提示和文档只作为研究材料读取，没有作为本仓库的操作指令执行。检查这些入口不等于审计上游全部代码，也不能证明每个第三方模型都遵守上游提供的指令。

## 2. 实际审读的代码及其含义

| 固定源码入口 | 观察到的实现 | 对本项目的含义 |
| --- | --- | --- |
| [`toolResultEncoding.ts:24–37`][rea-untrusted] | 将字符串、符号、反编译结果、页面、脚本、捕获记录、日志和文件内容归为分析目标数据；生成 `_meta.provenance.untrusted_content: true` 标记 | 目标里写出的“停止分析”“新的系统规则”不能自动成为 agent 的高优先级指令 |
| [`serverInstructions.ts:32–43`][rea-instructions] | 构造服务器说明时追加上述不可信内容说明 | 这一边界进入 REA 的 MCP 初始化说明，并非只出现在 README |
| [`createServer.ts:118–152`][rea-server] | 创建 MCP server 时实际传入 `serverInstructions(...)` | 存在从说明定义到服务器配置的接线；不能仅把它当作孤立常量 |
| [`toolEffects.ts:790–816`][rea-effects] | 除经过审核的少量工具外，默认把结果视为可能包含目标内容；未知工具名也属于该类 | 没有理由假设换一个工具返回文字，就能稳定绕过内容来源标记 |
| [`targetContentFramingMcp.test.ts:56–76`][rea-framing-test] | 测试通过 MCP 客户端读取初始化说明和结果来源标记 | 上游有传输层回归样例；此处是源码审阅，没有在本轮运行这些上游测试 |
| [`targetContentProvenance.test.ts:9–31`][rea-provenance-test] | 逐个检查工具合同的标记与例外集合是否一致 | 标记覆盖面有合同级检查；标记本身仍不等于客户端实际强制执行 |
| [`SKILL.md:465–474`][rea-skill] | 要求区分观察、推断和未知项；说明 REA 不要求逐次 permission grant，客户端可以独立设置审批 | 当前工作流没有因目标文件携带所有者声明就自动请求分析授权的承诺 |
| [`analysisAdmission.ts:15–40`][rea-admission] | 将分析操作交给当前 session 的 admission，或在 fixed 模式下检查取消状态后调用 | 名称中的 admission 不能直接理解为发布者的许可校验 |
| [`BinarySession.ts:1384–1411`][rea-session] | 等待会话切换、检查取消/关闭状态、跟踪调用及清理 | 这里保护的是会话生命周期，不是软件所有者签发的分析许可 |
| [`promptContracts.ts:103–141`][rea-prompt] | 将请求上下文以 JSON 数据放入工作流文字，明确不把上下文和补全结果当成授权 | 目标描述、提示参数或模型自述都不适合作为授权凭据来源 |
| [`registerPrompts.ts:78–91`][rea-register-prompt] | 返回带 `user` role 的工作流文本，没有执行分析操作 | 提示模板的存在不会创建密码学授权边界，也不会单独执行强制检查 |
| `docs/mcp-contracts.md` 的 [532–573][rea-contracts] 与 [1303–1329][rea-contract-approval] | 解释不可信标记，说明 host / hook 可以应用更严格的处理；工具 annotations 是效果提示，不能充当授权控制 | 强制条件需要由使用方的受信任代码执行，不能只添加工具说明或提示语 |

REA 自己的 [安全边界说明][rea-security] 也区分了 bridge 认证和操作系统隔离：会话 token、私有传输及临时目录不构成 sandbox，同一系统用户下的恶意进程仍在边界之外。因此，不能把 REA 的 bridge token 与本项目的发布者授权混为一谈。

## 3. 为什么没有采用“强行触发模型禁止任务”的文字

从上述代码可以直接得到一个有限结论：**在 REA 预期的信任模型里，目标内容中的指令应该被忽略。** 实际模型可能出错，但依赖这个错误不能提供稳定的保护。换模型、换客户端、禁用提示、先过滤字符串或直接使用分析器，都可能改变结果。这些是工程上的可绕过路径，不是本轮实测得到的成功率。

需要区分三类信息：

| 信息 | 可以表达什么 | 不能自行建立什么 |
| --- | --- | --- |
| 发布者的公开说明 | 产品标识、联系途径、希望采用的分析授权流程 | 对第三方 agent 的系统权限、强制拒绝或全球通用的 AI 策略 |
| 由已固定公钥验证的签名声明 | 指定密钥签发了这些字段，字段没有被修改 | 密钥持有人就是法律权利人、请求目的合法、任何软件许可证都被替换 |
| 受信任程序执行的前置检查 | 本程序在条件不满足时不调用被保护的处理函数 | 操作者不能绕过这个程序、另一个 REA 实例会自动执行同样检查 |

OpenAI 的 [指令层级研究][instruction-hierarchy] 讨论了把高权限指令与低权限输入区分开的方向。这支持将授权逻辑放在可信软件边界的设计判断，但该研究并不证明所有模型都能抵抗提示注入，也不提供让第三方模型必然拒绝逆向分析的接口。

同样，固定版本的 [MCP Tools 规范][mcp-tools] 将工具 annotations 视为需考虑来源信任的提示；[MCP Authorization 规范][mcp-authorization] 讨论的是访问受保护 MCP 服务的传输层授权。二者都不会把目标目录中的自定义声明自动提升成整个 MCP 生态通用的执行禁令。本项目的 analysis grant 是本项目协议，不能称为 MCP、REA 或某模型厂商的标准授权格式。

公开说明应保持直白、可读和可核对，不冒充系统消息，不伪造模型厂商政策，不要求删除证据或修改分析器，也不向目标文件夹放置自动安装的 agent 配置。

## 4. v0.6 的可验证边界

本轮的设计是 **signed analysis grant + 原有 signed manifest + 完整发行文件校验 + 固定处理函数**。实现逻辑继续集中在 Python 中，JavaScript / TypeScript 接入层调用同一验证器。

### 可信输入来自使用方

公钥、发行目录、预期 product / release、调用方 subject、服务 audience 和请求操作应由受信任的部署配置、已认证会话或固定程序代码提供。它们不能来自目标 README、目标 sidecar 自带公钥、反编译文本或模型生成的“我已经获准”字段。

调用方传入一个 `subject` 字符串不等于完成身份认证。本项目比较的是已由上层确认的预期值；部署方需要独立认证请求者并把结果绑定到这次处理。签发私钥必须留在发行者控制的环境，不能打包进发行目录、公开示例或下游客户端。公钥可以公开，但验证方必须先通过可信途径固定它，不能在验签前用待检查材料里的另一个公钥替换信任根。

### 一次完整检查的意义

1. 验证 manifest 和 analysis grant 的签名及格式，将 grant 绑定到具体发行身份。
2. 比较受信上下文中的 subject、audience、product、release 与 grant 内容。
3. 根据可信时钟检查有效期。本轮采用默认 3,600 秒、最高 86,400 秒的 grant 有效期；这只是合作检查器的策略，不是运行中分析任务的自动终止器。
4. 从明确选择的发行根目录重新读取完整 inventory 和文件 SHA-256，不把过去的通过结果当成本次授权依据。
5. 检查当前需要的独立 scope，全部通过后才进入调用方固定的处理函数。

`inspect`、`decompile`、`instrument` 是三个独立 scope，不自动继承。处理函数执行什么操作，就必须要求对应 scope；不能根据模型对行为的自然语言描述来选择权限。`inspect` 也可能读取敏感内容，并不代表任何对象都可以无授权检查。

签名 grant 是可以被复制的凭据。这里的时限、subject 和 audience 绑定不等于持有者证明，也不自动提供一次性消费或跨节点防重放。只有在使用方先认证 caller，并保证 expected subject / audience 不受其任意控制时，这些比较才有实际意义。

### SDK 控制的是固定处理函数

`withAnalysisAuthorization` 的可检验承诺是：授权检查未通过时，不调用传入的固定 handler。调用方必须遵守同一个边界：不预先启动 REA，不把已运行的异步任务作为 handler 传入，不在拒绝后自行继续执行，也不允许请求数据选择一个未经审查的处理函数。

JavaScript 接入层在 Python 检查返回后、调用 handler 前，还使用报告中的有效期（`validity`）和受信主机的 `Date.now()` 复核时间，拒绝在桥接期间已经到期的授权。这仍不是原子交接，也不会自动终止已经准入的 handler。

必须由 handler 自己使用已绑定的发行根目录、操作和输入。不能检查目录 A，却分析用户随后指定的目录 B；也不能在 `inspect` handler 内启动任意反编译、注入或 shell 命令。SDK 无法从任意 JavaScript 函数内部自动证明这些条件。

“检查完成”与“后续工具实际读取”之间仍有时间间隔。无缓存校验可以避免复用陈旧检查结果，但不能单独消除检查后的文件替换。需要保证交接时的字节身份时，部署方应使用隔离的只读发行快照或等价的不可变输入安排；本版不提供跨进程原子执行，也不隔离一个主动修改自身输入的操作者。

### 可以和不可以据此宣称的结果

| 场景 | 该设计的承诺 |
| --- | --- |
| 缺少 grant、签名错误、过期、身份不符、scope 不足、发行文件变化 | 接入的检查器拒绝；正确使用的 SDK 不调用 handler |
| 签名、范围、发行库存和可信上下文全部匹配 | 允许该次 handler 调用；不替代 handler 自己的参数验证与原宿主权限检查 |
| 目标文件声称已有授权，或请求者自行签发一份声明 | 未经固定信任根验证，不能据此通过 |
| 操作者自己启动 REA / Ghidra / Frida，或删除本地检查代码 | 本 SDK 不控制这些路径，不能阻止 |
| 软件本身的许可证与业务服务权限 | 继续按原机制处理；analysis grant 不授予软件使用权、发行权或业务 API 权限 |
| 合法研究、互操作或其他权利争议 | 本协议不判定法律权利；签名不证明法律所有权，也不能替代适用法律和原许可证 |

## 5. 接入便利性与性能约束

本轮的 `project-init --root dist --out .releaseguard --product ...` 为发布者准备项目配置、公开检查策略和说明；`check --config ...` 复用已有发布扫描器。初始化输出应位于发行目录之外，命令不自动更改用户的构建系统、agent 配置或软件许可证。公开声明用于说明流程，私有检查规则用于避免误发布；它们不应被误读为已签发的分析授权。

初始化拒绝已经存在的符号链接或 reparse 根目录，不会静默把 `dist` 固定到它当时指向的旧版本。尚未构建的普通根目录仍可以在初始化后创建。

这些入口应在构建、发布或独立分析环境使用。新增功能不要求在被保护软件里导入 Python / Node 模块，不添加启动时验签、后台扫描、网络轮询、反调试检查或业务路径回调，也不重写二进制。

“不进入软件运行路径”有明确范围：

- 生成配置、扫描文件、计算 SHA-256 和验签需要构建或分析环境的 CPU、内存、I/O 和时间，不能称为整个系统零开销。
- 扫描器若与应用同时在同一机器运行，仍可能竞争系统资源。要避免这类影响，应在 CI 或独立发布阶段运行。
- 校验前后发行文件的字节和 SHA-256 相同，可以支持“没有改写被保护文件”的结论；这不等于测量了任意应用、机器和工作负载的运行性能。
- 为了省时而只检查修改时间、文件大小，或缓存一次成功授权，会削弱本轮的文件身份承诺。没有充分的不可变输入保证时，本轮选择每次重新校验。

本轮的检查与授权工具保留普通 Python / JavaScript 贡献入口。原生内存组件仍由原有 C++ 实现承担；这次新增能力不要求普通应用增加 C++ 运行依赖。

## 6. 协作部署与后续 host hook 方向

最适合部署的地方，是发行者或合作分析方能控制的服务、构建工作流、分析门户和工具包装层：先认证请求者，再执行 grant 检查，最后调用绑定到同一目标和 scope 的固定操作。要形成强制入口，其他可直接访问同一目标的执行路径也需要由部署方的权限和隔离措施限制；SDK 不能替操作系统撤销文件访问能力。

真实客户端也存在可用的前置 hook。例如 [Claude Code 官方 hooks 文档][claude-hooks] 说明 `PreToolUse` 可以拒绝工具调用，并规定了 MCP 工具名匹配、错误及超时处理。然而这是未来集成方向，**本版没有提供或实机验证 Claude Code / 其他宿主 hook**。

不能把本项目 CLI 的拒绝退出码直接当成任意宿主的拒绝协议。例如本项目返回 findings / denied 时使用的退出码 `3`，在 Claude Code 的普通 command hook 中并不自动等价于阻止工具调用。该宿主有自己的 JSON 决策、退出码 `2` 和 `onFailure: "block"` 约定；官方当前文档对后一个选项要求 Claude Code 2.1.295 或更新版本。真正集成还需处理插件工具命名、目标路径、当前 REA session 身份、旁路工具入口和失败时默认拒绝。只写一个匹配工具名的模板，不足以证明这些条件成立。

因此，本轮精确承诺停留在 **SDK 固定 handler 的前置检查**。后续若实现宿主集成，需要固定客户端版本，分别验证授权通过、拒绝、解析失败、验证器不存在、超时、session 切换和旁路路径，不能根据文档样例推定已经有效。

## 7. 验证要求与不能推导的结论

| 要验证的性质 | 有意义的检查 |
| --- | --- |
| 拒绝先于操作 | 用带可观察副作用的固定 handler，检查缺失 / 无效 / 过期 grant 等情况下调用次数为零 |
| 身份与 scope 独立 | subject、audience、product、release、发行摘要、三个 scope 分别做不匹配样例；不把 `instrument` 自动视为 `decompile` 授权 |
| 目标文件身份 | 检查新增、删除、修改、替换文件及不安全路径；重新请求后再次计算库存，拒绝复用旧成功结果 |
| 严格格式与有界输入 | 重复 JSON 字段、类型错误、未知字段、非法时间、有界长度和格式错误不能报告为通过 |
| 数据不变 | `project-init`、`check` 与授权检查前后比较目标字节；生成内容留在指定的独立输出目录 |
| 原有能力兼容 | 原 native gate、签名 manifest / license、密码与 capability 行为及跨平台 JS 桥接继续通过现有回归 |
| 实际部署强制性 | 在固定宿主中验证目标、输入、caller 身份和下游操作一致，检查直接工具访问与检查后文件修改的边界 |

前五类功能测试通过，最多支持相应实现性质。它们不能证明任何第三方 AI 必然拒绝，也不能计算 REA 的破解失败率。真正的 REA / agent 评估仍需按 [既有威胁模型](rea-threat-model.zh-CN.md) 固定自有样例、上游提交、模型、provider、预算和独立成功判据，并把环境阻断、超时、模型拒绝及实际无法恢复分别记录。

## English summary

REA at the pinned revision marks target-derived strings, code, logs and files as untrusted data, adds that boundary to MCP server instructions, and documents that caller approvals are controlled by the agent host. Target text is therefore not a reliable way to force an unrelated model to refuse analysis.

The v0.6 direction is an opt-in, deterministic preflight: verify a signed analysis grant and the existing signed release manifest against trusted caller context, recheck the complete release inventory, then invoke a fixed handler only after authorization succeeds. `inspect`, `decompile` and `instrument` are independent scopes. Trust roots and caller identity must come from trusted deployment configuration and authentication, not from the target. A signature authenticates a key and document, not legal ownership.

This protects the cooperating SDK invocation. It does not control direct REA calls, prevent removal of local checks, authenticate a caller by itself, or make the check-to-use handoff atomic. The JavaScript bridge rechecks the reported validity interval before invoking the handler; this does not terminate an operation that was already admitted. The new functionality runs during build, release or analysis preparation; it adds no module or check to the protected application's execution path. Hashing and verification still consume resources outside that application. No third-party model refusal rate, host-hook compatibility result or end-to-end REA resistance result is claimed by this source review.

[rea-tree]: https://github.com/morluto/rea/tree/92f332652d352e60b550567adf2399d83d8ebe78
[rea-package]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/package.json#L1-L6
[rea-previous]: https://github.com/morluto/rea/tree/89317a39fab23df81efa4331311d09d2110377bd
[rea-compare]: https://github.com/morluto/rea/compare/89317a39fab23df81efa4331311d09d2110377bd...92f332652d352e60b550567adf2399d83d8ebe78
[forge-base]: https://github.com/Afloat16/anti-rea-forge/tree/32c7fefd6ae492d86de391875512c6d4870866dd
[rea-untrusted]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/src/server/toolResultEncoding.ts#L24-L37
[rea-instructions]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/src/server/serverInstructions.ts#L32-L43
[rea-server]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/src/server/createServer.ts#L118-L152
[rea-effects]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/src/contracts/toolEffects.ts#L790-L816
[rea-framing-test]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/tests/boundary/mcp/targetContentFramingMcp.test.ts#L56-L76
[rea-provenance-test]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/tests/conformance/contracts/targetContentProvenance.test.ts#L9-L31
[rea-skill]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/.agents/skills/reverse-engineer-anything/SKILL.md#L465-L474
[rea-admission]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/src/server/analysisAdmission.ts#L15-L40
[rea-session]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/src/application/binary/BinarySession.ts#L1384-L1411
[rea-prompt]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/src/contracts/promptContracts.ts#L103-L141
[rea-register-prompt]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/src/server/registerPrompts.ts#L78-L91
[rea-contracts]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/docs/mcp-contracts.md#L532-L573
[rea-contract-approval]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/docs/mcp-contracts.md#L1303-L1329
[rea-security]: https://github.com/morluto/rea/blob/92f332652d352e60b550567adf2399d83d8ebe78/SECURITY.md#L25-L43
[instruction-hierarchy]: https://openai.com/index/the-instruction-hierarchy/
[mcp-tools]: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
[mcp-authorization]: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
[claude-hooks]: https://code.claude.com/docs/en/hooks#pretooluse
