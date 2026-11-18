# 面向 JavaScript / TypeScript 的 Release Guard

[English](README.md)

这是对 Anti-REA Forge Python CLI 的小型 Node.js 接入层。实现使用可直接运行的
JavaScript ESM，提供 TypeScript 类型声明；不需要 JavaScript 编译步骤，也不另写
一套密码学实现。Web、Node.js 和 Electron 项目可以把同一套发布检查接入自己的构建流程。

需要 **Node.js 22+、Python 3.10+**，并把本仓库的 Python 包安装到所选解释器。
请使用匹配的 **1.3.0 SDK 与 Python 核心**。SDK 可从 GitHub Release 压缩包或本地目录安装；
package.json 保持 `private`，尚不声称已发布到 npm 注册表。

## 安装和运行

在 Anti-REA Forge 仓库根目录，Linux/macOS 使用：

```sh
python -m venv .venv
.venv/bin/python -m pip install -e .
export RELEASEGUARD_PYTHON="$(pwd)/.venv/bin/python"
npm --prefix packages/releaseguard test
npm --prefix packages/releaseguard run test:integration
```

Windows PowerShell 使用：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
$env:RELEASEGUARD_PYTHON = (Resolve-Path .venv\Scripts\python.exe).Path
npm --prefix packages/releaseguard test
npm --prefix packages/releaseguard run test:integration
```

JavaScript 单元测试不依赖 Python，也不需要先运行 `npm install`。真实集成测试
需要已经安装 Python 核心；两种测试都不需要安装 npm 依赖。

在其他本地 Node.js 项目中安装此包：

```sh
npm install /absolute/path/to/anti-rea-forge/packages/releaseguard
```

或在项目 `package.json` 中使用文件引用，调整相对路径：

```json
{
  "dependencies": {
    "@anti-rea-forge/releaseguard": "file:../anti-rea-forge/packages/releaseguard"
  }
}
```

```js
import { createReleaseGuard, ReleaseGuardError } from "@anti-rea-forge/releaseguard";

const guard = createReleaseGuard({
  python: process.env.RELEASEGUARD_PYTHON,
  timeoutMs: 30_000,
});

try {
  const report = await guard.scanRelease({ root: "dist", policy: "release-policy.json" });
  console.log(JSON.stringify(report, null, 2));
  process.exitCode = report.exitCode;
} catch (error) {
  if (!(error instanceof ReleaseGuardError)) throw error;
  console.error(`${error.code}: ${error.message}`);
  process.exitCode = 2;
}
```

可从仓库的 [通用发布策略](../../examples/policy-portable-release.json) 开始，按实际
产物调整规则。策略文件应放在被扫描目录之外。仓库内的 [可运行示例](../../examples/javascript/scan-release.mjs)
直接引用本地接入层，无需安装 npm 包：

```sh
node examples/javascript/scan-release.mjs --root dist --policy examples/policy-portable-release.json
```

## 初始化一次，之后按配置检查

自 v0.6 引入的项目工作流可以把可编辑配置保存在应用目录之外：

```sh
python -m releaseguard project-init --root dist --product Demo --out .releaseguard
python -m releaseguard check --config .releaseguard/project.json
```

按实际环境将 `python` 换成已安装核心的虚拟环境解释器。初始化之后检查
`.releaseguard/policy.json` 中的规则。可以先初始化、再构建 `dist`，执行检查时
发布目录必须包含文件。Node 构建脚本只需指定一个配置文件：

```js
const report = await guard.checkProject({ config: ".releaseguard/project.json" });
process.exitCode = report.exitCode;
```

这些操作放在构建和发布流程中，不给被保护应用添加运行时导入、启动扫描、后台任务
或钩子。扫描和哈希计算仍会占用构建环境、分析服务的时间。

## 分析工具调用前核对授权

在**配合接入且可信的分析网关**中，`withAnalysisAuthorization()` 先验证签名授权、
操作范围和完整的签名发布产物，通过后才执行一个回调。授权缺失时由普通程序逻辑
停止下游操作，无需依赖模型是否愿意听从声明。

```js
// 这些值来自可信服务配置和已认证会话，不能由模型或分析目标选择。
const expected = Object.freeze({
  manifest: "/srv/releases/demo-1.0-evidence/manifest.json",
  root: "/srv/releases/demo-1.0",
  publicKey: "/srv/trust/demo-issuer.pem",
  product: "Demo",
  release: "1.0",
  subject: authenticatedSession.subject,
  audience: "internal-analysis-gateway",
  operation: "inspect",
  grant: submittedGrantPath,
});

const result = await guard.withAnalysisAuthorization(expected, async (verified) => {
  // 服务端固定工具到范围的映射，使用同一份已捕获的不可变配置；
  // 操作完成前保持整个发布目录不可变，不要在检查后换成另一份文件。
  return analysisTools.inspect(expected.root);
});
```

这里的 `authenticatedSession`、`submittedGrantPath`、`analysisTools` 是接入方
已有的服务对象。仓库还提供可独立运行的
[authorized-analysis.mjs](../../examples/javascript/authorized-analysis.mjs)，保护一个
固定的目录列表工具；[示例说明](../../examples/javascript/README.md) 包含授权签发步骤。

`inspect`、`decompile`、`instrument` 三种范围彼此独立，不隐含其他权限。
每次调用都会重新检查，不缓存之前的允许结果。拒绝时抛 `AUTHORIZATION_DENIED`；
子进程或协议失败，以及回调准入前的取消，也不会执行回调。允许时回调只调用一次，
其返回值或异常直接传递，不自动重试。

Python 在哈希前后检查时间；包装方法还会在回调准入前，使用可信网关的 `Date.now()`
复核已验证的 `validity.not_before` / `validity.expires_at`。即便 Python 已返回允许，
调度延迟导致过期或网关时钟显示尚未生效时，仍会拒绝。两端时钟都必须可信。
检查与工具执行仍不是同一个原子事务；授权到期不会中止已准入的回调，执行期间的租约、
持续授权、取消与副作用由实际服务负责。

回调必须使用已经捕获的不可变配置和校验过的同一份产物。包装方法无法检查或改写回调
内部选择的工具参数；在回调中换成其他目标会绕过预期的接入边界。

已有工具分发逻辑的项目可以使用 `checkAnalysis()` 取得验证器的只读决定，但一份
JSON 报告本身不会阻止工具。要形成有效边界，相关工具入口必须都经过可信网关；
未受约束的 REA、shell 或文件读取工具仍可绕过。本 SDK 不修改 REA，也不能控制
其他人的 agent，更不会让产物中的文字变成系统指令。

公钥必须经可信渠道固定，主体来自已认证会话，操作范围来自服务固定映射。
授权在有效期内可重复使用（默认一小时、最多 24 小时），没有在线撤销检查，也不自行
认证分析者身份；这些控制由服务负责。签名表明已固定的密钥签发了特定内容，
不自行证明法律所有权，也不授予本工作流之外的其他权限。

## API 与返回值

`createReleaseGuard(options?)` 提供八个异步方法：

| 方法 | 必需参数 | 可选参数 | 对应 Python 命令 |
| --- | --- | --- | --- |
| `scanRelease(options, controls?)` | `root`、`policy` | `assetKeyFiles`、`privateInputFiles` | `scan-release` |
| `checkProject(options, controls?)` | `config` | `assetKeyFiles`、`privateInputFiles` | `check` |
| `checkAnalysis(options, controls?)` | `manifest`、`root`、`publicKey`、`product`、`release`、`subject`、`audience`、`operation` | `grant` | `analysis-check` |
| `withAnalysisAuthorization(options, handler, controls?)` | `checkAnalysis` 的参数及一个回调 | `grant` | `analysis-check`，允许后调用一次回调 |
| `audit(path, options?)` | PE 文件路径 | `strict`、`signal` | `audit` |
| `gate(options, controls?)` | `artifact`、`policy` | `root` | `gate` |
| `verifyManifest(options, controls?)` | `manifest`、`root`、`publicKey`、`product` | `release` | `manifest-verify` |
| `verifyLicense(options, controls?)` | `license`、`publicKey`、`product` | `subject`、`requiredFeatures` | `license-verify` |

`controls` 可传 `{ signal: controller.signal }`，用于取消请求。
[index.d.ts](index.d.ts) 包含 TypeScript 参数、报告和错误码类型。

`assetKeyFiles` 是可选的外置密钥文件路径数组，最多 16 个，每个文件必须为原始
32 字节资产/代码密钥。SDK 将路径作为独立的 `--asset-key-file` 参数传给 Python，
不接受内联密钥。`checkProject` 将它们追加到 `project.json` 的 `asset_key_files`，
合计最多 16 个；传空数组不会取消已配置密钥。统一扫描器检查普通文件和受支持
ZIP/ASAR 成员中的原始密钥、常见十六进制/Base64 表示，报告不会返回命中内容。
密钥文件缺失或格式无效时操作失败。

```javascript
const report = await guard.scanRelease({
  root: "dist", policy: "release-policy.json", assetKeyFiles: ["../issuer/asset.key"],
});
```

### v1.3 私有实现文件引用

`privateInputFiles` 接受发布目录之外的非空普通文件：**最多 64 个，每个最多 8 MiB，
合计最多 64 MiB**。Python 拒绝目录、通配符、文件或祖先目录符号链接，以及 Windows
reparse point。SDK 将每条路径作为独立 `--private-input-file` 参数传递，不接受内联私有内容。

```javascript
const report = await guard.scanRelease({
  root: "dist",
  policy: "release-policy.json",
  privateInputFiles: ["../service/private_quote.py", "../service/model.dat"],
  assetKeyFiles: ["../issuer/asset.key"],
});
if (!report.ok) process.exitCode = report.exitCode;
```

若每轮项目检查都必须带上这些文件，在构建专用 `.releaseguard/project.json` 中配置：

```json
{
  "version": 1,
  "product": "Demo",
  "root": "../dist",
  "policy": "policy.json",
  "private_input_files": ["../../service/private_quote.py"]
}
```

配置路径相对 `project.json` 解析。`checkProject` 的额外 `privateInputFiles` 会追加到
配置中，省略选项或传 `[]` 都不会清空已有引用；两处引用合计受上述上限约束。每轮扫描
读取引用文件当前的字节和身份，并在返回前重读、复核。文件缺失、替换或更改会让操作失败。
`checks.private_inputs_checked` 报告引用数量；命中输出 `private_input_exposure` 和 `rule_index`。

这条规则匹配**完整文件的 SHA-256 相同副本**，覆盖改名普通文件、已检查的 ZIP/ASAR
成员和已验证的 unpacked 旁文件。它不识别改写、编译、拼接或分片后的实现；追加一个换行
也会改变摘要。报告不列出私有引用路径、内容或单独的引用摘要，公开文件/成员路径及公开
清单中的哈希仍然可见。[私有服务示例](../../examples/private_service/README.md) 及真实 REA
[npm](../../docs/results/private-input-controls-v1.3.0-rea-6.9.0.json) /
[源码](../../docs/results/private-input-controls-v1.3.0-rea-source.json) 对照保留了正常分离与
故意重新发布私有文件的验证。

等价 CLI 选项适用于 `scan-release`、`check`、`prepare`；Python 参数为
`private_input_files`。`prepare` 将快照保留到签名和旁文件生成之后，再次复核引用与发布
清单；最终验证失败会移除本轮新建输出目录。签名仍使用 Python CLI/API，SDK 不增加签发接口。
操作期间应由可信构建流程保持引用文件、发布目录及其祖先目录稳定；这不是原子文件系统快照。

### 新扫描范围与完成状态

配置了 `assetKeyFiles` 后，核心独立启用 `canonical-marshal-integer/v1` PYC 检查，
关闭 `check_private_keys` 或 `check_native_metadata` 不会关闭这条已知密钥规则。
它检查 32 字节已知密钥在 signed/unsigned、大/小端重建下的规范 marshal LONG 表示，
不反序列化、导入或执行待检查字节码。范围包括已支持的 CPython 3.7–3.14 稳定 magic/header，
每个 payload 最多 64 MiB、最多 16 个已知密钥；每个密钥的四种整数解释都须至少有
128 个有效位。短整数别名、不支持的头部或预算超限会使检查不完整。

| 报告字段 | 含义 |
| --- | --- |
| `pyc_asset_keys_checked` | 是否由外置已知密钥启用该范围 |
| `pyc_asset_key_files_checked` | PYC 候选检查数，包括不支持的候选及已检查归档中的成员 |
| `pyc_asset_key_scan_completed` | 该精确模式检查是否完成，不代表完整 marshal body 已验证 |
| `pyc_asset_key_profile` | 配置密钥时为 `canonical-marshal-integer/v1`，否则为 `null` |

这些字段与 JSON/DER 的 `structured_secret_scan_completed` 独立。命中使用
`asset_key_exposure` / `python-marshal-integer`；不支持的范围使用
`structured_secret_unverifiable` / `invalid_or_unsupported_pyc_key_profile`。
应同时看启用状态和候选数量，不能只看 completion 为真。未知密钥、计算/分片/非规范常量
以及程序逻辑仍在范围之外。[PYC 范围说明](../../docs/python-pyc-key-profile.md) 列出完整边界。

`check_private_keys: true` 还检查 JSON 字符串中私有 PEM 头部外面的**一层** hex/Base64
包装，包括支持的前导说明、空白折叠和 Node Base64 表示。PEM 与 DER 包装共享每份 JSON
**64 个候选、256 KiB 解码字节**预算；每个已识别候选最多 **256 Ki 字符原始文本、
64 KiB 解码内容**，并继续受既有 JSON 结构预算约束。确认私有头部后输出
`private_key_marker` 和 `json-hex-pem` / `json-base64-pem`；已识别但无效或超限的候选
输出 `structured_secret_unverifiable`，并将结构检查完成状态设为 false。它不递归解任意
包装，也不证明每个带标记的密钥都有效；公钥 PEM 与证书不会因此作为私钥被拒绝。

原生扫描将精确识别的 LLVM 嵌入资料单列为 `native_compiler_metadata`。PE/ELF `gate`
新增 `require_no_compiler_metadata`，**默认 true**；有意发布编译器资料时必须在原生策略
中显式设为 false，其他要求仍有效。该字段不能放进通用扫描策略；`scanRelease` 使用范围
更广的 `check_native_metadata` 开关。改名、归档内的独立 raw/wrapped LLVM bitcode
被识别但不支持解析，输出 `native_metadata_unverifiable` 并将
`native_metadata_scan_completed` 设为 false。合法 JIT 应用可能需要这些输入，退出检查
并不使 IR 保密。普通 Linux ELF 中符合条件的编译器记录可用
[split-elf-debug](../../docs/private-elf-debug.md) 私有分离；PE/Mach-O 只检测，不自动改写。
精确 section 名称、预算和签名前后工作流见[通用发布指南](../../docs/portable-release.md)。

### 客户端选项

| 选项 | 默认值 | 范围 |
| --- | --- | --- |
| `python` | `RELEASEGUARD_PYTHON`，未设置时为 `python` | 单个解释器可执行文件路径/名称，不能是带参数的 shell 命令 |
| `timeoutMs` | `30000` | 整数 `1..600000` 毫秒 |
| `maxOutputBytes` | `4194304` | 整数 `1024..16777216` 字节，stdout 和 stderr 合计 |

建议使用解释器绝对路径。相对文件路径在调用方法时转换为绝对路径。拼错的选项名、
无效功能标识和无效控制参数会在启动 Python 前被拒绝。

检查通过时返回 Python JSON 报告并附加 `exitCode: 0`。
`scanRelease`、`checkProject`、`gate` 和严格模式的 `audit` 完成检查但发现规则不符时，返回
`ok: false`、`exitCode: 3`，不会抛异常。普通 PE `audit` 可以同时返回
`ok: true` 和 `policy_passed: false`；需要让警告阻断流程时传 `{ strict: true }`。

`checkAnalysis` 允许时返回 `authorized: true`、`decision: "allow"`、
`reason: "authorized"`、`exitCode: 0`；拒绝时返回 `authorized: false`、
`decision: "deny"`、固定拒绝原因和 `exitCode: 3`。必需的 `validity` 字段在
授权签名与结构通过前为 null，之后为包含严格 UTC `not_before`、`expires_at`
的不可变对象，区间限制为 1..86400 秒。包装方法会在回调前将拒绝或网关时间复核失败
转成 `AUTHORIZATION_DENIED` 异常。

清单/许可证方法的签名无效属于 CLI 错误；分析授权的签名、范围、时间、发布完整性不符
则属于明确拒绝。文件无法读取、CLI 输入损坏、策略不合法等未完成的检查会抛
`ReleaseGuardError`，其 `code`
为 `CLI_ERROR`，`exitCode` 通常为 2。无效 UTF-8/JSON、重复 JSON 字段、不完整
或互相矛盾的报告、意外的 stderr 和输出超限都不会被当作检查通过。

| 错误码 | 含义 |
| --- | --- |
| `INVALID_ARGUMENT` | 本地参数或选项不合法 |
| `AUTHORIZATION_DENIED` | 授权被拒绝或已失效，受保护回调没有调用 |
| `SPAWN_FAILED` | 无法启动指定解释器 |
| `CLI_ERROR` | Python 检查报错，见 `exitCode` |
| `PROTOCOL_ERROR` | 输出编码、JSON 或报告内容不符合协议 |
| `OUTPUT_LIMIT` | stdout/stderr 合计超过限制 |
| `TIMEOUT` | 超过执行时限 |
| `ABORTED` | 调用方取消操作 |
| `PROCESS_ERROR` | 子进程或输出流异常 |

`CLI_ERROR` 的受限诊断输出保存在 `error.diagnostic`；它不可枚举，也不会自动
拼入错误消息。需要排查时主动读取，该内容可能包含本地路径。超时、取消或输出超限
会终止此次 Python 工作进程。

## 信任边界

调用使用 `spawn`、`shell: false`、关闭的 stdin 和独立 argv，并运行
`python -I -m releaseguard`。隔离模式会从模块查找中排除当前目录和 `PYTHONPATH`，
因此必须将核心安装到所选解释器，仅设置 `PYTHONPATH=src` 不够。
解释器、已安装包和继承的进程环境需要由可信构建/服务环境控制。

检查方法提供本地只读检查；授权包装方法还会在检查通过后调用可信服务明确提供的回调，
不会自行选择或启动任意命令。SDK 不暴露密钥生成、签发、口令输入或能力令牌消费接口。
清单和许可证校验需要预先可信的公钥以及可信的预期产品、版本、
主体值。能控制客户端运行环境的人仍能修改本地检查；最终授权应放在适当的可信服务。
发布策略通过不等于获得防 REA 成功率，Python 核心的 [安全模型](../../SECURITY.md) 仍适用。

## 贡献

直接编辑 `src/` 中的 JavaScript，同步维护 `index.d.ts`，运行 `npm test`。
进程测试只启动受控的 Node.js 测试脚本；集成测试调用已安装 Python 核心，检查
签名校验、拒绝行为、回调准入以及同名模块隔离。授权测试还覆盖调度延迟后过期、
取消、上下文变更和缺少 stdio 的 spawn 失败；受保护回调均不得误执行。
`test/types-smoke.ts` 用于检查类型声明。
新增功能应继续共用 Python 实现，并保留“检查完成且不通过”与“检查未完成”的区别。

## 自 1.0 起的归档分发与 1.3 安装

SDK 与 Python 核心当前版本统一为 1.3.0。自 1.0 起，GitHub Release 提供可直接安装的 SDK 压缩包；
package.json 保持 private 以防误发 npm，未声称 npm registry 发布。已有本地目录安装仍然支持。

```sh
npm install https://github.com/Afloat16/anti-rea-forge/releases/download/v1.3.0/anti-rea-forge-releaseguard-1.3.0.tgz
```

配套 Python 解释器必须已安装 1.3 核心，并通过绝对路径配置。Linux、Windows、macOS
均执行归档安装和真实 CLI 正反对照；具体归档哈希与结果在 Release 附件中。
