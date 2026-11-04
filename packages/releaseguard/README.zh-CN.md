# 面向 JavaScript / TypeScript 的 Release Guard

[English](README.md)

这是对 Anti-REA Forge Python CLI 的小型 Node.js 接入层。实现使用可直接运行的
JavaScript ESM，提供 TypeScript 类型声明；不需要 JavaScript 编译步骤，也不另写
一套密码学实现。Web、Node.js 和 Electron 项目可以把同一套发布检查接入自己的构建流程。

需要 **Node.js 22+、Python 3.10+**，并把本仓库的 Python 包安装到所选解释器。
该包目前是 **本地、private 工作区包**，尚不声称已发布到 npm 注册表。

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

## API 与返回值

`createReleaseGuard(options?)` 提供五个异步方法：

| 方法 | 必需参数 | 可选参数 | 对应 Python 命令 |
| --- | --- | --- | --- |
| `scanRelease(options, controls?)` | `root`、`policy` | — | `scan-release` |
| `audit(path, options?)` | PE 文件路径 | `strict`、`signal` | `audit` |
| `gate(options, controls?)` | `artifact`、`policy` | `root` | `gate` |
| `verifyManifest(options, controls?)` | `manifest`、`root`、`publicKey`、`product` | `release` | `manifest-verify` |
| `verifyLicense(options, controls?)` | `license`、`publicKey`、`product` | `subject`、`requiredFeatures` | `license-verify` |

`controls` 可传 `{ signal: controller.signal }`，用于取消请求。
[index.d.ts](index.d.ts) 包含 TypeScript 参数、报告和错误码类型。

客户端选项：

| 选项 | 默认值 | 范围 |
| --- | --- | --- |
| `python` | `RELEASEGUARD_PYTHON`，未设置时为 `python` | 单个解释器可执行文件路径/名称，不能是带参数的 shell 命令 |
| `timeoutMs` | `30000` | 整数 `1..600000` 毫秒 |
| `maxOutputBytes` | `4194304` | 整数 `1024..16777216` 字节，stdout 和 stderr 合计 |

建议使用解释器绝对路径。相对文件路径在调用方法时转换为绝对路径。拼错的选项名、
无效功能标识和无效控制参数会在启动 Python 前被拒绝。

检查通过时返回 Python JSON 报告并附加 `exitCode: 0`。
`scanRelease`、`gate` 和严格模式的 `audit` 完成检查但发现规则不符时，返回
`ok: false`、`exitCode: 3`，不会抛异常。普通 PE `audit` 可以同时返回
`ok: true` 和 `policy_passed: false`；需要让警告阻断流程时传 `{ strict: true }`。

签名无效、文件缺失、策略不合法等 CLI 错误会抛 `ReleaseGuardError`，其 `code`
为 `CLI_ERROR`，`exitCode` 通常为 2。无效 UTF-8/JSON、重复 JSON 字段、不完整
或互相矛盾的报告、意外的 stderr 和输出超限都不会被当作检查通过。

| 错误码 | 含义 |
| --- | --- |
| `INVALID_ARGUMENT` | 本地参数或选项不合法 |
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

此 API 只提供本地只读检查，不执行被检查应用，也不暴露密钥生成、签发、口令输入或
能力令牌消费接口。清单和许可证校验需要预先可信的公钥以及可信的预期产品、版本、
主体值。能控制客户端运行环境的人仍能修改本地检查；最终授权应放在适当的可信服务。
发布策略通过不等于获得防 REA 成功率，Python 核心的 [安全模型](../../SECURITY.md) 仍适用。

## 贡献

直接编辑 `src/` 中的 JavaScript，同步维护 `index.d.ts`，运行 `npm test`。
进程测试只启动受控的 Node.js 测试脚本；集成测试调用已安装 Python 核心，检查
签名校验、拒绝行为以及同名模块隔离。`test/types-smoke.ts` 用于检查类型声明。
新增功能应继续共用 Python 实现，并保留“检查完成且不通过”与“检查未完成”的区别。
