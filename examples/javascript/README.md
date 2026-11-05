# JavaScript release checks and authorized analysis / 发布检查与授权分析

This example uses the local JavaScript/TypeScript bridge and the installed Python
core. Read the [English SDK guide](../../packages/releaseguard/README.md) or
[中文接入说明](../../packages/releaseguard/README.zh-CN.md) for setup and API details.

From the repository root, after setting `RELEASEGUARD_PYTHON` to an interpreter
with this repository installed:

```sh
node examples/javascript/scan-release.mjs --root dist --policy examples/policy-portable-release.json
```

The command writes a JSON report. Exit 0 means the configured release checks
passed, exit 3 means a completed check found a policy violation, and exit 2 means
the check could not complete. Passing is not proof that REA cannot analyze the
application. Keep the policy outside `dist`.

先把本仓库安装到所选 Python 解释器，并设置 `RELEASEGUARD_PYTHON`，再从仓库根目录
运行上述命令。检查通过返回 0，规则不符返回 3，检查未完成返回 2。策略文件应放在
`dist` 之外；通过检查不代表应用无法被 REA 分析。

## One saved configuration / 保存一次配置

```sh
python -m releaseguard project-init --root dist --product Demo --out .releaseguard
python -m releaseguard check --config .releaseguard/project.json
```

Use your installed virtual-environment interpreter in place of `python`. From a
Node build script, call `guard.checkProject({ config: ".releaseguard/project.json" })`.
The build scanner does not import or execute the protected application.

将 `python` 换成安装了核心的虚拟环境解释器。Node 构建脚本可调用
`guard.checkProject({ config: ".releaseguard/project.json" })`。扫描发生在构建环境，
不会导入或运行被保护应用。

## A fixed tool behind an authorization gate / 固定工具的前置授权

[authorized-analysis.mjs](authorized-analysis.mjs) demonstrates a fixed
`list_release_entries` tool with the `inspect` scope. It lists release filenames
only after a signed grant and the release manifest pass verification. It does
not launch REA or implement a general MCP proxy. The operator supplies trusted
configuration; the model and target must not choose the public key, expected
identity, release or scope mapping.

The commands assume an existing `dist` and the configuration created above.
Use a fresh path for each output; the CLI does not overwrite files. Keep the
issuer private key outside the release and version control. `keygen` prompts
for an encryption passphrase in an interactive terminal; automated runs should
provide `RELEASEGUARD_PASSPHRASE` from their secret manager.

```sh
python -m releaseguard keygen --private issuer-private.pem --public issuer-public.pem
python -m releaseguard prepare --config .releaseguard/project.json --private issuer-private.pem --release 1.0 --out release-evidence
python -m releaseguard analysis-grant-issue --manifest release-evidence/manifest.json --private issuer-private.pem --product Demo --release 1.0 --subject reviewer --audience analysis-service --operation inspect --ttl 3600 --out reviewer-grant.json

node examples/javascript/authorized-analysis.mjs --manifest release-evidence/manifest.json --root dist --public issuer-public.pem --product Demo --release 1.0 --subject reviewer --audience analysis-service --grant reviewer-grant.json
```

The example returns the tool's JSON result on success. Omit `--grant` to observe
exit 3 with `AUTHORIZATION_DENIED` and no directory-listing callback. An expired
grant, mismatched context or modified release also denies. Unreadable inputs or
other incomplete checks use exit 2. The SDK tests exercise these conditions and
assert callback invocation counts; a production service should log its own
admission decisions without logging grant contents.

`inspect`, `decompile` and `instrument` are separate scopes. This example always
chooses `inspect`; it accepts no model-selected tool or command. A real service
derives `subject` from authenticated session context and configures each tool's
scope in trusted code. The handler must use the same captured, immutable absolute
root; the wrapper cannot inspect or rewrite the handler's tool arguments. Mediate
every tool path and hold the release immutable throughout the operation. Call the
gate before every operation, never from the protected application's startup or
ordinary runtime path.

Python verifies validity around hashing; the JavaScript wrapper rechecks it with
the trusted gateway clock before callback admission. This covers expiry during
worker shutdown or scheduling. It is not an atomic handoff, and expiry does not
interrupt a handler that has already begun.

This requires cooperation from the analysis service. Users with an independent
REA installation or direct file access can analyze outside this gateway.
Signatures cannot force another model to refuse. Offline grants can be reused
during their lifetime and have no online revocation; use service policy for
authentication, revocation and auditing when required.

此示例把 `list_release_entries` 固定映射到 `inspect`，在签名授权和发布清单校验通过
后才读取目录列表。它不是 REA 启动器，也不是通用 MCP 代理。上述命令中的公钥、
产品、版本、身份与 audience 由可信操作者提供；真实服务应从已认证会话取得身份，
固定每种工具的操作范围，不允许模型或目标文件替换这些值。

省略 `--grant` 可验证缺少授权时返回 3 且不会进入目录列表回调；过期、范围不符、
发布产物被修改同样拒绝。输入无法读取或检查无法完成时返回 2。回调必须使用已经捕获
的不可变配置，包装器无法检查或改写其内部工具参数。保持整个发布目录在操作期间
不可变，所有相关工具调用都经过网关，每次操作前重新检查。不要把此检查放进被保护
应用的正常启动或业务运行路径。

Python 验证后，JavaScript 还会在回调准入前用可信网关时钟复核有效期，避免调度延迟
造成过期后准入；但它不是原子交接，也不自动中止已开始的回调。

该边界依赖分析服务接入，不能约束独立运行的 REA 或直接读取文件的人，也不能靠签名
强制其他模型拒绝。离线授权在有效期内可重复使用，没有在线撤销；额外的身份认证、
撤销和审计由实际服务实现。生成的私钥、分析者授权应保持在发布目录与版本控制之外。
