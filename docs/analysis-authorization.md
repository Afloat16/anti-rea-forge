# Build-only setup and analysis authorization / 构建接入与分析授权

v0.6 adds editable project setup, one-command release preparation and a
deterministic authorization check for cooperating analysis gateways. The
protected application does not import Release Guard, call a verifier at startup
or run a background scanner. Release files are read without rewriting.

**The enforced boundary is a gateway that checks before calling its fixed tool
handler. A notice cannot force an unrelated AI or REA instance to refuse.**
The [pinned REA review](rea-agent-authorization-2026-11-05.zh-CN.md) explains why.
Signatures authenticate a previously trusted key and document contents; they do
not establish legal ownership or replace the software license.

## 1. Initialize once, check after each build

Install this checkout in a Python 3.10+ virtual environment:

```bash
python -m venv .venv
```

Activate with `source .venv/bin/activate` on Linux/macOS, or
`.\.venv\Scripts\Activate.ps1` in Windows PowerShell. Then:

```bash
python -m pip install -e .
python -m releaseguard project-init --root ./dist --product MyApp
```

This creates a **new** `.releaseguard` directory containing `project.json`, an
editable `policy.json` and an unsigned `ANALYSIS_NOTICE.md`. It does not create
or modify `dist`, which may be built later. An existing root must be a regular
directory, not a symlink/reparse point; this avoids silently checking an old
release behind a moving link. Existing output directories are not merged or
overwritten. To select another location, add `--out ./my-guard-config`; its
parent directory must exist.

After your normal build creates the complete, immutable release in `dist`:

```bash
python -m releaseguard check
```

From another working directory, specify the config path:

```bash
python -m releaseguard check --config /path/to/project/.releaseguard/project.json
```

The config's `root` and `policy` resolve relative to the config file. Generated
relative paths survive moving the entire project; Windows locations on different
drives use absolute paths. Unknown fields, ambiguous JSON, links/special config
files and oversized input are rejected. JSON configuration cannot run commands
or load plugins. Product/release identifiers use the same rules as grants.

Review the initial policy for your release. It permits ordinary source files,
checks configured debug extensions and source-map/private-key markers, and
inspects supported ZIP members under explicit budgets. It is heuristic, not a
complete secret detector. Unsupported recognized containers do not pass.
See [portable scanning](portable-release.md). Keep private literal rules in the
trusted build environment rather than distributing them as public notices.

## 2. Prepare signed sidecars without changing the application

Use your controlled signing setup if you already have an issuer key. Otherwise,
create a private directory **outside both the source checkout and the release**:

```bash
mkdir ../releaseguard-keys
python -m releaseguard keygen --private ../releaseguard-keys/issuer-private.pem --public ../releaseguard-keys/issuer-public.pem
```

Key generation prompts for a passphrase. Automation may supply
`RELEASEGUARD_PASSPHRASE` through a secret manager; never put it in command-line
arguments, source files or shared logs. Keep the private key in the issuer
environment. Distribute and pin the public key through an independently trusted
channel.

Complete all packaging and code signing, freeze the release, then run:

```bash
python -m releaseguard prepare --private ../releaseguard-keys/issuer-private.pem --release 1.0.0 --out ./MyApp-1.0.0.guard
```

`prepare` uses the saved config, scans the release, signs the inventory using the
existing manifest format, and compares the signed inventory with the scan's
path/size/SHA-256 records. Findings or a difference prevent publication. A fresh
directory **outside `dist`** contains:

| Output | Purpose |
| --- | --- |
| `manifest.json` | Existing Ed25519-signed complete release inventory |
| `ANALYSIS_NOTICE.md` | Public unsigned English/Chinese explanation with product, release, manifest digest and issuer fingerprint |
| `release-report.json` | Unsigned build summary, including file count and absence of runtime integration |

Only the manifest and the later analysis grant are signed. The notice/report are
not authorization evidence. Never use the notice's fingerprint to choose or
replace the trusted key. Binary signature bytes remain unchanged because the
binary is not rewritten; this does not verify an Authenticode trust chain.

Keep the release, configuration, policy and ancestor directories under trusted
build control. The comparison is not an atomic snapshot. Publish and analyze the
same immutable files. A new release needs a fresh output directory and manifest.

## 3. Issue a bounded analysis grant

The trusted issuer first approves the analyst and operations, then signs:

```bash
python -m releaseguard analysis-grant-issue --manifest ./MyApp-1.0.0.guard/manifest.json --private ../releaseguard-keys/issuer-private.pem --product MyApp --release 1.0.0 --subject analyst-01 --audience team-analysis --operation inspect --operation decompile --ttl 3600 --out ../releaseguard-keys/analyst-01.analysis-grant.json
```

The manifest must have been signed by the same issuer key. Issuance checks its
signature/schema without reading or executing the application. The independent
`analysis-grant` signing domain binds:

- SHA-256 of the canonical **entire signed manifest envelope**, including its
  signed metadata, not merely a filename or version string.
- Exact `product`, `release`, authenticated `subject` and gateway `audience`.
- Independent `inspect`, `decompile`, `instrument` scopes. No hierarchy,
  wildcard or automatic inheritance is provided.
- A fresh grant ID and a UTC validity interval. The default is 3,600 seconds and
  maximum is 86,400 seconds; expiry is exclusive.

Each identity is NFC Unicode, nonempty, without surrounding whitespace or control
characters, at most 128 characters and 256 UTF-8 bytes. Files are created
exclusively with POSIX mode `0600`; protect the directory with suitable Windows
ACLs. Grants are readable and copyable, and can be reused until expiry. They are
not encryption, proof of possession, one-time tokens or online revocation.
The existing server `capability-consume` protocol is separate.

The issuer must authenticate and authorize before signing. This CLI cannot decide
entitlement, and possessing an arbitrary key does not establish authority for
another publisher's software.

## 4. Check at the cooperating gateway

The gateway obtains identity from its authenticated session and fixes the key,
release snapshot, audience and operation mapping through trusted deployment
configuration. Expected values must not come from model text or target files.

```bash
python -m releaseguard analysis-check --manifest ./MyApp-1.0.0.guard/manifest.json --root ./dist --public ../releaseguard-keys/issuer-public.pem --product MyApp --release 1.0.0 --subject analyst-01 --audience team-analysis --operation inspect --grant ../releaseguard-keys/analyst-01.analysis-grant.json
```

Remove `--grant` to observe `grant_required`. Request `instrument` with the example
grant to observe `operation_not_granted`. Missing files or malformed input are
errors, never successful checks.

| Exit | Meaning | Required caller behavior |
| --- | --- | --- |
| `0` | Complete check allowed this exact context | May call its matching fixed handler, retaining ordinary host permissions |
| `3` | Denial report, or build-policy findings | Do not invoke the operation / publish the release |
| `2` | Input, process or verification could not complete | Do not invoke the operation / publish |
| `130`, any other exit, timeout or cancellation | No completed authorization | Do not invoke the operation |

Direct consumers must validate the complete report. Allow requires `ok` and
`authorized` true, `decision: "allow"`, `reason: "authorized"`, and all four
checks true: `grant_signature`, `grant_scope`, `grant_time`, `release_integrity`.
`validity` contains verified `not_before` and `expires_at` UTC timestamps after
grant authentication, or `null` when no grant has been authenticated. A non-null
validity interval alone is not an allow decision.

Invalid grants are rejected before reading the release directory. Allowed grants
trigger complete inventory/hash verification and a second clock check after
hashing. There is no allow cache. Fixed denial codes avoid copying target contents
into reports. Input/parse errors go to stderr with exit 2.

The CLI prints a decision; ignoring it provides no enforcement. It does not
launch or sandbox a tool. It is not a ready-made Claude Code hook: host hook
protocols and failure handling differ, and exit 3 is not a universal block signal.

## 5. Put the JavaScript handler behind the check

The local plain-JavaScript SDK includes TypeScript declarations and no npm runtime
dependencies. It invokes the installed Python verifier in isolated mode and is not
published to npm. Choose the installed interpreter with client `python` or
`RELEASEGUARD_PYTHON` if the default `python` is not the installed environment.

```javascript
import { readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { createReleaseGuard } from "./packages/releaseguard/src/index.js";

const guard = createReleaseGuard();
// Operator configuration + an already authenticated identity.
const request = Object.freeze({
  manifest: resolve("MyApp-1.0.0.guard/manifest.json"),
  root: resolve("dist"),
  publicKey: resolve("../releaseguard-keys/issuer-public.pem"),
  grant: resolve("../releaseguard-keys/analyst-01.analysis-grant.json"),
  product: "MyApp", release: "1.0.0", subject: "analyst-01",
  audience: "team-analysis", operation: "inspect",
});
const entries = await guard.withAnalysisAuthorization(request, async () => {
  // The fixed operation uses the same immutable target that was verified.
  return readdir(request.root);
});
console.log(entries);
```

After a valid report, the wrapper checks its trusted clock against the authenticated
interval again immediately before the handler, covering delays after Python's
check. Denial, invalid protocol, process failure, timeout, expiry or cancellation
before admission prevents the callback. It invokes the handler once and does not
retry errors. Cancellation or expiry after the handler starts does not terminate
it; execution-time leases and cancellation belong to the operator.

Do not start REA before checking, pass a pre-started promise, catch denial and
continue, or let a model select arbitrary callbacks. The wrapper cannot inspect or
rewrite the callback's actual tool arguments. Use captured immutable configuration,
the same target, and a fixed tool-to-scope mapping. An `inspect` callback must not
dispatch arbitrary decompilation or instrumentation. Check and use are not an
atomic transaction: keep the snapshot immutable through completion.

The [runnable example](../examples/javascript/authorized-analysis.mjs) implements
a fixed directory-listing operation and does not launch REA. See the
[SDK guide](../packages/releaseguard/README.md) for types and errors.
`checkAnalysis` and the Python API only return reports; the caller must enforce them.

## 6. Performance and reproducible evidence

The new commands/SDK belong in the build or analysis environment. They add no
module import, branch, network request or timer to the protected application.
Existing optional native runtime components retain their own integration costs.

Tests compare target bytes, sizes, modification times and modes across setup,
preparation and verification. Reproduce the synthetic observation with:

```bash
python benchmarks/analysis_boundary.py --out analysis-boundary.json
```

It records build/preflight time, unchanged targets and negative authorization
controls without executing its target or starting REA. Timings depend on storage,
cache state and hardware; they do not measure an application workload or a model
refusal rate. A scanner running alongside a production app can still compete for
resources, so use CI or a separate release stage.

See [validation](testing-v0.6-2026-11-05.md),
[observations](results/analysis-boundary-2026-11-05.json) and
[security boundaries](../SECURITY.md).

## 中文使用要点

发布者初始化一次配置，再在正常构建后执行 `check`；需要签名证据时执行 `prepare`。
命令只读发布文件，将说明、报告和清单放在发布目录外，不给原软件添加启动验签、
后台扫描或业务路径检查。已有配置/输出不会覆盖，新版本使用新输出目录。

协作分析方先认证用户，再固定可信公钥、版本、发行快照、audience 和操作 scope。
grant 绑定这些值和完整 signed manifest；三个 scope 互不包含，默认一小时、最长一天。
私钥只留在签发环境；普通 subject 字符串不能代替身份认证。

`withAnalysisAuthorization` 将拒绝落实到回调之前。缺少/过期/伪造授权、身份或范围
不符、产物变化、验证进程失败、协议错误及准入前取消都不会调用 handler；在 Python
校验完成之后、实际回调之前还会复核有效期。handler 必须使用同一份不可变配置和目标。
该机制不会终止已经开始的任务，也不是原子的检查与执行事务。

公开说明是正常流程说明，不是系统提示词、法律权属证明、授权凭据或公钥信任来源，
不会替换原软件许可证。未接入的 AI、直接启动的 REA、删除本地检查的操作者不受
这个 SDK 控制。签名授权不能让第三方模型必然拒绝逆向。

这一版通过不进入应用运行路径满足性能目标；构建扫描与分析前验签仍有 CPU/I/O 成本。
字节一致检查支持“没有修改原程序”的结论，不代表所有应用性能都已实测。授权无在线
撤销、无一次性消费；还需只读快照或等价的不可变部署来处理检查后文件替换问题。
