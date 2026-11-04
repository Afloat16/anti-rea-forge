# Portable release checks / 跨语言发布检查

Anti-REA Forge 0.5 adds a **Python release scanner usable from any build system** and
a **JavaScript ESM bridge with TypeScript declarations**. The scanner reads a staging
directory without requiring an EXE, DLL or ELF entry file. The existing native `gate`
still provides PE/ELF structure, symbol and mitigation checks.

本版用 Python 统一维护扫描规则与安全判定，通过 JavaScript/TypeScript 接入 Node.js
构建流程；C++ 只保留在原生内存和构建组件中。贡献一条规则不需要 C++ 编译器。
选择依据与固定 REA 6.8.0 源码见[本轮审阅](rea-source-review-2026-11-04.zh-CN.md)。

## Quick start

From the repository root, create a virtual environment and install the core:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m releaseguard scan-release --root ./dist --policy examples/policy-portable-release.json
```

Windows PowerShell activation: `.\.venv\Scripts\Activate.ps1`. Replace `./dist` with
your completed, nonempty release staging directory. Keep the policy outside that directory.
The command inspects files only; it does not execute the application, delete source maps,
rewrite packages or change the release. Address each finding in your build configuration
and rerun the check before signing or distributing the result.

先完成构建，再扫描实际要发布的目录。策略应由可信构建流程维护，不能由待检查的包自行决定。
这份默认策略允许普通 `.py`、`.js`、`.ts` 源文件，适合本来就公开源码的项目；是否发布源码
属于项目策略。需要限制文件集合时配置 `allowed_release_files`，不要把所有语言都套用
“禁止一切源码文件”的原生软件策略。

### Python API

```python
from releaseguard.core import GuardError
from releaseguard.distribution import scan_release

try:
    report = scan_release("dist", "examples/policy-portable-release.json")
except (GuardError, OSError) as error:
    raise SystemExit(f"Release check could not complete: {error}")
if not report["ok"]:
    for finding in report["findings"]:
        print(finding)
    raise SystemExit(3)
```

### JavaScript and TypeScript

The local package is `packages/releaseguard`. Use Node.js 22 or newer and install the
Python core into the interpreter selected for the SDK. There is no npm registry release
to install by name at this stage.

```javascript
import { createReleaseGuard } from "./packages/releaseguard/src/index.js";

const guard = createReleaseGuard({
  python: process.env.RELEASEGUARD_PYTHON,
  timeoutMs: 30_000,
});
const report = await guard.scanRelease({
  root: "./dist",
  policy: "./examples/policy-portable-release.json",
});
console.log(JSON.stringify(report, null, 2));
process.exitCode = report.ok ? 0 : 3;
```

Set `RELEASEGUARD_PYTHON` to the virtual environment executable's absolute path:
`.venv/bin/python` on Linux/macOS or `.venv\Scripts\python.exe` on Windows. The bridge
uses `-I -m releaseguard`, separates all arguments and does not invoke a shell. It does
not load Python modules from the inspected working directory or from `PYTHONPATH`.
Python must be installed into the chosen interpreter; a user-site-only installation
is not available in isolated mode.

For local package installation, cancellation, timeout/output budgets, error types and
all five read-only APIs, see the [English SDK guide](../packages/releaseguard/README.md)
or [中文 SDK 指南](../packages/releaseguard/README.zh-CN.md). The SDK is a build/server
tool, not a browser library or a security boundary on an attacker-controlled client.

## Policy v1

Portable policies are separate from native `gate` policies. Both have `version: 1`, but
native-only fields such as `formats`, `required_pe_flags` or `require_native` are rejected
by `scan-release` instead of being ignored. Unknown fields, duplicate JSON members,
invalid types, ambiguous paths and invalid resource limits are errors.

| Field | Default | Behavior |
| --- | --- | --- |
| `version` | Required: `1` | Portable policy version |
| `forbid_literals` | `[]` | Up to 64 explicit strings, each 1–1024 characters; match UTF-8, UTF-16 LE/BE and UTF-32 LE/BE |
| `forbid_extensions` | `[".pdb", ".ilk", ".map"]` | Case-insensitive final extension; lowercase `.extension` entries |
| `forbid_path_components` | `[".git", ".svn", ".hg", ".env"]` | Exact path components, compared case-insensitively; no globs |
| `forbid_file_sha256` | `[]` | Reject exact known file digests, including expanded ZIP members |
| `allowed_release_files` | Omitted | Optional nonempty exact list of physical files relative to the release root; reject missing or extra files |
| `check_private_keys` | `true` | Detect supported PEM private-key begin markers in the five encodings |
| `check_source_maps` | `true` | Detect `sourceMappingURL` and the quoted `sourcesContent` marker in the five encodings |
| `scan_zip_archives` | `true` | Inspect recognized ZIP content recursively; disabling inspection creates a finding for each detected ZIP |
| `max_file_bytes` | `67108864` (64 MiB) | Limit each physical file and each expanded member; maximum 512 MiB |
| `max_total_bytes` | `268435456` (256 MiB) | Combined physical and expanded bytes across the complete scan; maximum 512 MiB |
| `max_archive_depth` | `2` | Permit a ZIP and one nested ZIP level; range 1–8 |
| `max_archive_entries` | `10000` | Aggregate ZIP entries, including directories and nested containers; maximum 20,000 |
| `max_files` | `20000` | Physical release-file limit; maximum 20,000 |

There are also fixed safety ceilings for inventory entries and report findings. A scan
that exceeds them fails instead of silently truncating results. The global byte budget
counts a nested archive's bytes and its expanded members: it bounds work rather than
estimating the final install size.

The private-key markers cover PKCS#8, encrypted PKCS#8, RSA, EC, DSA and OpenSSH PEM
headers. Public-key PEM headers do not match this check. A marker is evidence of possible
disclosure, not proof of a valid key, and its absence is not proof that no secret exists.
Binary DER keys, credentials outside the configured literals, encrypted/encoded strings,
split values and other secret formats need additional controls.

源映射检查采用明确的字节标记，可能命中文档或有意公开的调试材料。关闭
`check_source_maps` 不会自动移除 `forbid_extensions` 中的 `.map`；策略中的各项检查
独立生效。`sourceMappingURL` 无论指向 `.map`、任意文件名还是内联 data URI 都会命中。
该规则不是 JavaScript/JSON 语义解析器，不能识别任意转义或转换后的等价表示。

## Archives and paths

The scanner recognizes ZIP by structure/magic as well as common extensions such as
`.zip`, `.jar`, `.war`, `.ear`, `.whl`, `.nupkg`, `.vsix`, `.apk` and `.aab`. Renaming an
ordinary ZIP does not hide its members. Only **stored and deflated** entries are supported.
Members are read in memory under the byte budgets and are never extracted to filesystem
paths or executed.

Traversal, absolute/ambiguous names, Windows path aliases, case collisions, repeated
members, file/directory collisions, links and special files are rejected. Physical files
also undergo identity checks before and after reading, and the directory is inventoried
again to catch ordinary concurrent additions or removals.

The first version deliberately rejects encrypted entries, unsupported compression,
ZIP64, multipart ZIP, Unicode Path override extra fields and malformed metadata.
Self-extracting/prefixed archives, concatenated ZIPs and unindexed gaps between members
are also rejected: accepting just the last archive could leave earlier compressed content
uninspected. Standard UTF-8 names and checked data descriptors are supported. Local and
central headers, actual bounded DEFLATE output, stream completion and CRC must agree;
directory entries must contain an actually empty payload.

Detected ASAR, tar, gzip, bzip2, xz, zstd,
7z and RAR containers produce `unsupported_archive` findings. `archive_not_scanned`
indicates that ZIP inspection was explicitly disabled. Neither finding can yield `ok: true`.
Archive detection is not a universal file-format classifier: an unrecognized, disguised
or custom container can still contain uninspected encoded data.

本地文件检查无法覆盖部署服务器的 `SourceMap` HTTP 响应头、远端 source map 地址、
CDN 缓存和发布目录之外的调试资料。要检查这些对象，应另外审查实际部署和访问权限。
维护者控制的稳定构建目录是前提；身份与时间戳检查不是抗恶意父目录竞争的沙箱，
也不能阻止检查结束后替换文件。实际安装/加载流程应继续验证签名清单。

## Reports and exit codes

| Exit | Meaning | Action |
| --- | --- | --- |
| `0` | Completed configured checks and found no violations | Continue the build's other verification steps |
| `3` | Findings, including an unsupported or deliberately unscanned detected archive | Block publication and review the findings |
| `2` | Invalid policy, I/O/format error, resource exhaustion or incomplete inspection | Block publication; fix the error and rerun |
| `130` | Interrupted/cancelled command | Treat the scan as incomplete |

Normal reports contain `ok`, the resolved `root`, a physical `files` inventory with
sizes/SHA-256 values, `findings`, `checks` and `notes`. A finding identifies a code, a
physical path and, where applicable, a `rule_index`, encoding and an `archive_members`
array. Nested member names are separate from the physical path, avoiding delimiter
ambiguity. Matched file contents are not included in the report; filenames and the root
path remain visible and should be considered before publishing a report.

`checks.scan_completed` describes execution of the configured scan. An unsupported or
deliberately unscanned detected archive also sets `checks.archive_scan_completed` to
`false`. Check `ok` and all findings; even a true archive-completion flag only describes
recognized containers, not every conceivable file format.
Error reports go to stderr with `ok: false`; they are not partial passing reports.
The JavaScript bridge returns validated exit-0/3 reports and throws `ReleaseGuardError`
for tool/protocol/process failures. Callers should not catch such errors and continue a
release as if it had passed.

## Practical protection and evidence

REA's pinned source-map readers consume `sourcesContent` and map source locations;
its Frida integration exposes attach/spawn and caller-provided scripts. The
[source review](rea-source-review-2026-11-04.zh-CN.md) connects those code paths to this
release's choices. [ECMA-426](https://tc39.es/ecma426/) specifies embedded source content,
inline annotations and HTTP source-map headers. [Python's ZIP guidance](https://docs.python.org/3/library/zipfile.html#decompression-pitfalls)
explains why untrusted expansion requires resource limits.

These checks reduce avoidable material shipped to an analyst. They do not make shipped
code confidential, stop a live memory hook, prevent an analyst from rebuilding a map,
or make a patched client's authorization trustworthy. Keep issuer keys and genuinely
restricted operations in the trusted service, using the existing
[request-bound authorization](runtime-protection.md) where appropriate.

Run `python -m unittest tests.test_distribution tests.test_distribution_cli -v` for the
portable regression suite. [The validation record](testing-v0.5-2026-11-04.md) lists actual
results and untested scope. Source review and functional tests are distinct from a full
REA/provider/model evaluation, which this update does not claim to have completed.
