# Complete private-content checks / 私有内容包含检查

Version **1.4** extends the live `private_input_files` boundary introduced in 1.3.
The complete, unchanged bytes of a declared private file must not occur anywhere
inside an inspected public payload. A build header, trailing newline or concatenated
bundle no longer avoids this check. This is a publication control: already disclosed
source remains readable, and equivalent rewritten logic is outside this byte profile.

## Configure it once

Run from the project directory after the private inputs exist. The public `dist`
directory may be built later:

```sh
python -m releaseguard project-init --root dist --product MyApp --out .releaseguard \
  --private-input-file service/private_quote.py \
  --private-input-file service/model.dat \
  --asset-key-file issuer/asset.key
python -m releaseguard check --config .releaseguard/project.json --format text
```

Only include references your application actually uses. Omit the key option if no
external asset key is used; its file must contain exactly 32 raw bytes. Initializer
arguments resolve from the working directory. The generated configuration stores
paths relative to its own directory, validates every supplied reference before
writing, and rechecks them after writing. Invalid references do not leave a new
configuration bundle. Subsequent `check`, `prepare` and SDK `checkProject` calls
automatically use the saved references. An empty extra list does not clear them.

The same private-input option remains repeatable on `scan-release`, `check` and
`prepare`. Python uses `private_input_files`; JavaScript uses `privateInputFiles`.
Configuration and policy remain outside the public release.

## What is inspected

| Public layout | Result when it contains the entire unchanged reference |
| --- | --- |
| Renamed exact file | Existing complete-payload SHA-256 comparison rejects it |
| File with a header, footer or extra newline | Complete-content comparison rejects it |
| Bundle containing the entire source or data reference | Complete-content comparison rejects it |
| Stored/deflated ZIP, including inspected nested ZIP/ASAR members | The same comparison applies to every expanded payload |
| Packed ASAR or validated unpacked sibling | The same comparison applies at the actual payload location |
| Semantic rewrite, minification, compilation, encoding or partial copy | Outside this exact-byte profile; use other build and architectural controls |

The rule does not import or execute source. Container inspection retains its existing
format, path, depth and byte limits. Unsupported containers are not counted as
successful content inspection. A private byte sequence can occur in both a packed
container and its expanded member; these locations are separate findings, not
independent vulnerabilities or additional recovery successes.

## Bounded matching

Private references retain the 1.3 constraints: **at most 64 files, 1 byte to 8 MiB
per file and 64 MiB total**. They must be regular external files with trusted ancestor
directories. Missing files, directories, special files, symlinks and reparse points
fail. Snapshots contain length, identity, SHA-256 and a prefix of at most 64 bytes;
the full set of private contents is not held in memory for matching.

For a reference longer than 64 bytes, the prefix locates candidates in 128 KiB scan
windows. Each candidate is verified over its **entire original length** using a
streamed SHA-256. A prefix alone is never positive evidence. References of 64 bytes
or less use their entire bytes as the locating value, so even a one-byte reference
is checked. Declaring a very short or common private value can therefore reject
ordinary public files containing that value; prefer meaningful complete references.

Exact duplicate references share candidate verification but retain their individual
rule indices. Overlapping candidates, locating values split across windows and
references larger than a scan window are supported. The locating search is bounded
by the existing release byte budget and the 64-reference limit.

| Additional resource limit | Scope | Exhaustion |
| --- | --- | --- |
| 4,096 candidate verifications | One complete release scan, across files and expanded members | `private_content_candidate_limit` |
| 512 MiB of candidate verification reads | Same scan; each proposed span is charged before reading | `private_content_verification_limit` |

The scan reports `private_input_unverifiable` and sets
`private_input_scan_completed: false` on exhaustion. It stops additional containment
work while preserving independent complete-file and other checks. The release remains
blocked. A budget refusal is not a positive content match or proof that no private
content exists. Do not split a release or drop required references just to make its
budget report pass; review the build layout and inspect the complete intended release.

## Evidence and reports

| Field | Meaning |
| --- | --- |
| `private_inputs_checked` | Number of declared references |
| `private_input_profile` | `exact-content/v1`, or `null` when no reference is configured |
| `private_input_scan_completed` | Whether this configured inspection completed within its limits |
| `private_input_payloads_checked` | Payloads entering this check before any budget refusal |
| `private_input_candidate_checks` | Candidate verification attempts charged |
| `private_input_verification_bytes` | Full-length candidate bytes charged; short exact anchors need no additional read |

Positive findings retain code `private_input_exposure` and `rule_index`. New contained
matches add `representation: "contained-bytes"`; existing complete-file matches
keep their previous shape. No reference paths, contents, anchors or separate reference
hashes enter reports. Public file/member paths and the public inventory's hashes
remain visible. `--format text` supplies a fixed explanation and next action; JSON
remains the default for automation and the SDK.

`prepare` rechecks current input identities and bytes through signing and final
publication verification. A final failure removes its newly created sidecar bundle.
These are ordinary filesystem consistency checks, not an atomic snapshot against a
malicious directory owner. Keep the release, private references, configuration,
interpreter and ancestors controlled and stable throughout the operation.

The [v1.4 assessment](rea-defense-v1.4.0.zh-CN.md) records the verified official v1.3
baseline, actual REA observations, normal controls, remaining rewrite boundary and
measured matching cost. The [private-service example](../examples/private_service)
shows where the implementation can live when it should remain outside the client.

## 中文接入要点

1. 在 `project-init` 时用 `--private-input-file` 登记真实私有文件，初始化会校验输入并保存
   相对配置路径；以后无需每次重复参数。命令行路径相对当前目录，保存的路径相对 `project.json`。
2. 新规则检查整个私有文件的原始内容是否出现在公开文件或已展开成员中的任意位置；添加头尾
   或直接串接不能再绕过。它不识别等价改写、编译、编码或部分复制。
3. 报告同时看 `ok`、引用数量、`private_input_scan_completed` 和 findings。未配置引用
   与检查完成是两回事；超预算明确拒绝，不能算作“已确认没有泄露”。
4. 很短的引用会按字节如实匹配，可能出现在普通公开文件中。应登记真正需要隔离的完整资料，
   配合构建输入审查与可信服务部署使用。
