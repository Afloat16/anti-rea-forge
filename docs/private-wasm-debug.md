# Private WebAssembly metadata / 私有 Wasm 调试资料

`split-wasm-debug` separates supported private debug metadata from an owned
WebAssembly core module before signing or packaging. It keeps the **complete
original module** in a private file and produces a public module with the
recognized debug custom sections removed. It never executes the input or fetches
a debug URL.

## What changes

| Section | Public output | Reason |
| --- | --- | --- |
| `name` | Removed | Can expose private module, function, parameter and local names |
| `.debug_*`, `.zdebug_*` | Removed | Conventional DWARF/debug payloads; contents are not individually decoded |
| `sourceMappingURL`, `external_debug_info` | Removed | Pointers to separately hosted debug information |
| Standard sections: imports, exports, code, data, etc. | Exact original bytes and order | Keep the executable module content intact |
| `linking`, `reloc.*` | Input rejected before output creation | Linker symbols can survive name removal; finish final linking instead of deleting data a linker may require |
| Other custom sections, including `producers` and application data | Exact original bytes and order | They may be required by a consumer; no confidentiality claim is made for them |

The splitter compares every retained section before publication, reads back both
outputs, and verifies the original input identity again. Outputs must be new
files under existing trusted parent directories. The public and private trees
must be distinct and nonoverlapping; the original must be outside the public
tree. It rolls back files it created on failure. This is a trusted build operation,
not a filesystem sandbox or an atomic transaction across directories.

## Use it

```sh
mkdir public-wasm private-wasm
python -m releaseguard split-wasm-debug \
  --input build/pricing.wasm \
  --public public-wasm/pricing.wasm \
  --private private-wasm/pricing.original.wasm
python -m releaseguard scan-release \
  --root public-wasm --policy examples/policy-portable-release.json
```

Publish `public-wasm` only. Keep `private-wasm`, the original build, private maps
and symbol artifacts outside the served tree, installer, archive and CDN. Signing
must follow splitting because the module bytes change. Public output permissions
follow the input's ordinary permission bits; the private file uses restrictive
creation permissions supported by the host.

Default portable inspection (`check_native_metadata: true`) recognizes core Wasm
by magic rather than extension. A renamed module and a module inside inspected
ZIP or ASAR content receive the same checks. Findings use the existing
`native_debug_metadata`, `native_symbol_table` and `native_metadata_unverifiable`
codes with `format: "wasm"`. Full module instruction/type validation is **not**
performed by the scanner; its report explicitly describes a section-envelope
check. No external Wasm tool or Node installation is needed for production
inspection or splitting.

Since 1.2, recognized `linking` or `reloc.*` sections cause
`native_metadata_unverifiable` with reason
`linker_metadata_requires_final_link`. The completion flag is false: the scanner
recognizes the section names but does not parse their symbol or relocation
tables. The splitter refuses the input without creating either output. Some
such modules are executable, including the regression fixture; this is a
conservative release profile, not a claim that every relocatable module is invalid.

## Exact supported profile

The parser accepts the core-v1 magic/version and bounded standard/custom section
envelopes, including legal padded unsigned LEB32 values. It checks declared
lengths, standard-section order/uniqueness, UTF-8 custom names and inspection
budgets. Unknown standard section IDs, component-model modules, ambiguous private
section duplicates, NUL-containing custom names and malformed envelopes are
rejected. Limits are 8,192 sections, 4,096 bytes per custom name and 1 MiB of total
custom names; splitting additionally limits the whole module to 64 MiB.

Applications that inspect custom sections can observe their removal. Retaining
the executable sections does not prove all application-level behavior unchanged;
run the actual application's functional and interoperability checks. The owned
corpus below exercises several runtime features and does not cover all Wasm
proposals or all embeddings.

## Expanded real REA control in 1.2

The [corpus](../benchmarks/wasm_corpus_recovery.mjs) contains five different owned
programs: multiple helpers, imported calls/index shifts, memory/data/global
state, table/indirect calls, and branches/loops. Both published REA 6.9.0 and the
clean source build at `675287517c98c702ee88ad036c5e3b8dd4bcc7a7` run all three
sides with the same verified WABT 1.0.42 binaries.

| Observation | Original | Public | Private restored |
| --- | --- | --- | --- |
| Known private identifiers recovered in WAT and objdump details | 26 | 0 | 26 |
| Numerical checks, including a stateful sequence | 43 | Same 43 results | Same 43 results |
| Runtime traps / host memory-growth rejections | 2 / 1 | Same 2 / 1 | Same 2 / 1 |
| Standard section bytes and public custom notice | Original | Identical | Identical |

Each side must have valid WABT validation, complete typed interfaces, the exact
input hash, and all three provider executable identities. Partial analysis,
tool failure or missing input cannot establish absence. The 43 checks are not
independent attacks or applications; a separate JavaScript oracle verifies the
intended behavior. WAT instructions remain readable on every side.

A sixth, explicitly separate control compiles a producer-valid relocatable
module. The actual installed v1.1.0 splitter removes `name`, and its gate allows
the result, yet REA still recovers **one private helper** through `linking`.
Version 1.2 rejects this release and refuses the split. Because no new public
output exists, its recovery measurement is **not applicable**, never recorded as
zero recovery. The prior wheel hash and installed package bytes are verified.

[npm report](results/wasm-corpus-v1.2.0-rea-6.9.0.json) ·
[source-build report](results/wasm-corpus-v1.2.0-rea-source.json) ·
[full 1.2 assessment](rea-defense-v1.2.0.zh-CN.md)

## Historical single-module control in 1.1

The [reproducible control](../benchmarks/wasm_recovery.mjs) compiles one owned WAT
fixture with the verified official WABT 1.0.42 release. The published REA 6.9.0 CLI
calls that WABT provider independently on three inputs:

| Observation | Original | Public | Restored private original |
| --- | ---: | ---: | ---: |
| Known private identifiers recovered in WAT | 3 | 0 | 3 |
| Module bytes | 255 | 134 | 255 |
| Numerical inputs checked, including signed i32 extremes | 9 | 9 | 9 |
| WABT module validation / complete interface | Pass | Pass | Pass |
| Readable arithmetic instructions | Present | Present | Present |

All three have the same standard-section digest and the same nine results. The
public notice custom section remains intact. The private backup is byte-for-byte
identical to the original. Every REA call must finish without warnings, match the
selected artifact hash, cover the physical section ranges and provide a complete
interface. Missing tools, provider errors, partial output and empty WAT fail the
experiment.

[Machine-readable npm control](results/wasm-recovery-v1.1.0-rea-6.9.0.json) records
the npm integrity, WABT asset/executable hashes, input/output digests and scope.
The registry's provenance declaration is recorded separately; this project has
not independently verified its Sigstore signature chain. Source review and npm
execution are distinct evidence types.

The same experiment also ran against a clean source build of fixed REA commit
`c338e54c33213ca8dd157d30fbc922b65a04c49b`, with the same **3 / 0 / 3** result.
The [separate source-build report](results/wasm-recovery-v1.1.0-rea-source.json)
records the source identity and complete compiled-runtime inventory rather than
substituting the npm provenance claim. Both forms run in mandatory CI.

## 中文说明与边界

这项保护关闭的是**随公开模块附带私有调试名称和调试资料**的入口。它不会让 REA、
WABT 或其他分析器失效；公开 Wasm 的指令、导出和运行时数据仍可读取，本轮真实对照也
明确观察到了这些内容。3 → 0 → 3 是同一个自有模块中的三个已知标识符，不是三次独立
攻击、概率估计或算法保密结论。

私有文件包含完整原始模块。放回私有副本后 REA 再次恢复全部三个名称，说明保护依赖于
正确的发布隔离。不能把这个私有文件随安装包、调试附件、公开下载或 CDN 一起发出。
如果关键算法必须长期保密，应把关键计算留在开发者控制的服务端；如果需要保护选定的
数据，则采用独立密钥与严格的密钥交付。获得合法运行时访问的操作者仍可能观察明文。

See [security boundaries](../SECURITY.md) and the
[v1.1 source/capability assessment](rea-defense-v1.1.0.zh-CN.md).
