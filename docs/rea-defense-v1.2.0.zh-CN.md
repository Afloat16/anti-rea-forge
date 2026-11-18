# v1.2：扩展真实恢复对照，修复可复现的发布泄漏

验证日期：2026-11-18。本轮沿用 v1.1 的保护边界，用更多不同的程序、构建形式和实际
消费者寻找遗漏。确实复现了残留 Wasm 链接符号、不完整 map 原文和消费端兼容密钥表示
三类问题，并将修复、正反对照和安装包检查接入发布门禁。

## 本轮测到了什么

| 项目 | 修复前或原始产物 | 当前公开产物或门禁 | 私有恢复或正常对照 |
| --- | --- | --- | --- |
| 5 个不同 Wasm 程序 | REA 恢复 26 个已知私有标识 | 恢复 0 个 | 放回私有原件恢复 26 个 |
| 4 组 JS 构建、5 个 bundle | 精确恢复 9 份内嵌原文 | 精确恢复 0 份 | 放回 map 恢复 9 份 |
| 2 个不完整 map | 实际 v1.1 放行；REA 仍恢复原文 | v1.2 明确拒绝 | partial 结果仅用于证明成功恢复 |
| 1 个 Wasm 链接符号样本 | 实际 v1.1 分离后放行；仍恢复 1 个 helper | 拒绝发布，分离器不产生输出 | 不将不存在的输出计为“恢复 0 个” |
| 19 种密钥表示 | 实际 v1.1 全放行；19/19 可解密或签名 | 19/19 正面识别并拒绝 | 2/2 非秘密对照仍允许 |
| 1 个超出原始文本预算的已知密钥 | Node 仍恢复密钥，v1.1 放行 | 明确报告检查不完整并拒绝 | 单独记录，不计入 19 个阳性命中 |

Wasm 与 JS 对照分别运行于 npm REA 6.9.0 和固定源码构建，每个分发各执行 16 次
Wasm 检查、15 次 JS 检查，共 **62 次实际 REA 调用**。19 种密钥表示由 Node 和密码库
实际恢复，不冒充 REA 或 AI 会话。重复三侧、重复分发不会增加独立程序数，也不产生
通用防破解成功率。

## 固定对象与证据身份

| 对象 | 固定身份与检查 |
| --- | --- |
| 源码 REA | [`675287517c98c702ee88ad036c5e3b8dd4bcc7a7`](https://github.com/morluto/rea/tree/675287517c98c702ee88ad036c5e3b8dd4bcc7a7)，实际编译并执行，tracked tree 干净 |
| npm REA | `rea-agents@6.9.0`，锁文件与报告记录 SHA-512 integrity，和源码组分别记录 |
| WABT | 官方 Linux x64 1.0.42；归档及四个工具的 SHA-256 都验证 |
| JS 构建与独立读取器 | Terser 5.44.1、trace-mapping 0.3.31，开发实验依赖固定 |
| 旧版内核 | 官方 v1.1.0 wheel，SHA-256 `5040a0f33c6b5a640302af4983556abdcab1918e845f4bac4010ec2fa2233086` |

源码构建报告记录源码提交/树、源与安装锁文件、构建工具、launcher 及整个编译产物清单，
运行前后检查不变。与上一轮 c338 快照相比，675 快照间的变更均位于测试文件；本轮仍
重新构建并真实运行，不能以相同版本字段推断两个分发完全相同。

Wasm 和密钥脚本还核对旧解释器内全部 29 个 package 文件的集合与字节，实验前后均
等于指定 wheel。map 脚本单独运行时只核旧版安装版本；CI 先用 Wasm 脚本检查同一个
解释器的完整包身份，再运行 map 控制。这个限制也写入 map 报告。

## Wasm：程序差异、运行行为与字节保留

| 程序 | 额外覆盖 | 私有标识 | 原始 → 公开字节数 | 数值检查 |
| --- | --- | ---: | ---: | ---: |
| helper-chain | 多 helper、调用链、i32 溢出 | 5 | 283 → 148 | 8 |
| import-index | host import、函数索引偏移、宿主实参 | 4 | 255 → 142 | 8 |
| memory-state | memory/data/global、有状态存取、内存增长 | 6 | 355 → 185 | 6 |
| table-dispatch | table/element、间接调用、表修改、越界 | 6 | 349 → 176 | 11 |
| bounded-loop | 提前返回、循环、分支、输入上界 | 5 | 291 → 171 | 10 |

这些小型自有程序共 43 个数值检查，包含有状态序列，并非 43 个独立攻击。三侧均通过
单独编写的 JavaScript 行为 oracle；另有 2 个 Wasm trap 和 1 个宿主 memory-growth
拒绝。每个标准 section 的原字节与 framing 保留，私有备份与完整原件相同，公开 notice
custom section 保留。读取被移除 custom section 的宿主仍可能观察到行为变化。

每次 REA 调用必须确认输入摘要、WABT 验证有效、typed interface 完整、工具文件摘要、
WAT 与 objdump details；三个名称恢复通道分别检查。指令在全部组里仍然可读，这直接
保留了“可以继续分析公开算法”的观察结果。

### 为什么新增 final-link 门禁

另一个 WABT `--relocatable --debug-names` 样本可正常运行。实际 v1.1 分离器删除
`name`，门禁放行，但 `linking` 中仍留有私有 helper；两种 REA 均恢复成功。

v1.2 识别 `linking` / `reloc.*` 段名，报告 `linker_metadata_present`，默认扫描给出
`native_metadata_unverifiable(reason="linker_metadata_requires_final_link")`，完成标志
为 false。分离器在任何输出创建前拒绝，要求先最终链接。它没有解析全部链接表，也没有
删除可能影响后续链接的内容，更没有把这个可执行样本说成“无效 Wasm”。

[npm Wasm 报告](results/wasm-corpus-v1.2.0-rea-6.9.0.json) ·
[源码 Wasm 报告](results/wasm-corpus-v1.2.0-rea-source.json)

## JavaScript：更多构建与不完整图的正确计分

| 构建 | bundle 数 | 真正提供内容的原文 | 特点 |
| --- | ---: | ---: | --- |
| multiple-sources | 1 | 3 | 多源码合并 |
| multiple-bundles | 2 | 3 | 多 bundle 与本地 import |
| unicode-escaped | 1 | 2 | Unicode 路径/内容、转义 JSON key |
| partial-originals | 1 | 1 | 另有 1 项 `sourcesContent=null`，不计为恢复或保护 |

每侧实际执行 16 个功能输入，共 48 次配对输出检查；生成 JS 字节不变。REA 检查所有
相关文件、JS 摘要、无跳过/解析失败、完整未截断图；trace-mapping 逐项返回原文并验证
真实映射位置。每侧运行后再次核对完整文件 inventory。

两份转义 map 分别缺少 `mappings` 或使用数值。其 JSON 字节改名为 `.js.map` 后，REA
虽报告 partial graph，仍返回和已知原文完全一致的摘要；普通 JSON 读取也直接得到原文。
改名副本与被检查文件逐字节相同，显式格式选择写入报告。实际 v1.1 默认门禁放行，
v1.2 对解码后的 `sourcesContent` 报告 `source_map_marker` 并拒绝。

另有嵌套 indexed map 可真实恢复两份原文，但当前分离器只支持 flat v3，所以明确拒绝
且不保留两份输出。以上三项独立控制都不计入“成功转换的 4 组构建”。

[npm map 报告](results/source-map-corpus-v1.2.0-rea-6.9.0.json) ·
[源码 map 报告](results/source-map-corpus-v1.2.0-rea-source.json)

## 密钥：从真实恢复反推识别规则

最初九种表示已暴露遗漏；交叉复核又发现宽松解码和前缀筛选的缺口，最终对照扩展为
19 种。所有测试材料均为自有公开 fixture，不能作为生产密钥。

- Node 真正导入不同 JWK，签名由原公钥验证。覆盖 Base64 字母表、折行、无用 padding
  bits、忽略字符、额外 padding、padding 后尾随内容，以及 UTF-16 的消费端别名。
- RSA 私有整数加前导零后仍能使用；检查按整数材料识别，不将表示差异当作无泄漏。
- JSON 的整数值小数/指数与较长字节数组内的连续窗口可恢复已知资产密钥；恢复后实际
  AES-GCM 解密返回精确明文。
- 混合大小写 hex、折行 Base64、JSON 内私钥 DER 的 hex/Base64 及其可忽略分隔符也
  实际恢复并成功使用。

这些是确定的消费端兼容性，不是放宽 JWK 标准。新规则先限制原始字段，再归一化；
DER 只有满足私有 ASN.1 前缀才进入密码库，单项 64 KiB、每 JSON 最多 64 候选和
256 KiB 解码候选预算。数组仅识别 0..255 的整数值，不执行任意 JavaScript 强制转换。
已声明非空私有字段却无法完整识别时，明确记为不完整；预算超限不能静默放行。

19 项结果都是 **positive finding**，没有以不完整拒绝冒充密钥识别。两项正常对照包含
公钥材料和无关数据，两版本均允许。已公开的密钥仍然有效可恢复，发布前拒绝不能代替
泄漏后的轮换。

最终验收还发现：38,744 个字符的可忽略噪声可以把一个有效的已知密钥编码撑过普通
字段预算。现在已知密钥的整串 Base64 解码检查先取 32,768 个字符；能明确排除完整
32 字节密钥时返回，否则未读完且无法判断就明确 incomplete。测试真正用 Node 恢复并
完成解密，再验证拒绝；这 1 项预算控制单列，不增加阳性检测分母。已出现终止 padding
的完整密钥与长尾无关文本另有正常识别对照。

[全部密钥恢复数据](results/secret-representation-recovery-v1.2.0.json)

## 复现与发布门禁

先安装候选内核、锁定的实验 npm 依赖和官方 WABT，并单独安装经过上述 SHA-256 核验的
v1.1 wheel。命令使用可信路径，输出路径必须全新：

```sh
node benchmarks/wasm_corpus_recovery.mjs --wabt-bin /trusted/wabt/bin --python /trusted/candidate/python --baseline-python /trusted/baseline/python --baseline-wheel /trusted/open_release_guard-1.1.0-py3-none-any.whl --out wasm.json
node benchmarks/source_map_corpus_recovery.mjs --python /trusted/candidate/python --baseline-python /trusted/baseline/python --out maps.json
python benchmarks/secret_representation_recovery.py --baseline-python /trusted/baseline/python --baseline-wheel /trusted/open_release_guard-1.1.0-py3-none-any.whl --out keys.json
```

源码 REA 组给前两个命令增加 `--rea-source /trusted/rea-source` 和
`--rea-source-commit 675287517c98c702ee88ad036c5e3b8dd4bcc7a7`。完整准备步骤见
[必跑 CI](../.github/workflows/ci.yml)。密钥命令应由已安装候选内核的 Python 执行。

新回归进入三平台测试，wheel/源码包在 checkout 外真实安装后分别验证新拒绝行为；
发布器要求全部安装字段通过。发布继续绑定 main 精确提交、13 个指定 CI 作业、无脏
文件的安装报告、归档大小与摘要。最终发布结论以 Release 附带的 `release-evidence.json`、
`installation-report.json` 和 `SHA256SUMS` 为准。

最终本地候选完整回归共 913 项：900 通过、13 跳过、0 失败；SDK 65 项和真实 CLI
集成 10 项全部通过；wheel、源码包和 SDK 全新安装验证通过。[本地记录](results/validation-v1.2.0-local.json)
绑定相关源码摘要，并明确记录当时是尚未提交的候选工作区。跳过项不算成功，本地包也
不替代 main 的干净构建和发布资产。

## 仍然保留的范围限制

所有 JS 构建使用同一 Terser，不能称为跨打包器覆盖；Wasm 覆盖五个程序，不能称为
覆盖所有提案或宿主。REA、WABT 和标准读取器仍能分析公开程序。私有原件泄漏后可恢复，
合法运行进程也可能持有密钥/明文。PYC、CIL、Go 专有元数据没有新增保密转换，远程 map、
CDN 和 HTTP 头没有被本地目录实验覆盖。没有开展不受限的 REA agent 会话或独立安全审计。

[v1.1 历史实验](rea-defense-v1.1.0.zh-CN.md)、原生恢复失败记录与既有工具对照全部保留，
不使用新增测试数覆盖历史失败。后续改善仍应以新的可复现恢复样本和具体修复为依据。
