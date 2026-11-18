# 跨平台发布与输入一致性加固（2026-11-18）

本轮基于已经合入主分支的 PR #10（`7d697b5639c340479d101e507c88d9f5ef3bf375`）继续开发。
目标是补上可复现的授权/发布一致性缺陷，并扩大实际发布格式的检查范围。没有修改签名文档格式，
也不要求普通软件用户安装新的运行时组件。

## 实现变化

### 原生令牌校验器隔离

此前分别生成的两个 verifier 使用同名的外部 inline digest/函数。它们位于不同编译单元时，
链接器可能把两者合并到同一发行实例；修复前在 G++ 的 O0/O2 和两种链接顺序下均复现了错误接受。

生成的 digest 现在为 `static constexpr`，verifier 为 `static inline`；调用 API 保持不变。
每个编译单元使用自己包含的 verifier，同一编译单元只包含一份生成头文件。
双编译单元回归要求四个交叉结果恒为 `1 0 0 1`，随机 bearer 经 stdin 传入，不写入 argv 或报告。
这修复实例隔离，不阻止控制客户端的人替换校验代码。[实现说明](native-tokens.md)

### 封装前拒绝会输出对象数据的 LLVM 附件

`!pcsections` 可以在函数或指令上引用编号 metadata，并把其中常量写入对象节；
仅检查 named metadata roots 不足以覆盖它。封装器现在拒绝实际语法中的该附件，字符串和注释中的
同名文本不触发拒绝。真实 LLVM 回归先编译自有未保护样例、要求 marker 实际出现，再检查封装器拒绝。

这是已知输出通道的定点封闭，不宣称分析了任意未来 LLVM metadata。
格式依据为 [LLVM 18 官方测试](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/llvm/test/CodeGen/X86/pcsections.ll)。

### 函数定义完整性

后续复查发现：只核对所有全局存储仍可能遗漏整个函数定义。在自有 VM 样例后附加一个
未被覆盖的函数，旧封装器会成功返回并保留其明文计算体。external、internal、private、
available_externally、linkonce_odr、weak 六种链接形式及被标记 removed 的原函数变体均复现。

现在要求全部定义恰好组成“已验证 wrapper + 已验证 runtime 的 private helper 依赖闭包”。
未使用的声明可保留，无关定义和编译器残留克隆会失败。新增真实 LLVM 对照先要求自有
8 字节 marker 确实出现在未保护对象中，再检查封装器拒绝；正向对照编译两层 helper 调用，
验证上锁、授权执行、整数边界及 clear 后重新上锁。

直接封装 API 还核对规范解析器之外的 `define` token，避免同一行或其它未支持语法藏住定义。
普通 CLI 会先让 LLVM 规范化模块，因此该语法问题不被宣传为已复现的 CLI 绕过。
解释器/helper 本身仍是公开代码，不能把依赖闭包检查当作任意 helper 算法或常量也已加密。

### 清单和密钥输入的完成检查

清单创建和验证记录每个已读文件的身份；整个读取完成后再次枚举目录并核对这些身份。
签名前、签名返回后重复闭合检查。文件读取有初始大小上限，拒绝增长、特殊文件及替换成 FIFO 的情况。
接入 `verify_manifest` 的分析网关继承这些检查，避免“较早文件已变，较晚文件读完后仍授权”。

外部密钥在扫描入口保存文件身份和内容，返回前安全重读核对。`prepare` 独立持有密钥快照，
并在新的 sidecars 写入完成后执行“密钥复核 → 验证签名发布物 → 密钥复核”；
失败会回滚这个新建输出目录。报告不保存快照、密钥、密钥摘要或私有 key 路径。

这些是可信构建流程中的一致性检查，增加构建阶段 I/O。它们不是原子文件系统快照，
也不能抵抗恶意目录所有者持续改写路径；发布物、密钥、策略及祖先目录仍需保持可信和不可变。
[接入约束](analysis-authorization.md)

### Mach-O 发布元数据检查

`check_native_metadata` 现在识别 thin 32/64 位、两种字节序以及有界 canonical universal Mach-O。
每片分别检查范围、load commands、section、符号和字符串表；dSYM、DWARF、STABS 和具名 local /
private-external symbols 会产生 finding。公开导入/导出保留。

`CAFEBABE` 同时是 Java class 的标识，不能按扩展名或一个整数版本号区分。
只有排除 native 候选后、完整通过受支持 Java 结构识别，才不把该文件作为 Mach-O。
已有可信 native slice 的容器不能因另一个 slice 损坏而降级为 Java。预算耗尽与未支持的候选会拒绝。

真实 macOS 对照使用本项目的 C 程序，执行 `clang`、`strip -S -x`、`dsymutil`、`nm`、`lipo`，
比较公开导入/导出与主机架构行为。测试只给自有产物加 ad-hoc signature，避免修改后失效的签名
把运行故障误算成防护结果。CI 要求工具存在；其它平台的跳过不会冒充真实 Darwin 实测。

该审计不是完整 loader/codesign/JVM 验证器，不隐藏 ObjC/Swift/Go 等运行时元数据；
加密 Mach-O、shared-cache/fileset 等未支持形状仍被拒绝。
格式依据：[Apple cctools](https://github.com/apple-oss-distributions/cctools/tree/e0d56624eca2a76c2ace4c21850df9e666de4ca5/include/mach-o)、
[Java class 规范](https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html)。

实际 macOS CI 曾发现一个误报：`strip -S -x` 在需要间接符号表而不再有局部符号时，
会加入固定 `N_OPT` 记录 `radr://5614542`。独立 `nm`/`otool` 输出与
[Apple strip 源码](https://github.com/apple-oss-distributions/cctools/blob/e0d56624eca2a76c2ace4c21850df9e666de4ca5/misc/strip.c)
一致。现在仅对完整记录和局部/间接表上下文都匹配的标记单独计数；改名、改字段、增加
其它 STABS 或 DWARF 都仍会拒绝。另修正 `N_OSO` 可把 CPU subtype 放在 `n_sect` 的语义，
它仍被报告为调试资料，而非按错误节索引中止。

### Windows PE 调试节及改名调试容器

旧 PE 审计只关注调试目录和 COFF 符号表，遗漏了独立的 DWARF/STABS 节。真实 GNU
`objcopy` 在自有 PE 夹具中加入 `.debug_info` 后，八字节截断名 `.debug_i` 可以在没有
调试目录、没有符号表时通过旧检查。`objdump -h` 能看到该节，自有 marker 也确实位于文件中。

新检查同时核对短节名、截断名及 GNU `/decimal` 长节名，支持符号条目已清空但字符串表
保留的情况。字符串表上限 1 MiB、单个名称上限 4096 字节；越界、重叠、未终止及未支持
索引布局会失败。原生 `gate` 与便携 `scan-release` 共用此修复，ZIP/ASAR 成员也适用。
真实对照随后移除该节，核对 marker 消失并恢复正常通过；没有把合成 PE 的格式处理称为
Windows 程序运行。GNU 扩展依据为 [GNU ld 文档](https://sourceware.org/binutils/docs/ld/Options.html#index-_002d_002denable_002dlong_002dsection_002dnames)。

独立 MSF7、MSF2 和原始 `BSJB` CLI 元数据现在按签名识别。去掉 `.pdb` 后缀、放进 ZIP/ASAR
都不能静默通过。其结果是 `native_metadata_unverifiable/unsupported_standalone_metadata`，
检查完成标志为 false；这表示**识别后拒绝未支持格式**，没有声称已经解析完整 PDB。
`BSJB` 也用于普通 CLI 元数据，不据此宣称文件一定是 Portable PDB。
[微软 MSF 实现](https://github.com/microsoft/microsoft-pdb/blob/master/PDB/msf/msf.cpp)只比较
MSF7 的 30 字节签名，两个对齐字节不参与比较；检测覆盖该兼容变体。

Windows CI 新增 mandatory MSVC 控制：真实 `/Zi /Od /DEBUG:FULL` 编译自有程序并运行，
确认 linker PDB 内有私有函数名和源码文件标记，再验证改名/ZIP 两种发布路径被拦下。
其它系统的跳过不算 Windows 验证。

### 静态库不能再静默跳过

真实 GNU `ar` 对照编译带 `-g` 的自有对象；`nm` 能读出私有符号，同一对象单独扫描会失败。
旧扫描器却把包入 ar 并改名的同一内容判为 `ok=true`、`archive_scan_completed=true`。
现在普通 ar、thin-ar 的魔数以及 `.a/.lib/.deb` 扩展名明确产生 `unsupported_archive`。
这会阻止包含这些尚未支持容器的发布包；并未新增其成员解析。thin-ar 的外部引用永不打开，
回归在删除外部对象后仍能安全拒绝。支持的 ZIP/ASAR 内也执行相同判定。

因此，本轮实质进展是关闭“未检查却返回通过”的入口、消除保护构建中的漏项，并修正
真实工具链误报；不是让 GNU 工具、Ghidra、IDA 或任何独立 REA 实例失去分析能力。

### ASAR unpacked 成员

外置成员绑定同一 namespace 中准确的 `archive-name.unpacked/member-path`。这个 namespace 可以是
实际发布目录、一个 ZIP 或一个外层 ASAR；其它位置或其它容器的同名文件不能满足该引用。
Header 只登记逻辑位置，不据此打开 host 路径，也不把成员解压到磁盘。

读取实际 sibling 时核对大小与可选完整/分块 SHA-256，再在扫描结束时检查引用全部满足。
缺失、篡改、未索引的 sidecar，包括 wholly packed archive 旁的旧 sidecar 都被拒绝。
外部字节在实际位置计一次；ASAR 声明计入条目预算。重复声明同一外部 payload、链接及未知布局仍拒绝。

官方 `@electron/asar 4.3.2` 对照扩展到 packed/unpacked、目录、空文件、改名和逆序 ZIP 包装，
并将缺失、大小变化、等长改写、未索引四组 mutation 与合法上游提取验证分开记录。
[完整格式范围与预算](portable-release.md)

## 当前 REA 资料与未覆盖入口

本次只读资料快照为 [morluto/rea@05be423acbdf3a56673bdbd3004e4b500c0f5217](https://github.com/morluto/rea/tree/05be423acbdf3a56673bdbd3004e4b500c0f5217)。
它不同于 CI 中锁定执行的 npm REA 版本，不能把文档审阅等同于运行了最新 agent/model。

该快照新增的 [Maven/Gradle metadata 入口](https://github.com/morluto/rea/blob/05be423acbdf3a56673bdbd3004e4b500c0f5217/docs/maven-gradle-metadata.md)
可观察公开 POM/.module 中的坐标、依赖、属性和变体。保留这些公开声明通常是正常分发需求；
本轮没有把它们自动加密或一律禁止，可按业务使用既有 allowlist/literal 策略。

[Android OTA CrAU](https://github.com/morluto/rea/blob/05be423acbdf3a56673bdbd3004e4b500c0f5217/docs/guides/firmware/android-ota-payload.md)
现在明确产生 `unsupported_archive`，包括受支持容器中的成员；本项目没有实现 OTA 分区解析或签名验证。
DEX/CIL 自动保护、任意内存提取、远端 CDN/响应头、无限预算的算法恢复仍不在本轮完成范围。

## 验证记录

<!-- validation-start -->
最终实现提交为 `9d70d00b2efc7698422988ca6ebce991f9024dcb`。
[GitHub Actions run 44225596500](https://github.com/Afloat16/anti-rea-forge/actions/runs/44225596500)
已完成，**10/10 个作业成功**。随后追加的内容仅为文档和验证证据；
[机器可读记录](results/cross-platform-hardening-validation-2026-11-18.json)
保存实现文件的 SHA-256、具体作业链接、测试汇总、跳过项及中间失败原因。

| 实测环境 | 结果与范围 |
| --- | --- |
| Linux / Python 3.10、3.13 | 各 765 tests，OK，分别跳过 11 项环境或平台控制 |
| Windows / Python 3.12 | 初始套件 751 tests / 49 skips；初始化 MSVC 后原生套件 24 tests / 7 skips；真实编译、执行及链接器 PDB 检查成功 |
| JavaScript / Linux、macOS | 每个平台 65/65 单元测试及 10/10 Python CLI 集成测试成功 |
| JavaScript / Windows | 单元测试 64 passed / 1 个 POSIX 信号控制跳过；CLI 集成 10/10 成功 |
| Portable / Linux、macOS、Windows | 各 261 tests，分别 0、2、6 skips；macOS 另执行 mandatory 编译/strip/dSYM 对照 1/1 成功 |
| Linux release exposure / official ASAR | 144 tests / 0 skips，包含真实 GNU ar、PE objcopy、javac 和官方 ASAR 对照 |
| LLVM 18 | 162 tests / 0 skips；后续 validator 10 tests / 0 skips；实际对象字节、非规范定义、合法标识符和 helper 生命周期控制全部成功 |
| Ghidra / REA source recovery | Ghidra 原生套件 39 tests / 0 skips，后续实际 Ghidra 导出、外泄密钥提取与补丁控制成功；固定版本 REA CLI 与 Craft Anything 恢复对照成功 |

本地完整套件在生产代码提交 `3fc558ba97474d9403706601088b3245c6cbb8bc` 执行：
762 tests，OK（skipped=13）。之后两次修改仅修正新增 LLVM 正对照样本，
最终提交的本地 sealing 定向套件为 23 tests / 1 个 LLVM 环境类跳过，
实际 LLVM 执行以以上 CI 为准。本地 SDK 65/65、真实 CLI 集成 10/10、
mandatory GNU ar/PE 控制 18/18 全部成功；
[原生发布暴露基准](results/release-exposure-followup-2026-11-18.json) 的 21 个检查全部为 true。
本地缺少的 CMake、LLVM 18、Java、macOS、MSVC 控制不计作本地执行成功。

真实 macOS 失败由 `nm`/`otool` 记录定位到 Apple strip 的兼容标记；修复保留了严格的
STABS/DWARF 拒绝策略。中间两次 LLVM 失败分别是新正对照样本中参数与基本块重名，
以及 `opt` 整数文本规范化后样本仍引用旧文本摘要。修正后的样本先独立确认 descriptor
字节完全相同，再绑定规范化观察；未放松生产校验。所有中间失败和最终成功都在记录中保留。

这些是自有样本的可复现实测。Ghidra、REA CLI 和 validator 的成功不代表所有版本、
所有模型或完整 REA 工具链均无法恢复；未支持格式的明确拒绝也不等于已解析或保护其内容。
<!-- validation-end -->

此前日期的 JSON 记录继续绑定各自的工具、样例与源码哈希，不能改称本轮实测。
