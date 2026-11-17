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
本轮本地执行器在启动沙箱时发生 ENOSPC，新增补丁不能在该环境运行。修复前的 token 串绑、
清单变化和密钥轮换样例在故障前已复现；新补丁的执行结果以随后 GitHub Actions 的具体 head/run 为准。
这里不把静态审查、测试定义或此前版本的成功当成当前版本已通过。

验证入口包括完整 Python/SDK 矩阵、mandatory LLVM 18、真实 Ghidra、官方 ASAR，
以及 macOS mandatory 编译/strip/dSYM 对照。新增一致性和格式回归也加入 portable 矩阵。
<!-- validation-end -->

此前日期的 JSON 记录继续绑定各自的工具、样例与源码哈希，不能改称本轮实测。
