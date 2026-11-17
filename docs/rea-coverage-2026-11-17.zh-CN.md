# REA 通用工具入口与发布防护覆盖（2026-11-17）

本轮把防护重点落在**工具共同能读取的内容**：发布包中的源码映射、原生调试资料、私有符号、意外随包分发的密钥，以及本应加密却仍留在原生模块里的初始化数据。REA 可以切换 provider；防护不能依赖某个反编译器的输出恰好为空。

新的 [发布暴露对照程序](../benchmarks/release_exposure_controls.py) 实际运行了 GNU binutils 和自有 C/C++ 程序。它记录哪些内容能被读到、处理后哪些内容不再随包发布，以及发布门禁是否正确放行或拒绝。**它不测量所有 REA 工具的破解成功率，也不承诺客户端算法无法恢复。**

## 固定的上游资料

本轮通过 GitHub refs API 读取到 REA `main` 提交：

`43b9fa87fbbaa74224731a1fe3a8e67a2d336ae3`

以下上游链接固定到该提交。本次是对官方文档中相关入口的定点审阅，没有运行该提交的 REA CLI、MCP、agent 或模型，也没有验证它与某个 npm 发布包的字节一致性。

| 官方入口 | 文档明确支持的路径 | 对防护设计的要求 |
| --- | --- | --- |
| [REA README][rea-readme]、[Kuna provider][rea-kuna] | 原生深度分析可选择 Ghidra、IDA、Hopper 或 Kuna；可输出函数、字符串、调用关系、伪代码或汇编，具体能力取决于 provider | 删除一个名字、改变控制流或令一次反编译失败，不会自动消除机器码与数据的可读性 |
| [GNU objdump、GDB、Rizin][rea-native-tools] | objdump 可读取节、符号、重定位、DWARF 和汇编；Rizin 接受调用者命令；GDB 提供 Linux 调试会话 | 整个发布树及包内的原生模块都应检查调试资料；不能只检查主 EXE 或只禁用 `.pdb` 后缀 |
| [JavaScript/Electron artifact][rea-javascript] | 直接分析目录或 ASAR，无需执行目标；源文件及源码映射可被选取并关联 | ASAR 是可读取的容器；源码映射必须按 JSON 语义检查，后缀和关键字的字面拼写都不足以判断暴露 |
| [.NET 分析][rea-managed]、[Android/JADX][rea-android] | .NET 直接解析元数据和 CIL；JADX 可反编译 APK 方法并读取资源、清单与引用 | 发布门禁只能减少误发布；现有原生 LLVM 功能不等于 .NET、DEX 或 Java 自动代码保护 |
| [Frida instrumentation][rea-frida] | attach/spawn、加载调用者 JavaScript、观察消息；脚本在目标进程权限内执行 | 正常解密后的密钥、明文和 VM 指令仍可能被有权限的进程观察者获取；长期秘密和最终权限判断需要受控边界 |
| [固件分析][rea-firmware]、[PyInstaller][rea-python] | Binwalk/Unblob 的区域识别和显式解包；PyInstaller CArchive/PYZ 库存和提取 | 打包或压缩不是保密措施；扫描器不支持的格式不能被宣传为已经检查 |
| [网络捕获][rea-network] | 读取 HAR、SAZ 或 mitmproxy 记录中的请求、响应和载荷 | 本地发布检查不覆盖服务端响应、CDN 发布状态、会话录制或远端源码映射响应头 |

## 本轮实现与边界

### 1. 对实际发布内容进行同一套检查

便携发布扫描新增默认启用的 `check_native_metadata`。它按文件签名识别 ELF/PE，检查原生调试资料和静态符号；不能可靠解释的已识别原生文件产生 `native_metadata_unverifiable`，不会因解析失败而被标记为干净。检查覆盖物理文件和被支持的容器成员，而非只依赖扩展名。

源码映射检查在已有字节标记规则之外，识别 v3 JSON 的结构，包括转义后的键和 indexed map。解析超出预算、歧义或结构过深时产生明确的不可验证结果。`source_map_structure` 表示实际识别到了地图结构；它与源码已经保密或 JavaScript 已无法分析没有等价关系。

本轮新增 ASAR 的受限内容读取，与原有 ZIP 路径共用成员扫描。目录、范围、别名、嵌套和展开预算需要通过校验；不支持的链接、外置成员和布局会阻止检查成功。ASAR 支持的具体范围及策略选项以 [便携发布扫描](portable-release.md) 为准。格式清单之外的任意编码仍可能存在未识别内容。

### 2. 将外置密钥检查带入日常发布流程

外部密钥检测应运行在最终暂存目录，并纳入 `check`、`prepare` 及 JavaScript 接入流程。显式提供要保护的密钥，扫描其原始字节、常见十六进制和 Base64 表示；报告保留命中位置和规则编号，不返回匹配内容。

这是对**已知密钥误发布**的检测，不会发现所有未知凭证或任意可逆编码。把密钥留在客户端而只改它的表现形式，不能建立外置密钥的信任边界。参见 [原生资产说明](native-assets.md) 和 [项目准备流程](analysis-authorization.md)。

### 3. 封装原生 VM 数据时拒绝遗漏的初始化存储

`sealed-virtualize` 的目标是在外部密钥交付前，使选定函数执行所需的 VM 指令与描述数据不以可直接使用的形式随包发布。本轮对转换后模块中的初始化全局存储加强覆盖核对，拒绝未被授权归入封装范围的内容，避免“主要 bytecode 已加密，但副本或额外常量仍在对象文件中”的情况。

它仍限于 [原生函数说明](native-code.md) 中列出的平台、LLVM 工具链和函数形状。授权后的进程持有明文 VM 数据，公开解释器与 ABI 仍可分析；不能把这项检查称为通用抗内存读取或全语言防反编译。

## 实际运行的发布暴露对照

机器可读记录：[release-exposure-controls.json](results/release-exposure-controls.json)。

本次运行使用 Linux x86-64、GCC/G++ 14.2.0、GNU binutils 2.44、OpenSSL CLI 3.5.7。报告保留 Python/宿主版本、工具版本、核心源码摘要、样例源码摘要和每个执行文件摘要。外部密钥仅临时生成，报告不保存密钥或工具的原始输出。

### 私有符号和调试资料

| 自有样例 | `strings` / `nm` 私有名字 | `readelf` DWARF / 静态符号 | 门禁结果 |
| --- | --- | --- | --- |
| 带 `-g` 的原始 ELF | 两个工具均可读取 | 均存在 | 拒绝：`native_debug_metadata`、`native_symbol_table` |
| 经 `split-elf-debug` 的公开 ELF | 两个工具均未读到指定私有名字 | 均已移除 | 通过 |
| 私有 debug sidecar 改名为 `resource.dat` | 不把改后缀当作隐藏 | 文件内容仍含相关元数据 | 拒绝 |
| 公开 ELF 与改名 sidecar 一起压入 ZIP | 成员使用同一检查路径 | 包内元数据仍被识别 | 拒绝 |

`objdump` 导出的 `.text` 在拆分前后均为 **281 字节**，SHA-256 完全一致；导出的每个字节也与 ELF 原文件对应范围逐字节核验。两个程序均输出 `22`。公开 ELF 仍有 **89 行**可反汇编的指令观察，故这项结果证明私有元数据分离和行为保持，不能被解释为代码不可读。

### 原生资产与真实密钥泄漏控制

三种程序输出同一份 **51 字节**的自有资源。明文对照没有密钥门；两个加密对照使用现有 C++17/OpenSSL 资产加载器。

| 自有样例 | 资源可被 `strings` 直接读到 | 正确密钥输出 | 错误密钥输出 | 门禁结果 |
| --- | --- | --- | --- | --- |
| 明文资源随包分发 | 是 | 与原资源相同 | 仍输出资源，因该对照无密钥门 | 拒绝：配置的 `forbidden_literal` |
| 加密资源、密钥独立保存 | 否 | 与原资源相同 | 退出码 3，零输出字节 | 通过 |
| 同样加密，但把真实密钥故意编译进程序 | 否 | 与原资源相同 | 退出码 3，零输出字节 | 拒绝：`asset_key_exposure` |

第三个对照直接验证真实密钥字节确实位于执行文件中。它说明只检查“没有资源明文”会遗漏严重的发行错误；本实验没有把使用私有答案进行的字节匹配冒充独立密钥恢复。

额外的转义 JSON 对照把源码映射保存为 `resource.dat`，并将 `version`、`sources`、`sourcesContent` 的部分字符写为 Unicode 转义。结构规则仍将其识别并拒绝。

本轮记录的 **21 个布尔检查均通过**。这些是同组自有样例上的相关检查，并非 21 个独立破解样本，更不是“21/21 防破解成功率”。用于维护该证据路径的五项测试还覆盖缺失/截断/错位的 objdump 输出、报告覆盖保护、工具失败不能计为防护成功，以及报告不泄漏已知测试密钥。

## 复现

### 官方 Electron ASAR 打包兼容性

另一组[独立程序](../benchmarks/asar_package_controls.py)实际调用官方 `@electron/asar 4.3.2`
与 Node `v24.22.1`，对七组自有包运行 `pack`、`list` 和 `extract-file`，逐一核对提取字节。
正常包（含空文件）及改名为 `.bin` 的同一包通过；转义源码映射、`.env`、误带真实密钥及
改名后的密钥泄漏包均在实际成员位置被门禁发现。官方 `--unpack '*.node'` 生成的外置
sidecar 也经官方 CLI 提取核对，但当前 packed-only 扫描明确拒绝这种布局。

[ASAR 实测记录](results/asar-package-controls.json)中的 **11 项对照断言均通过**，保留
工具版本、已安装代码摘要、npm 来源/完整性字段、样例摘要与规则结果，不保存密钥或工具
原始输出。这些结果验证格式兼容与发布检查，没有运行 Electron 应用或 REA agent。
精确共享范围的去重布局另外由解析器回归覆盖；该 CLI 观察不扩大为所有 ASAR 版本测试。

```sh
npm install --prefix /tmp/asar-controls --ignore-scripts --no-audit --no-fund @electron/asar@4.3.2
python benchmarks/asar_package_controls.py \
  --asar-cli /tmp/asar-controls/node_modules/.bin/asar --out /tmp/asar-packages-new.json
```

该程序也拒绝覆盖已有输出；缺工具、工具错误或超时记录为 `not_measured`，不能当成防护成功。

### 原生与发布门禁对照

需要 Linux、Python 3.10+、GNU binutils、GCC/G++ 和 OpenSSL 开发文件。先安装项目，再使用一个尚不存在的输出路径：

```sh
python -m pip install .
python benchmarks/release_exposure_controls.py --out /tmp/release-exposure-new.json
python -m unittest tests.test_release_exposure_controls -v
```

退出码 `0` 表示本次全部对照断言符合预期，`1` 表示至少一个对照未达到预期，`2` 表示缺工具、编译失败、超时等执行错误。执行错误的 `protection_outcome` 为 `not_measured`。程序不覆盖已有报告，临时样例与密钥在退出时清理。

不同运行会生成新密钥、加密参数和临时构建路径，因此 ELF/密文摘要可能变化。复现的是程序、校验和对照判据；报告中的摘要标识具体一次运行，不声称跨机器字节完全相同。

## 未完成的验证

本地整合验证基于新合入的 `08ed341` 原生 VM 内存保护继续进行：Python 报告为
`Ran 658 tests / OK (skipped=10)`；十个跳过条目需要本机未安装的 CMake、LLVM 18 或
相关插件，不代表这些路径已实际执行。JavaScript 65 项测试、10 项真实 CLI 集成测试
和 TypeScript 类型检查通过。[整合验证记录](results/release-hardening-validation.json)
保存命令、跳过原因与实现摘要；远端 CI 单独运行真实编译器和分析器流程。

这个新 benchmark 没有启动 Ghidra、IDA/Hex-Rays、Hopper、Kuna、Rizin、GDB、Frida、JADX、JEB、Binwalk、Unblob 或 REA 模型流程。历史 Ghidra/IDA 记录保留各自日期、版本和样例范围，不能自动改称本轮已完成这些工具的实测。

当前也没有新增 Android/.NET/Python 自动加密转换、Mach-O 发布元数据完整审计、在线响应审计、通用算法恢复评估、运行时内存不可读保证或无限预算下的逆向失败结论。对于控制客户端的人仍可观察的关键计算或授权结果，应在受信服务等可控制的边界内执行，并按具体业务验证授权与数据交付流程。

[rea-readme]: https://github.com/morluto/rea/blob/43b9fa87fbbaa74224731a1fe3a8e67a2d336ae3/README.md
[rea-kuna]: https://github.com/morluto/rea/blob/43b9fa87fbbaa74224731a1fe3a8e67a2d336ae3/docs/kuna-provider.md
[rea-native-tools]: https://github.com/morluto/rea/blob/43b9fa87fbbaa74224731a1fe3a8e67a2d336ae3/docs/reverse-engineering-tools.md
[rea-javascript]: https://github.com/morluto/rea/blob/43b9fa87fbbaa74224731a1fe3a8e67a2d336ae3/docs/guides/javascript/javascript-artifact-reconstruction.md
[rea-managed]: https://github.com/morluto/rea/blob/43b9fa87fbbaa74224731a1fe3a8e67a2d336ae3/docs/guides/managed/managed-code-analysis.md
[rea-android]: https://github.com/morluto/rea/blob/43b9fa87fbbaa74224731a1fe3a8e67a2d336ae3/docs/guides/android/android-analysis.md
[rea-frida]: https://github.com/morluto/rea/blob/43b9fa87fbbaa74224731a1fe3a8e67a2d336ae3/docs/guides/runtime/frida-instrumentation.md
[rea-firmware]: https://github.com/morluto/rea/blob/43b9fa87fbbaa74224731a1fe3a8e67a2d336ae3/docs/guides/firmware/firmware-analysis.md
[rea-python]: https://github.com/morluto/rea/blob/43b9fa87fbbaa74224731a1fe3a8e67a2d336ae3/docs/python-packaged-applications.md
[rea-network]: https://github.com/morluto/rea/blob/43b9fa87fbbaa74224731a1fe3a8e67a2d336ae3/docs/guides/web/web-network-captures.md
