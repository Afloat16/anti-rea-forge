# 原生函数指令保护与实测

`native-obfuscate` 将专用计算单元的 LLVM 18 IR 构建为可链接的 `protected.o`。`sealed-virtualize` 使用 Amice 将函数转换为 VM 指令，再通过独立随机密钥加密执行该函数所需的指令、描述表和随机校验字。生成的 C++17/OpenSSL 组件负责认证、装载和清理这些内容。

当前接入范围为 Linux x86-64、自包含标量整数计算，支持 1、8、16、32、64 位整数。密钥通过应用自己的授权流程独立交付。授权后的进程内存中存在明文 VM 指令，可访问该内存的分析者能够读取它们。公开 ABI、解释器指令集、程序尺寸和格式元数据仍可观察。

## 已完成的迭代

先前测试依次使用普通编译、控制流平坦化、基本块拆分与运算替换、指令虚拟化。独立恢复者分别从普通、混合变换、虚拟化程序及真实 Ghidra 输出重写出普通 C 实现。三份实现都通过 1,081,924 次隐藏参考计算。虚拟化样本的该次恢复耗时 310 秒，分析者使用原始 ELF 反汇编补充了不完整的反编译结果。[原始记录](results/native-code-recovery.json) · [公开后的源程序与恢复实现](../benchmarks/function_recovery/README.md)

这些结果推动了函数指令加密。发行文件中的 VM 存储初始化为零，完整认证成功后才填充指令并启用 wrapper。检查发现的具体问题都保留了回归。

| 发现 | 处理 |
| --- | --- |
| 上游静默跳过 `used` 函数或不支持的循环 | 必须验证目标 wrapper、runtime、字节码依赖和原函数体替换 |
| 原函数体以另一名称残留 | 检查全部转换后函数的规范化指令体 |
| 原始全局常量仍被带入对象 | 密封输入要求专用计算单元，拒绝原始全局存储 |
| 模块级汇编可携带任意明文字节 | 密封输入拒绝模块级汇编 |
| `prologue` 被丢弃，计算结果改变 | VM profile 拒绝 `prefix` 与 `prologue` |
| 文件名、`llvm.ident` 可保留任意字符串 | 固定生成文件标识，并清除 ident 元数据 |
| 链接选项与依赖库元数据保留明文 | 明确拒绝这些附加链接依赖 |
| 可逆描述表检查泄露一个 8 字节校验字 | 每条描述记录使用独立非零随机校验字，其比较值一并密封 |
| 清理后两侧零值可能通过相等检查 | 执行时同时要求非零，回归测试强制修改 ready 后的零状态 |

最初密封样本的独立评估实际恢复了该 8 字节，评估者保留原条件分支，通过成功路径 marker 验证结果。隐藏载荷复核确认了恢复值。修复前的失败记录与修复后测试分别保留。[独立检查与修复记录](results/native-code-hardening.json)

## 构建自己的函数

从仓库根目录执行。准备 Linux x86-64 构建机、Python 3.10+、LLVM 18、C++17 编译器和 OpenSSL 开发文件。`sensitive.c` 保存自己的计算函数，示例假定函数链接名为 `rg_compute`。C++ 函数使用实际 LLVM 链接名，或通过 `extern "C"` 声明稳定入口。

```sh
python -m pip install .
curl --fail --location -o amice-llvm18.so \
  https://github.com/fuqiuluo/amice/releases/download/v0.1.6-beta.1/libamice-llvm18-linux-x86_64.so
echo 'aa4527516a03ddbdc4034e68dece3190110dfe8ff34a4d1a8284e896a733a882  amice-llvm18.so' | sha256sum --check

python -m releaseguard asset-keygen --out ../private-code-key.bin
/usr/lib/llvm-18/bin/clang -O2 -fPIC -g0 \
  -fno-unroll-loops -fno-vectorize -fno-slp-vectorize \
  -emit-llvm -c sensitive.c -o sensitive.bc

python -m releaseguard native-obfuscate \
  --input sensitive.bc --out sealed-function \
  --llvm-bin /usr/lib/llvm-18/bin \
  --plugin amice-llvm18.so \
  --plugin-sha256 aa4527516a03ddbdc4034e68dece3190110dfe8ff34a4d1a8284e896a733a882 \
  --function rg_compute --profile sealed-virtualize \
  --key-file ../private-code-key.bin \
  --product myapp --release v1 --module-id compute
```

输出目录必须是新目录。`--function` 可重复，指定必须通过覆盖检查的函数。插件处理整个输入单元，因此每个保留的原始函数都需要有效 VM 覆盖。密封模式拒绝外部 native 调用、指针与内存访问、浮点、向量以及未经支持的 ABI。VM profile 使用固定受控配置，`--seed` 仅用于两种控制流变换 profile。

输出包含以下文件。

| 文件 | 用途 |
| --- | --- |
| `protected.o` | 函数 wrapper、VM runtime、零初始化存储 |
| `releaseguard_native_code.hpp` | 初始化与清理接口 |
| `releaseguard_native_code.cpp` | 认证、完整载荷核对、装载与清理 |
| `releaseguard_native_code_asset.hpp` | 密文及公开认证参数 |
| `releaseguard_sealed_asset.hpp` | 复用的 HKDF/AES-GCM 实现 |
| `report.json` | 工具版本、哈希、覆盖记录、模块 namespace 和存储布局 |

从 `report.json` 的 `code_seal.cpp_namespace` 读取实际 namespace，将它用于 `initialize_native_code(external_key)` 与 `clear_native_code()`。应用以 C++17 编译，链接 `protected.o`、生成的 `.cpp` 和 `-lcrypto`。英文指南给出了对应 C++ 调用片段。[C++ 调用方式](native-code.md#execute-encrypted-function-instructions)

初始化顺序为清理旧状态、AEAD 认证、完整长度与 SHA-256 核对、复制全部存储、最后设置 ready。初始化失败会清理旧指令。锁定 wrapper 返回零，应用需要检查初始化的布尔结果，因为正常函数也可能返回零。

在启动工作线程前独占初始化，在线程全部退出后清理。各模块拥有独立 namespace、ready 与存储。调用方管理外部密钥的生命周期，发布前使用 `scan-release --asset-key-file` 检查最终发行目录。[发布检查](native-assets.md)

## 复现真实 Ghidra 对照

下列流程生成新的自有随机函数，保存私有参考，构建三个完整程序，并用 Ghidra 导出的全部初始化字节测试候选密钥。准备官方 Ghidra 12.2 ZIP 文件，probe 会核对固定发布哈希。

```sh
python benchmarks/sealed_code_controls.py prepare code-corpus \
  --llvm-bin /usr/lib/llvm-18/bin \
  --plugin amice-llvm18.so \
  --plugin-sha256 aa4527516a03ddbdc4034e68dece3190110dfe8ff34a4d1a8284e896a733a882

for variant in plaintext encrypted key_leak; do
  python benchmarks/ghidra_function/probe.py "code-corpus/public/$variant" \
    --archive ghidra.zip --include-program --out "code-analysis/$variant"
done

python benchmarks/sealed_code_controls.py analyze code-corpus \
  --observations code-analysis --out code-observation.json
```

三种程序为完整明文 VM、独立密钥的加密 VM、故意把实际密钥放回程序的加密 VM。每个程序都先读取 32 字节密钥，再读取小端 32 位输入序列。参考检查包含 82,014 次计算，并对分析器的每个已分配文件字节核对来源。

修复后样本的实际结果如下。[完整记录](results/native-code-sealed-controls.json)

| 对照 | 不同连续 32 字节候选 | 成功解密 | 正确密钥下的函数输出 |
| --- | --- | --- | --- |
| 明文 VM | 23,842 | 0 | 全部 82,014 次与参考一致 |
| 加密 VM，密钥独立保管 | 30,982 | 0 | 全部 82,014 次与参考一致 |
| 故意内嵌实际密钥 | 31,046 | 1 | 恢复密钥后，全部 82,014 次与参考一致 |

将外层 `rg_code_gate` 改成直接返回成功后，加密程序输出锁定零值，82,014 次结果全部偏离正确参考。强制 GCM 最终检查返回成功时，错误密钥仍被完整载荷摘要检查拒绝，正确密钥仍给出全部正确输出。实际重编译的密文篡改和错误上下文对照均拒绝初始化。

工具完整性检查保存函数、helper、初始化数据、原始 ELF、日志、函数警告和哈希。`decompileCompleted()` 成功时仍可能有未恢复的跳转表或截断控制流，报告会保留这些诊断。独立恢复需要重新编译实现，并通过隐藏输入参考评分。[Ghidra 采集契约](../benchmarks/ghidra_function/README.md)

现代 IDA 9.x 的导出适配器已实现，并通过引擎独立验证测试。当前环境缺少可执行的 IDA 9.x 与对应 Hex-Rays，因此实机运行状态为待验证。历史 IDA 5.0 的数据加密实验记录了另一组 i386 样本。[IDA 9.x 接入说明](../benchmarks/ida_function/README.md)

修复后的第二轮独立恢复子任务被执行层自动审查阻止，返回原因为可能涉及网络安全风险，该项独立复验状态为未完成。修复后的自动化对照、私有载荷核对和真实编译回归均有单独记录。[验证范围与执行状态](results/native-code-hardening.json)

## 性能与开源实现

原虚拟化恢复样本在同一台机器上进行三轮预热和七轮各一百万次相关调用。原生基线中位数为 16.91 ns，平坦化为 35.24 ns，组合变换为 47.34 ns，VM 为 4,425.94 ns。该小函数的 VM 成本约为原生基线的 262 倍。数据包含循环运算，编译、进程启动和输入输出另计。将目标函数的性能与功能测试纳入自己的构建验收。[完整测量](results/native-code-recovery.json)

控制流 profile 使用固定 eshard 提交 `be910da9267b40cbe6ae8c946eb2ef008f6e55f4`，其许可证为 NCSA。VM 使用固定 Amice 提交 `19b6c473ee8a59d66a91d3b7c2d460bb6af7c99e`，其许可证为 Apache-2.0。构建阶段载入经过哈希核对的独立插件，仓库中保留集成与验证代码。[eshard 上游](https://github.com/eshard/obfuscator-llvm/tree/be910da9267b40cbe6ae8c946eb2ef008f6e55f4) · [Amice 上游](https://github.com/fuqiuluo/amice/tree/19b6c473ee8a59d66a91d3b7c2d460bb6af7c99e)
