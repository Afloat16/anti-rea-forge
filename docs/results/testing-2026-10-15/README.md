# 测试证据说明

对应 [实际测试报告](../../testing-2026-10-15.zh-CN.md)。文本记录中的本机工作目录前缀统一替换为 `<workspace>`；其他实验结果未改动。`functional-summary.json` 是实际 unittest 输出的整理摘要，文件内明确标识它不是原始日志。

`fixture/sample.elf`、`fixture.cpp` 和 `ground_truth.json` 仅为本次自有合成样本。口令是测试数据，不是生产秘密或客户许可证。原样本 SHA-256 为 `e745495228de8b2ad64de3f5189505cdc2bc9ea007318010682127302645717b`。分析完成后才归档源码和保留答案；盲测时未向分析方提供这些材料。二进制按数据文件保存，没有设置执行权限。

Ghidra 的 `recover_sample_literal.py` 只复放已记录的样本专用常量推导，不能当成通用恢复器。`pseudocode.txt` 保留反编译器原始输出，包括占位入口和已说明的返回值建模误差。

`runtime-boundary.json` 来自独立的新随机样本；它不是这里的 `sample.elf`，请按各自 SHA-256 区分。可运行仓库 `benchmarks/runtime_boundary.py` 重新产生自己的样本；每次随机口令、构建种子和产物哈希均可变化，成功观察恢复时 `protection_goal_met` 应为 `false`。

`rea/` 保留实际 CLI 和整合故障。环境故障不计为保护成功。`blind-runtime/context.json` 明确标识盲测关联信息为事后补记，原始盲测验证没有前后哈希，不能作为独立审计链。文件清单摘要见 `evidence-sha256.json`，不含该摘要文件自身。
