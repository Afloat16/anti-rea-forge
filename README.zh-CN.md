# Anti-REA Forge v0.10.0

[简体中文](README.zh-CN.md) · [English](README.md) · [MIT 许可证](LICENSE)

## 开发中的原生函数保护

`native-obfuscate --profile sealed-virtualize` 新增实验性的 LLVM 18 接入，支持 Linux x86-64 标量整数函数。执行函数所需的 VM 指令和描述表经过加密，由生成的 C++17/OpenSSL 组件使用独立提供的 32 字节密钥装载。授权后的进程内存中存在明文 VM 存储。

普通、组合控制流变换和单纯 VM 样本都曾被独立重写，三份恢复实现各自通过全部 1,081,924 次隐藏参考计算。随后加入函数指令加密、真实 Ghidra 提取与补丁对照，并针对发现的编译和元数据问题建立回归。现代 IDA 9.x 的实机执行仍待完成。[完整接入与实测说明](docs/native-code.zh-CN.md) · [英文指南](docs/native-code.md)

## v0.10.0 原生数据保护

**将原生程序的数据加密后发布，在授权使用时独立提供密钥。**

Anti-REA Forge 新增 C++17/OpenSSL 数据读取组件。构建过程接收密文封装和应用固定的上下文，使用时通过独立提供的随机 256 位密钥取回数据。发布检查还能发现误打包的密钥及其常见编码形式。

## Ghidra 和 IDA 能恢复里面的数据吗？

两款工具实际分析了同一组三个完整的 Linux i386 程序。程序、密钥和资源均为本项目生成的模拟样本，每个程序在收到正确密钥后都能返回同一份随机 32 字节资源。实验逐字节核对分析器数据库导出的内容，并要求覆盖 ELF 中所有已分配且有文件内容的节。

| 交给分析器的程序 | Ghidra 12.2 | IDA Freeware 5.0 |
| --- | --- | --- |
| 内置原始明文资源 | 恢复原始数据 | 恢复原始数据 |
| 内置加密资源，密钥独立保管 | 数据和有效密钥恢复数均为 0 | 数据和有效密钥恢复数均为 0 |
| 内置加密资源，并故意把实际密钥放回程序 | 找到密钥，交回原程序后读出原始数据 | 找到密钥，交回原程序后读出原始数据 |

提取流程将导出的初始化字节中每个不同的连续 32 字节候选都用于尝试解密公开封装。Ghidra 实际反编译了授权函数，IDA 实际反汇编了授权函数。IDA 通过其额外文件加载 API 补充默认 ELF 加载器省略的元数据范围，报告逐项记录补充地址，并将最终导出字节与原文件核对。[双工具实测记录](docs/results/native-asset-controls.json) · [复现步骤和加载设置](docs/native-assets.md#reproduce-the-native-controls)

## 把程序改成“通过”能取出数据吗？

两款工具分别定位授权入口，实验按各自报告的地址修改程序副本。使用错误密钥时，明文对照在打补丁后输出了原始资源，加密程序没有输出数据。

随后，测试专用组件强制 OpenSSL 的最终认证检查返回成功。加密程序确实以成功状态退出，并输出 32 字节，但输出的 SHA-256 与原始资源不同。同一已修改程序收到正确密钥后，仍能返回原始数据。故意嵌入密钥的发行目录也被生产发布检查以 `asset_key_exposure` 拦下。[原生实验代码](benchmarks/native_asset_controls.py)

这层防护的对象是独立保管密钥的加密数据。程序指令仍可被分析，合法使用时的进程也会持有密钥和明文。实测结论限于上述工具版本、Linux i386 模拟程序以及记录中的提取和补丁流程。[开源参考与适用范围](docs/research-native-data-2026-11-09.md)

## 接入自己的原生程序

在仓库根目录操作，Linux 构建机需要 Python 3.10+、C++17 编译器、OpenSSL 开发头文件和 libcrypto。下例假定私有的 `../asset-issuer` 目录已经存在，其中保存着不超过 1 MiB 的 `data.bin`。输出文件和目录使用新路径。

```sh
python -m pip install .
python -m releaseguard asset-keygen --out ../asset-issuer/key.bin
python -m releaseguard asset-seal ../asset-issuer/data.bin \
  --key-file ../asset-issuer/key.bin \
  --product myapp --release v1 --purpose reference-data --asset-id table \
  --out asset.json
python -m releaseguard native-asset-export asset.json \
  --product myapp --release v1 --purpose reference-data --asset-id table \
  --out generated-asset
mkdir release-asset
c++ -std=c++17 -O2 -Igenerated-asset examples/native-asset/read.cpp \
  -lcrypto -o release-asset/read-asset
./release-asset/read-asset < ../asset-issuer/key.bin
```

最后一条命令会输出原始资源。接入应用时包含生成的头文件，调用 `releaseguard::open_embedded_asset(external_key, output)`，通过自己的授权流程独立交付密钥，并保管好签发目录。发布前使用 `scan-release --asset-key-file` 检查最终发行目录。[完整接入和发布检查命令](docs/native-assets.md)

在一台 Linux x86-64 主机上，1 MiB 数据预热 5 次后测量 25 次，打开耗时的中位数为 **189.860 微秒**。计时包含 HKDF、AES-GCM、内存分配和上一次输出的清理，密钥获取和进程启动另计。报告保留全部样本，包括最高的 1,456.005 微秒。[性能原始记录](docs/results/native-asset-cost.json)

项目已有的接入方式还包括私有 ELF 调试信息、服务端授权、C++ 外部随机令牌和 JavaScript source map 管理。[私有 ELF 符号与服务端操作](docs/private-elf-debug.md) · [原生令牌](docs/native-tokens.md) · [私有 source map](docs/private-source-maps.md)

如果这解决了你的发布问题，欢迎给项目一个 **Star**，或贡献一个可复现的自有样本。[贡献说明](CONTRIBUTING.md)
