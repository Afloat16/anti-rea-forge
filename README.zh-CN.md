# Anti-REA Forge v0.8.0

[简体中文](README.zh-CN.md) · [English](README.md) · [MIT 许可证](LICENSE)

**把校验函数编进程序，把能解锁的令牌留在二进制之外。**

如果程序自带“正确答案”，分析者可以提取它，再交给未修改的程序。Anti-REA Forge 为 C++ 应用生成一枚含 **256 位随机量**的令牌：持有人单独领取令牌，开发者只把公开的 SHA-256 校验摘要编进程序。申请解锁时，程序计算输入的摘要并进行定长比较。

## Ghidra 实际提取到了什么？

我们用官方 **Ghidra 12.2** 自动分析三个自有 Linux x86-64 ELF，反编译实际决定放行的函数，从加载的数据和选定函数的伪代码中提取符合格式的候选，再把每个候选交给**未修改的原程序**。

| 交给 Ghidra 的程序 | 提取的不同候选 | 能解锁的候选 |
| --- | ---: | ---: |
| 内置明文参考令牌的普通程序 | 2 | **1** |
| 只编入公开校验摘要的程序 | 1 | **0** |
| 同一校验机制，但故意把原令牌误放进诊断数据 | 2 | **1** |

三次反编译都成功，三个程序都接受真正的令牌。第二组中，Ghidra 找到了预置的无效诱饵，还读出了程序引用的 **32 字节真实摘要**；把摘要拼成格式正确的令牌，原程序仍然拒绝。补回泄漏的原文后，又能提取并解锁。[本机原始证据](benchmarks/ghidra_token/observation-2026-11-09.json) · [CI 独立复测](docs/results/ghidra-token-ci-2026-11-09.json) · [复现实验](benchmarks/ghidra_token/README.md)

另一次独立实验只提交错误输入并观察比较函数：使用可逆文字掩码和 `strcmp` 时能取回一个有效参考值；改用新验证器后，比较点看到的是两个摘要，重放没有一个能解锁。[比较点记录](docs/results/native-token-comparison-2026-11-09.json)

**保护范围是提取并重放令牌。** 这项实测不代表不能反编译程序、不能打补丁跳过本地判断，或不能在合法持有人输入时截获令牌。该接口只用于签发器生成的高熵随机值，不用于人选口令或短序列号。

## 在自己的项目里试用

下面是 Linux 示例：需要 Python 3.10+、C++17 编译器和 OpenSSL 开发库。Ghidra 只用于复现实验，使用工具时无需安装。

```sh
git clone https://github.com/Afloat16/anti-rea-forge.git
cd anti-rea-forge
python -m pip install .
mkdir -m 700 ../myapp-issuer
python -m releaseguard native-token-issue --public-dir generated --secret-out ../myapp-issuer/demo.rg-token
c++ -std=c++17 -O2 -Igenerated examples/native-token/check.cpp -lcrypto -o check-token
./check-token < ../myapp-issuer/demo.rg-token
```

- **给构建系统**：`generated/` 中的头文件。业务入口调用 `releaseguard::verify_issued_token(candidate)`；只有主动校验时才做哈希与比较，没有后台扫描或反调试线程。
- **给授权持有人**：通过私有渠道交付 `.rg-token`，不要随程序发布。现有发布扫描默认拦截文件或受支持 ZIP 成员里完整的令牌格式，帮助发现误打包。[接入、轮换与使用边界](docs/native-tokens.md)

## 如果你还发布 JavaScript

`split-source-maps` 保持公开 JS 的字节不变，把外部 source map 单独留给开发者。对同一份压缩 JS，Craft Anything 在普通包中恢复了 **1 份源码原文**，只给公开目录时恢复 **0 份**，补回私有 map 后又恢复 **1 份**。REA 目录分析的 map 源码节点从 **1 个降到 0 个**。[构建命令与实测记录](docs/private-source-maps.md)

如果这解决了你的发布问题，欢迎给项目一个 **Star**。也欢迎[贡献一个自有样本](CONTRIBUTING.md)，让下一种提取方式也能用同样的对照检验。
