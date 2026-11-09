# Anti-REA Forge v0.9.0

[简体中文](README.zh-CN.md) · [English](README.md) · [MIT 许可证](LICENSE)

**发布程序可以保留机器码、移除内部函数名。即使客户端被改成“通过”，服务端仍能要求有效授权。**

如果用户能修改自己的客户端，把本地判断改成“通过”并不难。Anti-REA Forge 为 Linux 构建拆分私有调试信息，并为 Python 服务提供一次性签名授权检查。下面的程序、凭据和服务都是本项目生成的模拟样本。Ghidra 和 IDA 实际运行并分析了同一组三份 ELF。

## Ghidra 和 IDA 能恢复内部函数的原名吗？

我们给两个分析器相同的私有函数地址，让它们直接查看同一段机器码。函数原名带有每次实验新生成的随机值。公开入口则始终保留名称，供分析器独立定位。

| 交给分析器的 i386 Linux 程序 | Ghidra 12.2 | IDA Freeware 5.0 |
| --- | --- | --- |
| 带原始符号和调试信息 | 找到原名 | 找到原名 |
| 只提供公开 ELF | 显示 `FUN_08049000` | 显示 `sub_8049000` |
| 从私有调试文件取回名称，重新加入公开 ELF | 再次找到原名 | 再次找到原名 |

三份程序的 `.text` 哈希相同，三组输入的运行结果也相同。Ghidra 成功反编译了目标函数，IDA 成功反汇编了目标函数。分析者仍能根据指令推断函数用途。这里验证的是能否从发行文件的元数据直接读出原名。[双工具原始记录](docs/results/native-elf-controls.json)

## 修改客户端能拿到受限结果吗？

两个分析器都从公开符号独立找到了同一个入口。实验脚本按各自报告的地址修改测试程序副本中的六个字节，客户端返回值从 `39` 变成了模拟“通过”的 `42`。随后两个独立运行的模拟服务收到测试请求，实验逐份核验服务端回执的签名。

| 服务如何决定是否执行 | 实际结果 |
| --- | --- |
| 直接相信客户端返回值 | 原客户端被拒绝，打补丁后拿到了有效回执 |
| 服务端验签，已修改的客户端缺少授权、使用自签授权或篡改请求 | 三种请求都未执行受限操作 |
| 同一已修改客户端提交针对原请求签发的有效授权 | 首次拿到有效回执，重用同一授权时被拒绝 |

需要保护的操作应在你控制的服务上执行。纯离线功能的本地判断仍可修改。两款工具的联合结论限于这组 32 位 x86 模拟程序和表中版本。[实验设计与复现](docs/private-elf-debug.md#reproduce-the-two-engine-observation)

## 接入自己的软件

在有 GNU binutils 和 Python 3.10+ 的 Linux 构建机上安装。下例假定你已有带符号的 `build/myapp`，并想检查内部函数名 `calculate_internal_quote`。

```sh
git clone https://github.com/Afloat16/anti-rea-forge.git
python -m pip install ./anti-rea-forge
python -m releaseguard split-elf-debug build/myapp \
  --public release-linux --private private-symbols \
  --private-name calculate_internal_quote
```

**只部署 `release-linux/myapp`。** 私有的 `private-symbols/myapp.debug` 可用于内部崩溃定位。如果指定的名称仍藏在导出表、日志或宽字符串里，命令会指出名称并拒绝发布。拆分只在构建时执行，应用无需加载额外运行库。[输入限制和调试用法](docs/private-elf-debug.md)

如果软件需要执行受限操作，在服务端固定签发公钥、用户身份和处理函数。授权绑定请求的原始字节，验签并消费授权之后才调用 `create_export`。

```python
from releaseguard.capabilities import run_authorized_operation

receipt = run_authorized_operation(
    grant, trusted_issuer_public_key, replay_store,
    subject=authenticated_user, audience="exports", product="myapp",
    operation="create-export", request=request_bytes, handler=create_export,
)
```

[服务端接入示例](docs/private-elf-debug.md#put-the-restricted-operation-behind-a-service-side-check)

项目也支持 [C++ 外部随机令牌](docs/native-tokens.md) 和 [JavaScript 私有 source map](docs/private-source-maps.md)。如果这解决了你的发布问题，欢迎给项目一个 **Star**，或[贡献一个可复现的自有样本](CONTRIBUTING.md)。
