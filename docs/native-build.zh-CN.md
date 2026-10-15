# v0.2 原生工程编译接入指南

v0.2 将 Release 优化、LTO、选中文字的静态掩码和发布检查接入现有 CMake 目标。
当前支持 Windows 的 Microsoft MSVC，以及 Linux 的 GCC／Clang；需要 CMake 3.20+、
Python 3.10+。字符串组件需要 C++17；C 源文件可使用编译加固，但不能调用 `RG_TEXT`。
hook 接受本地构建的可执行程序、共享库或模块库目标，不接受 imported／alias 目标。

这需要业务源代码和重新编译，不是对任意语言现成 EXE/DLL 的自动变换工具。
接入 hook 不会自动保护全部字符串；开发者需要选择敏感字面量并使用 `RG_TEXT`。
没有 .NET、Electron 等语言的自动转换 backend。

## 1. 安装命令行工具

在你的软件工程目录创建虚拟环境，并从本项目源码安装。把安装路径换成本地检出的
`anti-rea-forge` 目录。Python 分发包名仍为 `open-release-guard`，CLI 仍为 `releaseguard`。

Linux：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install /absolute/path/to/anti-rea-forge
releaseguard --help
```

Windows PowerShell：

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install C:\src\anti-rea-forge
releaseguard --help
```

CMake 配置和构建时也需要使用安装了该包的 Python。下面的命令显式指定解释器，
避免 CMake 找到另一份系统 Python。Windows 还需要在可用 MSVC 工具链的终端中构建。

## 2. 初始化构建资产

从你的软件工程目录运行：

```bash
releaseguard native-init --out ./vendor/releaseguard
```

输出目录必须不存在、为空，或是同版本工具之前生成且未修改的完整资产目录。
也可以将资产放在业务源码目录之外，再将对应绝对路径交给 CMake；这更便于把生成资产
与业务源码分开管理。不要在生成目录中放置自己的 policy、源码或其他文件。

| 生成路径 | 用途 |
| --- | --- |
| `include/releaseguard/literal.hpp` | C++17 字面量组件 |
| `cmake/ReleaseGuard.cmake` | CMake 接入函数 |
| `releaseguard_build.hpp` | 当前生成资产使用的公开构建种子 |
| `releaseguard-native.json` | 工具版本、种子和资产摘要，用于校验重复初始化 |

需要可复现的初始化结果时，可明确给出 16 位十六进制种子：

```bash
releaseguard native-init --out ./vendor/releaseguard --seed 0123456789abcdef
```

同一份合法资产重复运行 `native-init` 会复用原种子，不会每次随机改写。
要换种子、改变生成资产或升级资产版本，请指定新的不存在或空目录，并更新引用。
工具会拒绝覆盖种子冲突、被修改、缺文件或夹带额外文件的已有目录。

**种子是公开的构建多样化参数，不是密钥。** 不要把私钥或其他秘密写入种子头文件。

## 3. 创建发布策略

在业务工程中创建 `releaseguard-policy.json`，不要放入上一步的生成资产目录。
下面的示例同时允许 Windows PE 和 Linux ELF；把示例文字换成实际需要检查的字面量。

```json
{
  "version": 1,
  "formats": ["pe", "elf"],
  "forbid_literals": ["MYAPP_INTERNAL_RELEASE_MARKER"],
  "forbid_extensions": [".pdb", ".ilk", ".map"],
  "require_native": true,
  "require_no_debug_metadata": true,
  "require_no_symbol_table": true,
  "required_pe_flags": [],
  "max_binary_bytes": 536870912
}
```

字段名和类型必须准确，未知字段、重复 JSON 键和不合法值会被拒绝。
除 `version` 外可省略字段，省略时采用下表默认值。

| 字段 | 类型、默认值与约束 |
| --- | --- |
| `version` | 必填整数，目前只能为 `1` |
| `formats` | 默认 `["pe"]`；非空且不重复，只允许 `pe`、`elf` |
| `forbid_literals` | 默认 `[]`；最多 64 条不重复字符串，每条 1～1024 个字符 |
| `forbid_extensions` | 默认 `[".pdb", ".ilk", ".map"]`；最多 32 条不重复的小写扩展名，格式为点加 1～16 位小写字母或数字 |
| `require_native` | 布尔值，默认 `true`；拒绝被识别的托管产物，不证明所有业务逻辑都是原生代码 |
| `require_no_debug_metadata` | 布尔值，默认 `true`；禁止检查器识别到的调试元数据 |
| `require_no_symbol_table` | 布尔值，默认 `true`；禁止 PE COFF 符号表或 ELF 静态符号表，不等于消除导入、公共导出或 ELF 动态符号 |
| `required_pe_flags` | 默认 `[]`；可选 `dynamic_base`、`nx_compat`、`guard_cf`、`high_entropy_va`，不允许重复，仅对 PE 应用 |
| `max_binary_bytes` | 整数，默认 `536870912`（512 MiB）；范围 `1`～`4294967296`（4 GiB） |

文字规则扫描目标二进制的 UTF-8、UTF-16 LE／BE、UTF-32 LE／BE 字节表示。
命中结果包含从 `0` 开始的 `rule_index`、编码和偏移，不打印被禁文字内容。
policy 文件自身包含原文字面量；它不是凭证或私钥存储方式。

PE 标志检查还要求相关静态元数据存在。例如 `dynamic_base` 需要重定位证据，
`guard_cf` 需要 Load Config 与 `dynamic_base`，`high_entropy_va` 需要 PE32+、
`dynamic_base` 和重定位证据。CFG 检查不验证 Guard 函数表的完整性或实际覆盖率。
`high_entropy_va` 不适用于 32 位产物。ELF 在缺少足够 section 元数据而无法判断
禁止的调试资料或静态符号表时会拒绝通过，不会将未知当作安全。

PE 调试目录会保留原始存在性和条目类型，另按内容判断是否存在调试或未验证元数据。
默认策略仍拒绝 CodeView、COFF/POGO、未知类型和未验证字段；规范空载荷 REPRO
标记及已识别位值的四字节扩展 DLL 安全特征不等同于 PDB/源码调试资料。

## 4. 接入现有 CMake 目标

在 `add_executable` 或 `add_library` 创建目标之后调用保护函数。
以下代码可以合入现有 `CMakeLists.txt`；已有的源文件、依赖与工程配置按原项目保留。

```cmake
cmake_minimum_required(VERSION 3.20)
project(MyApp LANGUAGES CXX)

include("${CMAKE_CURRENT_SOURCE_DIR}/vendor/releaseguard/cmake/ReleaseGuard.cmake")

add_executable(myapp main.cpp)

releaseguard_protect(myapp
    POLICY "${CMAKE_CURRENT_SOURCE_DIR}/releaseguard-policy.json"
)
```

hook 会添加头文件搜索路径、强制包含生成的种子头文件，并要求至少 C++17。
它在配置阶段为目标生成 `build/releaseguard-generated/myapp` 资产，并检查编译器和
链接器是否支持 IPO／LTO；不支持时会在配置阶段报错。
Release 启用 LTO 和平台相应的优化、编译加固及链接选项，链接后运行 policy 门禁。

MSVC 的 Release 保护还设置 `/DEBUG:NONE`、`/INCREMENTAL:NO` 和 `/NOCOFFGRPINFO`，
抑制 PDB、增量链接及 COFF 分组调试记录。`/NOCOFFGRPINFO` 未列在微软公开 LINK
选项清单中，其接受情况与实际效果依赖所用工具链；请检查链接诊断和最终门禁结果。
本项目没有通过放行 COFF/POGO 条目来消除构建失败，也不修改二进制以清空安全元数据。

目标构建目录中的种子与第 2 步 vendor 资产中的种子分别管理；目标不会自动继承
vendor 种子。默认在同一目标构建目录复用已生成的种子。若要固定实际目标构建种子：

```cmake
releaseguard_protect(myapp
    POLICY "${CMAKE_CURRENT_SOURCE_DIR}/releaseguard-policy.json"
    SEED 0123456789abcdef
)
```

同一目标只调用一次 `releaseguard_protect`。要切换目标种子或工具资产版本，使用新的
构建目录；不要在已有构建目录中强行覆盖生成资产。

Linux 的 Release 链接使用 `-z now` 提前完成符号绑定，可能改变原来依赖延迟绑定的
行为，需要执行项目兼容性测试。共享库与模块库保留既有符号可见性；hook 不会自动隐藏
或重命名公共导出。修改 DLL／共享库的 ABI 仍由开发者明确决定并验证。

## 5. 在 C++ 中选择要保护的文字

```cpp
#include <cstdio>
#include <releaseguard/literal.hpp>

int main() {
    auto message = RG_TEXT("MYAPP_INTERNAL_RELEASE_MARKER");
    std::puts(message.c_str());
    return 0;
}
```

通过 hook 构建时，种子头文件已被强制包含。脱离 hook 手动编译组件时，必须先包含
生成的 `releaseguard_build.hpp`，再包含 `releaseguard/literal.hpp`，并设置相应搜索路径。

`message` 拥有解码后的缓冲区，指针只能在该对象存活期间使用。先保存对象，再调用
`message.c_str()`／`message.data()`；组件禁止从临时对象直接取指针。
若下游 API 异步保存指针，应让对象活到异步工作结束，或按该 API 的所有权约定复制内容。
复制出的明文不由本组件管理。

该组件在编译期生成可逆的静态掩码，在使用时解码，析构时清理自己拥有的缓冲区。
它不能阻止 Frida 或其他运行时工具观察明文，也不会消除调用者、库或系统产生的副本。
解码器、种子和掩码都可以被分析，不应使用它分发签名私钥、长期凭证或真正需要保密的秘密。

## 6. 构建 Release 并处理门禁结果

Linux，从软件工程根目录运行：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DPython3_EXECUTABLE="$PWD/.venv/bin/python"
cmake --build build --config Release
```

Windows PowerShell：

```powershell
cmake -S . -B build -DPython3_EXECUTABLE="$PWD/.venv/Scripts/python.exe"
cmake --build build --config Release
```

单配置生成器（如 Ninja）在 Windows 也需要配置 `-DCMAKE_BUILD_TYPE=Release`；
Visual Studio 等多配置生成器使用 `--config Release` 选择配置。
严格 policy 下，Debug／RelWithDebInfo 保留调试资料而导致门禁失败是预期结果；
这些配置也不启用 hook 的 Release LTO 和优化选项。

链接后的自动门禁会检查当前目标文件，并默认检查其旁边**同文件 stem**的侧文件。
例如 `myapp.exe` 对应 `myapp.pdb`、`myapp.map`；它不会自动检查整个发布目录中的
任意调试资料。错误返回会令构建失败；先查看 JSON `findings`，再修改发布产物或明确调整策略。
不要把未完成扫描、未知元数据或工具配置失败记为通过。

## 7. 检查完整发布目录并签发

将实际要发布的文件整理到独立目录后，显式指定 `--root`：

```bash
releaseguard gate ./release/myapp --policy ./releaseguard-policy.json --root ./release
```

Windows 将目标路径替换为例如 `./release/myapp.exe`。目标必须位于所选发布目录内。
`--root` 将禁止扩展名的检查范围扩大到整个目录及子目录；字面量和二进制元数据检查
仍只针对命令中指定的目标。发布多个 EXE／DLL／ELF 文件时，应对每个适用二进制分别运行。

推荐的发布顺序是：

1. 生成 Release，执行功能、DLL ABI 与性能验证，整理最终发布目录。
2. 对每个二进制运行 gate，并用 `--root` 检查整个目录的禁止扩展名。
3. Windows 发布物需要 Authenticode 时，完成 Authenticode 签名；在最终已签文件上再次运行 gate。
4. 对最终发布目录生成并签署 Release Guard 清单，然后验证清单和最终文件。

Authenticode 会改变文件字节和摘要，所以清单必须基于完成代码签名后的文件生成。
清单签名文件放在被签目录之外；签署清单后不要再修改受清单保护的文件。
日志、缓存、用户配置等运行期可变数据放在独立位置，不纳入要求内容不变的发布清单。
签发私钥留在开发者或服务端受控环境中；客户端只需要公钥。

gate 通过表示该产物符合声明的静态发布规则，**不表示已经通过 REA 反编译或破解评估**。
对 REA 的能力审阅和真正的对照实验要求见
[REA 威胁模型](rea-threat-model.zh-CN.md)。
