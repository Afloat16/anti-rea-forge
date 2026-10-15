# Windows 构建与发布加固

本页说明从 v0.1 保留的 `releaseguard_harden` MSVC 接口及 Windows 发布流程。v0.2 的 `releaseguard_protect`、文字掩码、LTO 和发布门禁见[编译接入指南](native-build.zh-CN.md)。本页列出的缓解选项本身不会阻止 IDA、Ghidra 或其他工具读取机器码、反汇编或反编译。

开源算法与实现可以接受公开审查；授权和清单签名的可信性应依赖你独立保管的私钥。公钥允许公开。客户端校验仍可被修改，因此关键业务权限应由你控制的服务端执行。不要把“签名不可伪造”理解为“本地程序无法被补丁绕过”。

## CMake 集成

`releaseguard_harden` 要求 CMake 3.20 或更高版本、Windows 和 Microsoft MSVC 原生 C/C++ 工具链，建议使用安装了“使用 C++ 的桌面开发”工作负载的 Visual Studio 2022。该兼容接口不支持 clang-cl、MinGW、Linux，也不适用于 .NET、C++/CLI 或驱动程序；Linux 构建请使用 v0.2 的 `releaseguard_protect`。

在你自己的项目里，先创建目标，再调用函数：

```cmake
cmake_minimum_required(VERSION 3.20)
project(MyProduct LANGUAGES CXX)

include("path/to/anti-rea-forge/cmake/ReleaseGuard.cmake")
add_executable(my-product main.cpp)
releaseguard_harden(my-product)
```

对 DLL 可使用 `add_library(my-library SHARED ...)` 或 `MODULE`，然后调用相同函数。每个目标都要分别配置；选项使用 `PRIVATE`，不会自动加固其依赖项。静态库、接口库、对象库、导入目标、别名目标和不支持的工具链会报出配置错误。请把函数应用到实际参与编译、链接的目标。

| 阶段 | 选项 | 作用 |
| --- | --- | --- |
| C/C++ 编译 | `/GS` | 检测部分栈缓冲区破坏。 |
| C/C++ 编译 | `/sdl` | 启用额外安全检查和相关诊断，可能暴露已有代码问题。 |
| 编译和链接 | `/guard:cf` | 增加控制流保护检查及元数据，约束部分间接调用目标。 |
| 链接 | `/DYNAMICBASE` | 使映像支持地址空间布局随机化。 |
| 链接 | `/NXCOMPAT` | 声明映像与数据执行保护兼容。 |
| 64 位目标链接 | `/HIGHENTROPYVA` | 支持高熵 64 位地址空间布局随机化，与 `/DYNAMICBASE` 配合。 |
| 仅 Release | `/O2`、`/OPT:REF`、`/OPT:ICF` | 启用优化、移除未引用的 COMDAT、折叠相同 COMDAT；不是保密措施。 |

64 位目标使用 `CMAKE_SIZEOF_VOID_P` 判断，不能从构建机器位数推断。模块不会把 Release 优化应用到 Debug，避免与常见的 `/RTC` 设置冲突。如果项目自行在 Release 中加入 `/RTC`、`/ZI`、`/clr`、`/guard:cf-`、`/DYNAMICBASE:NO` 等不兼容或相反的选项，需要先解决冲突。模块不会覆盖所有项目级设置，也不能证明第三方依赖已经加固。

CFG 应同时传给编译器和链接器。PE 头中出现安全标志不等于每段代码都受到保护；需要结合 Load Configuration、工具链输出、依赖项及实际运行测试判断。保留重定位信息，不要用 `/FIXED` 破坏 ASLR 的前提。

## 在 Windows 上构建示例

从仓库根目录，在有 MSVC 工具链的 PowerShell 或 Visual Studio 开发者终端中执行：

```powershell
cmake -S examples -B build-example -G "Visual Studio 17 2022" -A x64
cmake --build build-example --config Release
& .\build-example\Release\releaseguard-example.exe
dumpbin /headers .\build-example\Release\releaseguard-example.exe
dumpbin /loadconfig .\build-example\Release\releaseguard-example.exe
```

示例运行后应输出 `ReleaseGuard example: build mitigations enabled.`。使用 `dumpbin` 检查 Dynamic base、NX compatible、High Entropy VA，以及 Load Configuration 中的 CFG 元数据。工具链版本和程序内容可能影响具体显示。再用本工具的 PE 审计功能记录机器可读结果；审计输出不会替代运行测试。

另建 `-A Win32` 构建目录时，模块应省略 `/HIGHENTROPYVA`；Debug 构建不应出现本模块添加的 `/O2` 和 `/OPT`。v0.1 开发环境未安装 CMake 或 C++ 编译器，因此这里未在本地完成 Windows 配置、编译、运行与 `dumpbin` 验证。这些命令是供 Windows 环境执行的验证步骤，不能当作已经通过的测试结果。

## 发布顺序与符号管理

1. 以 Release 配置完成构建和功能测试，审计每个 EXE、DLL 及其发布依赖。
2. 保留精确对应这一构建的完整 PDB，放入有访问控制的私有符号服务器或私有归档，用于故障转储分析。不要把完整 PDB、源码路径清单或密钥直接加入公开安装包。确需公开调试符号时，单独评估公开符号的内容。
3. 使用你自己的 Authenticode 代码签名证书签名最终 EXE、DLL，并完成时间戳和签名验证。代码签名证书与本项目的 Ed25519 发布清单密钥是两套独立的信任机制。
4. 对签名后的最终字节生成并签署发布清单。之后再改版本资源、嵌入数据、签名或时间戳，都会改变文件字节，需要重新生成清单。
5. 在可信发布渠道提供固定公钥或可信公钥指纹、发布包、签名清单及校验说明。只把新公钥放进同一个未受信任下载包，不能建立发布者身份。

不要为减少可见符号而随意删除 DLL 导出：导出表属于 ABI，调用方、插件系统和系统加载器可能依赖它。先定义必要的公开接口，再通过 `.def` 或明确导出声明管理它；改变接口后执行兼容性测试。也不要通过修改已经签名的 PE 来“清理”内容。

Authenticode 签名不是代码加密；发布清单可以帮助发现文件被修改，离线授权可以检测未持有签名私钥者伪造的授权，但它们都不能阻止有本机控制权的人修改校验流程。需要保护的算法、服务凭据和签名私钥，应尽量留在受控环境。

## .NET 项目与 Native AOT

本 CMake 模块只处理 MSVC 原生构建，不会自动转换现有 .NET DLL。对符合条件的 .NET 项目，可以单独评估 Native AOT：它在发布时将 IL 编译为本机代码，改变直接反编译 IL 的条件，但仍然可以被分析，不能提供“无法破解”的保证。

Native AOT 需要审查项目和依赖的兼容性，尤其是动态程序集加载、运行时代码生成、反射与裁剪。微软列出的限制包括不支持 `Assembly.LoadFile`、`System.Reflection.Emit` 和 C++/CLI；Windows 还存在内置 COM 限制。需要审阅并解决 AOT/裁剪警告，并对发布后的程序做完整功能测试，不能承诺所有桌面、插件或第三方库项目都能直接使用。

若已确认兼容，可在项目中评估以下设置及发布命令：

```xml
<PropertyGroup>
  <PublishAot>true</PublishAot>
</PropertyGroup>
```

```powershell
dotnet publish -r win-x64 -c Release
```

这不是本项目自动执行的步骤。Native AOT 导出的原生共享库还具有明确的调用约定和生命周期限制；例如微软当前文档指出，不支持使用 `FreeLibrary` 卸载此类库。已有 .NET 插件接口不能据此假定保持兼容。

## 微软官方参考

- [C++ 安全最佳实践](https://learn.microsoft.com/en-us/cpp/security/security-best-practices-for-cpp)
- [/GS 缓冲区安全检查](https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check)
- [/sdl 额外安全检查](https://learn.microsoft.com/en-us/cpp/build/reference/sdl-enable-additional-security-checks)
- [Control Flow Guard 编译与链接选项](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard)
- [/DYNAMICBASE](https://learn.microsoft.com/en-us/cpp/build/reference/dynamicbase-use-address-space-layout-randomization)、[/HIGHENTROPYVA](https://learn.microsoft.com/en-us/cpp/build/reference/highentropyva-support-64-bit-aslr)、[/NXCOMPAT](https://learn.microsoft.com/en-us/cpp/build/reference/nxcompat-compatible-with-data-execution-prevention)
- [链接器优化选项 /OPT](https://learn.microsoft.com/en-us/cpp/build/reference/opt-optimizations)
- [SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
- [符号服务器与符号存储](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-stores-and-symbol-servers)
- [Native AOT 部署与限制](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/)
- [Native AOT 原生库](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
