# v0.4.0 的运行时保护边界

[English](runtime-protection.md) · [简体中文](runtime-protection.zh-CN.md)

Anti-REA Forge 增加了两个需要主动接入的组件：减少不必要秘密暴露的 C++17 内存分配，以及由可信服务一次性消费、绑定具体请求的短期授权。它们无法让攻击者控制的客户端具有机密性。能够观察合法操作的调试器、注入脚本或 hook，仍可能获得操作的输入和输出。

Python 发行包仍为 `open-release-guard`，CLI 与导入包仍为 `releaseguard`。这些组件不会部署身份认证、TLS、授权服务器、TEE 或原生资产解密 SDK。密码校验记录、加密资产与发布门禁见[密码学接入说明](crypto-protection.zh-CN.md)，完整信任边界见[安全说明](../SECURITY.md)。

## 已审阅的 REA 源码能力

本轮审阅固定在提交 [`d72021b0dabedcc6fbc7bc6e0286fd359c604271`](https://github.com/morluto/rea/tree/d72021b0dabedcc6fbc7bc6e0286fd359c604271)。其 [`package.json`](https://github.com/morluto/rea/blob/d72021b0dabedcc6fbc7bc6e0286fd359c604271/package.json) 声明源码包版本 **6.7.0**、可选依赖 **Frida 17.23.2**。这用于标识源码与依赖，不代表已核验 npm 发布状态，也不代表已完成 REA 对本版本的端到端攻击测试。

固定版本的[工具契约](https://github.com/morluto/rea/blob/d72021b0dabedcc6fbc7bc6e0286fd359c604271/src/contracts/fridaToolContracts.ts)、[插桩管理器](https://github.com/morluto/rea/blob/d72021b0dabedcc6fbc7bc6e0286fd359c604271/src/frida/FridaInstrumentationManager.ts)、[工具注册](https://github.com/morluto/rea/blob/d72021b0dabedcc6fbc7bc6e0286fd359c604271/src/server/registerFridaTools.ts)和 [Frida 说明](https://github.com/morluto/rea/blob/d72021b0dabedcc6fbc7bc6e0286fd359c604271/docs/frida-instrumentation.md)提供 attach、spawn 会话、调用方脚本加载与脚本消息采集。spawn 的进程可以先暂停，在加载脚本后恢复执行。脚本路径是工具读取脚本的路径；加载脚本并不等于只允许被动观察。Frida 官方 [JavaScript API](https://frida.re/docs/javascript-api/#interceptor)包含内存访问、函数拦截与替换能力。

实际能否运行仍受可选绑定、平台策略、目标权限与架构限制。REA 单次插桩的超时和消息采集预算不是脚本内存读取能力的上限，持久会话另有生命周期。模型或 provider 错误、权限拒绝、超时、截断和清理失败只能说明实验受阻或不完整，不能证明防护成功。Ghidra 静态字节读取和被动 JavaScript runtime provider 也不能被表述为已完成原生运行时 dump。

| 威胁 | 可接入的措施 | 仍然存在的边界 |
| --- | --- | --- |
| attach 已运行进程，或在 spawn 后主程序运行前插桩 | 将敏感操作和签发私钥放在客户端外，减少不必要的本地秘密存活时间 | guard 页和本地调试器检测无法隔离具有目标进程权限的脚本 |
| 读取注入脚本、hook 函数、观察或替换比较 | 不分发可重复使用的签发秘密，由服务器授权真实操作 | 字面量掩码、本地校验记录和本地公钥固定都可能被受控客户端补丁修改 |
| 修改本地“已授权”分支或伪造客户端成功响应 | 可信服务核验自身获得的认证上下文，并亲自执行受保护操作 | 本地校验无法强制远端服务放行；完全离线的功能仍可能被补丁修改 |
| 重放有效签名令牌 | 绑定确切请求和上下文、限制有效期，再由持久服务端状态原子记录消费 | 窃取有效 bearer 令牌的人仍可能抢先消费其原本授权的请求 |
| 普通 core dump，或已不用的秘密留在自有原生缓冲区 | 检查锁页和 dump 状态，缩短 `secure_buffer` 作用域并显式清理 | dump 排除不阻止进程内 hook、任意调试器读取、宿主快照或其他位置的副本 |
| 合法函数使用秘密时观察明文 | 缩短生命周期，由受控服务只返回必要结果 | 这些 API 无法让攻击者控制进程中合法存在的数据不可观察 |

## 1. 明确持有并清理有界原生分配

独立头文件为 [`releaseguard/secure_buffer.hpp`](../src/releaseguard/data/include/releaseguard/secure_buffer.hpp)，要求 C++17，支持 Linux 和 Windows。现有 CMake 接入会提供包内 include 目录，`native-init` 也会将该头文件复制到生成目录的 `include` 下。本类不需要构建 seed。原有 CMake 接口见[原生构建说明](native-build.zh-CN.md)。

```cpp
#include <releaseguard/secure_buffer.hpp>

// Application-defined functions: neither should retain a copy or log the secret.
void fill_secret(unsigned char* output, std::size_t size);
void use_secret(const unsigned char* input, std::size_t size);

void handle_secret() {
    releaseguard::secure_buffer_options options{};
#if defined(__linux__)
    options.require_dump_exclusion = true;
#endif
    releaseguard::secure_buffer secret(32, options);
    fill_secret(secret.data(), secret.size());
    use_secret(secret.data(), secret.size());
    secret.clear();
}
```

这是接入示意：`fill_secret` 和 `use_secret` 由应用实现，需要遵守应用自身的错误处理与并发策略。构造接受 **1–1,048,576 字节**；其他大小抛出 `std::length_error`，要求的 OS 保护失败时清理后抛出 `std::system_error`。对象不可复制、不可移动。`data()` 只可从左值取得，指针生命周期和同步仍由调用方负责。

`secure_buffer_options` 默认 `require_lock=true`、`require_dump_exclusion=false`。支持的保护即使不是必需项也会尝试。通过 `protection_status()` 获取实际的 `locked`、`dump_excluded`、`guard_pages` 和 `dump_exclusion` 类型；可选保护下构造成功不等于全部保护成功。

| 机制 | Linux | Windows | 含义 |
| --- | --- | --- | --- |
| 分配与 guard 页 | `mmap`/`mprotect`，两侧不可访问页 | 保留不可访问页，中间提交可读写区 | payload 申请读写而非执行权限。guard 页围绕的是**按页取整**后的区域，越界到页内 padding 不一定触发异常 |
| 锁页 | `mlock` | `VirtualLock` | 报告 OS 锁页是否成功；不阻止调试器、特权读取或所有快照、休眠机制 |
| dump 排除 | 接受 `MADV_DONTDUMP` 后类型为 `linux_madv_dontdump` | **未实现**：`dump_excluded=false`、类型 `none`，没有 WER 接入 | Linux 只排除配合该标志的 core dump，不阻止任意读取或进程内 hook |
| 清理 | volatile 写入整个按页取整区域 | `SecureZeroMemory` 清理整个按页取整区域 | `clear()` 和析构在解锁、解除映射前清理自有分配，不能擦除其他副本 |

Windows 上设置 `require_dump_exclusion=true` 会失败，绝不将 `VirtualLock` 当作 dump 排除。Linux 锁页配额或策略也可能使默认必需锁页失败。应用应明确选择失败处理，不应静默降级必需保护。Linux dump 范围遵循 OS 的 [`MADV_DONTDUMP` 契约](https://man7.org/linux/man-pages/man2/madvise.2.html)。

尽量缩短分配生命周期，并直接向自有页生成秘密。将 Python `bytes`、`std::string` 或库返回值复制到该对象，并不会缩短原副本的生命周期。清理不会擦除寄存器、调用方缓冲区、分配器历史、库内部副本、此前已写出的 swap 或日志。Python 密码、资产与 capability API 使用托管对象，**不保证内存清零**。本类不会透明包裹这些 API，也不阻止 hook 读取仍在使用的 payload。

## 2. 在可信服务中消费授权

`releaseguard.capabilities` 使用 Ed25519 为 capability 签名，签名域与发布清单、离线许可证分离。签发服务必须先按服务端策略完成身份认证和授权。如果对所有未认证请求直接签发，只是在为攻击者选择的参数加签。

```python
from releaseguard.capabilities import ReplayStore, issue_capability, consume_capability

# Provision ONCE in a controlled server directory; never initialize on a miss.
ReplayStore.create(server_database_path, max_entries=10000)

# Issuer service: all identity/policy values and request bytes are trusted inputs.
document = issue_capability(
    issuer_private_key,
    subject=authenticated_subject,
    audience="export-service",
    product="MyApp",
    operation="export",
    request=authorized_request_bytes,
    ttl_seconds=60,
)

# Resource service: reconstruct expected context from its own authenticated request.
store = ReplayStore(server_database_path, max_entries=10000)
claims = consume_capability(
    document, pinned_issuer_public_key, store,
    subject=authenticated_subject,
    audience="export-service",
    product="MyApp",
    operation="export",
    request=actual_request_bytes,
)
# Only after successful committed consumption:
perform_protected_operation(actual_request_bytes, subject=authenticated_subject)
```

示例中的路径、密钥、认证身份、请求字节和业务函数都由接入方提供。初始化与日常消费属于不同部署阶段；`ReplayStore(path)` 只打开已有、验证通过的数据库。store 为各次操作建立连接，不作为 context manager 使用。

接口为：

```text
issue_capability(private, *, subject, audience, product, operation,
                 request: bytes, ttl_seconds=60, now=None) -> dict
consume_capability(document, public, store, *, subject, audience, product,
                   operation, request: bytes, now=None) -> dict
ReplayStore.create(path, max_entries=10000) -> ReplayStore
ReplayStore(path, max_entries=10000)
```

有效期必须为 **1–300 秒的整数**，请求字节上限为 **1 MiB**。四个身份或上下文字段必须是非空 NFC 文本，各不超过 128 个 UTF-8 字节，不能有首尾空白或被禁止的控制、格式字符。envelope 仅含 `format`、`claims`、`signature`，format 为 `open-release-guard-capability/v1`。签名 claims 包含 `version`（1）、`subject`、`audience`、`product`、`operation`、随机 `jti`、`request_sha256`、`iat`、`exp`。这些字段可读，并非加密内容。签名文档本身是凭证，不应公开到日志或 issue。拒绝时抛出 `releaseguard.core.GuardError`。

使用固定的签发公钥或可信服务控制的密钥注册表。不要从令牌或随令牌一起到来的不可信下载中接受替换公钥。签发私钥只留在签发方控制的环境，不能嵌入客户端、构建 seed、资产或分发配置。可信验证方还应确保该密钥确实属于当前产品与策略。私钥泄漏后需要撤销、轮换，并制定尚未过期令牌的处理策略。

服务端自己提供预期的 `subject`、`audience`、`product` 和 `operation`，不能照抄令牌 claims 或客户端参数。它对即将执行请求的确切字节计算散列。这里没有自动 HTTP 或 JSON 规范化：应用应定义无歧义的编码，并绑定识别授权动作所需的资源、payload、会话或 challenge。只散列客户端提供的摘要，却执行另一份请求，会破坏绑定。应在认证后于可信服务内重建这些上下文。

两个 API 均接受带时区的 `datetime` 作为 `now`，用于可信时钟与确定性测试；默认使用服务器当前 UTC 时间。不要将客户端时间戳或令牌中的时间作为验证时钟。应使用维护正常的服务器时间，而非受控客户端的墙上时钟。

### 重放状态与失败处理

持久 SQLite store 使用原子消费，使共享同一个有效 store 的并发调用不能都消费同一授权。服务必须在放行或开始受保护操作**之前提交消费**。签名错误、上下文不符、请求字节不符都不能被当作继续执行的理由。

store 持久保存时钟下限，检测到时间回拨时拒绝，而不是用回拨时间清理记录。签名、上下文、请求或时间不合法时不会推进下限；其他检查通过的尝试，即使因重放或容量被拒绝，也可能推进下限。过期条目只能在允许的时间推进后清理。这依赖可信服务器时间和完整状态；数据库中的时钟下限不是硬件可信时间。恢复旧数据库或整机快照，可能同时恢复已消费令牌和旧时钟状态。

数据库及祖先目录必须由可信服务控制，不得并发替换，存储须支持正常的 SQLite 锁与持久性。文件检查可检出普通替换，不能抵御恶意文件系统所有者或状态回滚。Windows 目录需配置适当 ACL；POSIX store 文件权限为私有的 `0600`。数据库缺失时应拒绝，不能静默创建空重放状态。`max_entries` 已持久化，重新打开时必须匹配；仍有效条目达到上限时拒绝，不会通过驱逐记录来放过重放。损坏、锁竞争、容量耗尽和存储错误都需要明确运维处理，不能在状态不可用时绕过验证。多个副本各用独立数据库，会允许每个副本消费一次。需要共享权威重放状态的架构，或另行评估的分布式协议；SQLite 本身不是该分布式协议。

每次消费都会验证有界数据库，包括已有记录。默认容量为 10,000，可配置上限为 1,000,000；它们是资源边界，不是已验证的生产吞吐目标。将其作为在线服务依赖前，应评估部署中的延迟、锁竞争和存储增长。

这里提供的是**至多一次授权消费**，不是恰好一次业务执行。消费后、业务完成前崩溃，会使授权已用但业务未完成。幂等、持久任务状态和恢复要与业务事务一起设计。持有被窃有效 bearer capability 的人，仍可能抢先执行其原本授权的请求。短有效期与精确绑定只能限制该用途，无法识别持有者或阻止窃取。传输认证、TLS、客户端或会话控制、限流和应用授权仍属于部署责任。audience 和权限范围的理由与 [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) 一致，但本项目不是 OAuth 实现，也不作合规声明。

### CLI 接入示意

这些命令应在受控的签发或资源服务环境中使用，不能单独完成用户身份认证或运行远端服务。请在源码仓库和发布目录外准备可信目录，私钥须已按原有签发密钥流程生成。`request.bin` 代表服务器批准的确切请求字节，不是客户端自行给出的授权决定。

```bash
releaseguard replay-store-init --out server-state/replay.db
releaseguard capability-issue --private issuer/issuer-private.pem --subject customer-001 --audience export-service --product MyApp --operation export --request server-work/request.bin --ttl 60 --out server-work/capability.json
releaseguard capability-consume server-work/capability.json --public server-config/issuer-public.pem --store server-state/replay.db --subject customer-001 --audience export-service --product MyApp --operation export --request server-work/request.bin
```

签发私钥通过 `getpass` 或现有 `RELEASEGUARD_PASSPHRASE` 秘密管理输入解锁，没有明文口令参数。输出创建拒绝覆盖已有文件。同一令牌再次消费会报错。CLI 的成功 JSON 只说明已消费，不会执行业务操作。应将 API 接入服务自身的强制执行路径，不能接受客户端上报的 CLI 成功结果。

## 影响设计边界的研究

原生设计也参考成熟开源项目的安全内存指南：[libsodium](https://doc.libsodium.org/memory_management) 说明守卫分配、明确清理与检查锁页结果；[OpenSSL secure heap](https://docs.openssl.org/3.6/man3/OPENSSL_secure_malloc/) 说明初始化及实际保护状态，包括某些条件下的保护降级或普通分配回退。这些资料支持本项目显式要求保护并报告真实状态的选择。本头文件是独立且范围有限的 OS 封装，不继承上述项目的审计结论，也不能保证库内部副本或实时 hook 的保密性。

以下是 2024–2026 年的一手研究来源。论文的系统、假设和测量与本项目相互独立。本项目**没有实现或复现其中的防御或攻击**，也不会把论文耗时、概率转换成本项目对 REA 的抵抗分数。

- **Stateful Least Privilege Authorization for the Cloud — USENIX Security 2024。** 作者 Leo Cao、Luoxi Meng、Deian Stefan、Earlence Fernandes。[会议页面](https://www.usenix.org/conference/usenixsecurity24/presentation/cao-leo) · [论文](https://www.usenix.org/system/files/usenixsecurity24-cao-leo.pdf)。论文通过服务端策略与动作历史约束 bearer token 权限，支持将状态和最小权限一起审查。本项目的精确请求 capability 与 SQLite 重放库没有复现其 WebAssembly/OAuth 框架，也不能继承论文的评估结果。
- **HECKLER: Breaking Confidential VMs with Malicious Interrupts — USENIX Security 2024。** 作者 Benedict Schlüter、Supraja Sridhara、Mark Kuhne、Andrin Bertschi、Shweta Shinde。[会议页面](https://www.usenix.org/conference/usenixsecurity24/presentation/schl%C3%BCter) · [论文](https://www.usenix.org/system/files/usenixsecurity24-schluter.pdf)。恶意宿主中断可影响机密虚拟机控制流。工程启示是审查宿主与客户机接口及可信计算基，不能把反调试当作隔离。它不是针对本项目的演示，论文 TDX 定位实验包含应用插桩。
- **CounterSEVeillance: Performance-Counter Attacks on AMD SEV-SNP — NDSS 2025。** 作者 Stefan Gast、Hannes Weissteiner、Robin Leander Schröder、Daniel Gruss。[会议页面](https://www.ndss-symposium.org/ndss-paper/counterseveillance-performance-counter-attacks-on-amd-sev-snp/) · [论文](https://www.ndss-symposium.org/wp-content/uploads/2025-1038-paper.pdf)。所评估环境中，宿主可见性能计数器泄露依赖秘密的行为。内存加密不足以证明没有侧信道，但该结果也不能证明所有当前 TEE 配置都存在相同漏洞。
- **TEEcorrelate: An Information-Preserving Defense against Performance-Counter Attacks on TEEs — USENIX Security 2025。** 作者 Hannes Weissteiner、Fabian Rauscher、Robin Leander Schröder、Jonas Juffinger、Stefan Gast、Jan Wichelmann、Thomas Eisenbarth、Daniel Gruss。[会议页面](https://www.usenix.org/conference/usenixsecurity25/presentation/weissteiner) · [论文](https://www.usenix.org/system/files/usenixsecurity25-weissteiner.pdf)。其计数聚合与数值去相关针对特定可观察通道，不是任意随机延迟的配方，不是反 Frida 功能，也不保证阻止明文 dump。
- **BreakFAST: Confused Deputy Attack on Infinity Fabric to Break AMD SEV-SNP — IEEE S&P 2026。** 作者 Philipp Giersfeld、Benedict Schlüter、Shweta Shinde。[官方录用列表](https://www.ieee-security.org/TC/SP2026/accepted-papers.html) · [作者论文](https://www.shwetashinde.org/publications/breakfast_oakland26.pdf)。该平台信任链缺陷说明应审查固件、宿主接口与远程证明假设。它不能证明所有 TEE 已被攻破；论文作者没有实现并验证其提出的缓解方案。

将秘密操作移到服务器，改变的是需要信任哪台主机，不代表服务器不可攻击。其输出和可观察行为仍可能被用于黑盒功能复刻。TEE 只有在合适的平台、更新后的固件、远程证明与密钥释放策略、较小可信代码基及明确侧信道假设下，才能改变威胁模型。本版本没有 TEE 接入。更换算法或添加调试器检测，无法修复客户端已经持有秘密或明文的事实。

## 证据与后续工作

[早期验证记录](testing-2026-10-15.zh-CN.md)与 [v0.3 观察结果（英文）](testing-2026-10-20.md)记录了自有合成样本的恢复，包括运行时明文恢复。这些失败仍然有效。源码审阅和 API 功能测试不会推翻它们，也不构成 REA 端到端防护通过。平台覆盖以 [v0.4 验证报告（英文）](testing-v0.4-2026-10-20.md)和[确切提交的 Actions 结果](https://github.com/Afloat16/anti-rea-forge/actions)为准，本说明不估计破解概率，不声称执行了未运行的平台测试。

一次[真实 Frida 17.23.2 尝试](results/frida-buffer-2026-10-20.json)用 GCC 13.3、`-O2` 编译自有 C++ 样本，其独立对照运行成功退出。spawn 返回 `NotSupportedError: target exited with status 1`；attach 前自有进程仍存活，但 attach 返回 `ProcessNotFoundError: unable to find process with pid 27`。两条路径均未完成 hook 或内存读取观察，具体 OS 原因未经证实。记录为 `environment_or_instrumentation_failure`、`protection_outcome=not_evaluated`，不能记为防护通过。该尝试也未运行 REA agent、模型或 provider 流程。

欢迎贡献可复现且获得授权的实验、Windows 验证、失败处理及范围明确的威胁模型改进。仅使用自有或获授权样本，记录工具版本和受阻阶段；恢复出秘密时应记为防护失败。遵循[贡献说明](../CONTRIBUTING.md)与[安全说明](../SECURITY.md)，不要提交真实签发私钥、令牌、密码或客户数据。
