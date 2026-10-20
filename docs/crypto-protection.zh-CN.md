# v0.3.0 的密码学保护边界

[English](crypto-protection.md) · [简体中文](crypto-protection.zh-CN.md)

Anti-REA Forge v0.3.0 新增口令验证器、外部密钥加密的数据资产，以及更严格的发布目录门禁，用于改善可逆文字掩码暴露出的具体问题。这些能力不保证本地程序无法破解，不阻止内存观察，也不代表已经成功抵御 REA。

Python 分发名仍为 `open-release-guard`，CLI 和导入名仍为 `releaseguard`。资产接口处理数据，不是 EXE/DLL 加壳器、代码加载器或原生应用 SDK。现有 CMake 加固与 `RG_TEXT` 是独立组件，见 [原生接入指南](native-build.zh-CN.md)。

### 密码学方案取舍

本版实现成熟的 AES-256-GCM、HKDF 和 Argon2id，不自创 RC4/XTEA 方案或代码虚拟机。[AES-GCM-SIV（RFC 8452）](https://www.rfc-editor.org/rfc/rfc8452.html) 针对 nonce 误用，[HPKE（RFC 9180）](https://www.rfc-editor.org/rfc/rfc9180.html) 处理混合公钥加密；TEE/KMS 架构与后量子密钥建立处理其他信任或密钥分发问题。这些需要另行评估，当前没有实现。不能借这些名称或 FHE 宣传“本地明文 dump 已不可能”。客户端一旦合法持有解密密钥或明文，更换密码算法不会修复这个信任边界；真正保密能力的服务端划分仍然重要。

## 将用户提供的场景映射到实际改动

用户粘贴的文章描述了若干轮恢复过程及耗时，但没有提供可独立核验的作者 URL 或发布时间。因此这里只把它当作**用户提供的场景**，不将轮次和耗时写成独立测得的 REA 结果、基准数据或防护概率。本次实现不验证文章中报告的时间。

| 场景 | 具体改善 | 仍然存在的边界 |
| --- | --- | --- |
| 从静态代码、常量或解码逻辑恢复可逆 key/口令 | 口令判断改存 Argon2id 验证器；数据资产使用外部随机主密钥和认证加密 | `RG_TEXT` 仍然可逆；验证器允许离线猜测；把资产主密钥再次嵌入客户端就重现了密钥恢复问题 |
| dump 内存或观察比较/解密边界 | 没有外部密钥和预期上下文时，不能正常打开资产 | 受控客户端一旦拿到密钥或明文，就可能被观察、复制；Python 不保证密钥、口令和明文缓冲清零 |
| 在旧源码、答案、旁文件或误打包内容中找到秘密 | 对选定发布根目录扫描声明文字，拒绝已知旧文件哈希和禁止路径组件，并要求精确文件集合 | 这些不是通用秘密识别器；旧文件改字节后哈希就不同；已公开的真实秘密需要轮换 |
| 复刻功能或补丁跳过授权分支 | 用签名清单验证发行身份；把真正必须保密的能力与凭据留在受控服务端 | 签名不阻止本地补丁或独立编写兼容实现；数据加密不会自动隐藏所有原生算法 |

本次核对的 REA 官方源码为 commit `f93a0335a8c1a60bbf6debdca16675ba303e4422`，源码标识版本 **6.7.0**，并包含 Frida 插桩说明。这里说的是该源码树，**不能据此宣称 npm 已发布 6.7.0，或本项目 v0.3.0 已击败 REA/Frida**。固定来源为 [REA README](https://github.com/morluto/rea/blob/f93a0335a8c1a60bbf6debdca16675ba303e4422/README.md)、[Frida 文档](https://github.com/morluto/rea/blob/f93a0335a8c1a60bbf6debdca16675ba303e4422/docs/frida-instrumentation.md) 和 [分析 skill](https://github.com/morluto/rea/blob/f93a0335a8c1a60bbf6debdca16675ba303e4422/.agents/skills/reverse-engineer-anything/SKILL.md)。

## 1. 存口令验证器，不存可恢复答案

`releaseguard.passwords.create_password_verifier(password_bytes)` 返回精确的 `{format, phc}`，格式为 `open-release-guard-password/v1`；`verify_password(candidate_bytes, document)` 判断候选口令。记录中不存可逆口令。

固定 Argon2id 参数采用 RFC 9106 的**第二推荐配置**：

| 参数 | 值 |
| --- | --- |
| 内存 | 65,536 KiB / 64 MiB |
| 迭代轮数 | 3 |
| lanes | 4 |
| 随机盐 | 16 字节 |
| 验证值 | 32 字节 |

创建接受 12–1,024 字节口令，验证接受不超过 1,024 字节的候选值。最低长度不等于足够熵。API 接受不透明字节；CLI 将输入编码为 UTF-8，不进行文字规范化。

解析器只接受精确、规范的固定参数格式，在创建 KDF 之前拒绝恶意成本参数，不把攻击者指定的 PHC 成本直接交给密码库。这只限制单次操作，调用方仍需要限流与并发限制。Argon2id 后端不可用时会失败，不会悄悄降级到廉价算法。

先准备发布目录，再在交互终端执行：

```bash
releaseguard password-create --out release/App/password-verifier.json
releaseguard password-check release/App/password-verifier.json
```

CLI 从 `getpass` 获取输入；自动化可由可信秘密管理流程注入 `RELEASEGUARD_USER_PASSWORD`。不提供明文口令命令行参数。不要把真实口令写进 shell 命令、日志或提交的脚本。它与解锁发行签名私钥的 `RELEASEGUARD_PASSPHRASE` 是不同变量。Argon2id 当前是 Python API/CLI，尚未实现原生验证 SDK。

口令不匹配返回 3；无效输入或后端不支持属于工具错误。输出必须写到新文件。需要保护验证器完整性，否则替换验证器可改变被接受的口令。盐和验证值不是秘密密钥，但拿到它们可以进行离线猜测。强口令仍可被尝试猜测，本地校验分支仍可被补丁修改。这些命令不会自动把授权逻辑插入 C/C++ 程序，也不会自动从用户口令生成资产密钥。

## 2. 使用外部随机密钥加密数据资产

请在源码仓库之外的独立打包工作目录执行以下示例。为密钥和明文工作文件准备受控目录，放在 Git 仓库和发布包之外。以下相对目录仅用于说明布局；`work/model.bin` 应是你的自有数据，最大 **1 MiB**：

```bash
mkdir -p external work release/App
releaseguard asset-keygen --out external/asset.key
releaseguard asset-seal work/model.bin --key-file external/asset.key --product App --release 1 --purpose model --asset-id model-main --out release/App/model.sealed.json
releaseguard asset-open release/App/model.sealed.json --key-file external/asset.key --product App --release 1 --purpose model --asset-id model-main --out work/model-opened.bin
```

`external/asset.key` 是**随机的 32 字节原始二进制文件**，不是 Base64、口令、PEM 签名私钥，也不是公开的 CMake 构建种子。不要把它放进仓库或发布包。生成命令拒绝覆盖现有文件；父目录必须已存在且可信。请设置合适的目录权限和 Windows ACL。读取接口会拒绝链接或发生变化的密钥文件，但这些检查不能替代对祖先目录的控制。

Python 入口为 `releaseguard.sealed.seal_asset(plaintext, key, product, release, purpose, asset_id)` 和 `open_asset(document, key, product, release, purpose, asset_id)`。它们处理字节及 32 字节主密钥，是有大小上限的内存数据接口，不是流式模型加载器。

每次封装内部生成 32 字节随机盐，通过 HKDF-SHA256 派生 32 字节资产密钥，再生成 12 字节随机 nonce 进行 AES-256-GCM 加密。密文附带完整的 16 字节认证 tag。调用方不能自行传入盐或 nonce。JSON 信封的字段精确为：

```text
format, salt, nonce, ciphertext
```

`format` 为 `open-release-guard-sealed-asset/v1`。二进制字段使用带填充的规范标准 Base64；`ciphertext` 包含认证 tag。信封不包含主密钥，也不能自行决定受信任的产品和版本身份。

`product`、`release`、`purpose`、`asset_id` 四项必须来自调用方的可信预期，打开时再次提供。它们同时参与密钥派生和认证附加数据绑定。不要读到攻击者提供的包或下载响应后，就把其自报上下文当成可信预期。实现验证有长度上限的 NFC 标识符；两端必须使用完全相同的值。

认证失败时 `open_asset` 不返回明文。CLI 在整个有限大小的资产认证成功后才新建明文输出，拒绝覆盖已有路径。打开操作会实际生成明文文件，必须把输出留在发布目录之外；接口不会执行资产内容。

保密前提是主密钥不落入攻击者手中。持有该密钥的人既能解密，也能创建有效资产；受控进程仍可观察解密结果。同一上下文内的有效旧资产可被重放，预期版本需要独立可信更新/新鲜度策略。Python 和密码库缓冲没有可靠清零保证。

## 3. 检查最终发布根目录

主产物参数仍是 PE 或 ELF；`--root` 指定最终发布目录，主产物必须位于其中。[policy-strict-release.json](../examples/policy-strict-release.json) 提供严格示例，请按自己的构建调整文件名与规则：

```bash
releaseguard gate release/App/App.exe --policy /path/to/anti-rea-forge/examples/policy-strict-release.json --root release/App
```

| 新策略字段 | 含义 |
| --- | --- |
| `forbid_path_components` | 拒绝不区分大小写的精确路径组件名，包括禁止目录；不是通配符 |
| `forbid_file_sha256` | 拒绝已知的完整文件 SHA-256，写成 64 位小写十六进制 |
| `allowed_release_files` | 要求精确的发布相对文件集合，多文件或少文件都失败 |
| `scan_release_literals` | 为 true 时，对发布目录每个文件扫描 `forbid_literals`，不只检查主程序 |
| `max_release_scan_bytes` | 限制发布范围文字/哈希扫描读取的总字节数；默认 64 MiB，允许 1–536,870,912 字节 |

**只要显式写入上述任意字段，就必须提供 `--root`，即使字段值为 `false` 或空列表。** 不带 `--root` 的 CMake 构建后门禁不能替代最终目录检查。显式提供的 `allowed_release_files` 必须非空。未知字段会被拒绝。

提供的示例把 `allowed_release_files` 固定为 `["MyApp.exe", "model.sealed.json"]`，必须按实际发布文件的精确集合替换，不会自动学习允许集合。按上述布局，应将该字段改为 `"allowed_release_files": ["App.exe", "model.sealed.json", "password-verifier.json"]`。旧文件哈希列表初始为空，请按需要从可信旧文件计算 `forbid_file_sha256`。不要编造哈希，也不要假设示例已经排除了所有历史资料。

发布范围扫描覆盖 UTF-8、UTF-16 LE/BE、UTF-32 LE/BE。超过读取预算会导致检查失败，不会把大文件或不可读文件静默记为通过。文件哈希规则只匹配相同字节，文字规则只匹配声明编码。门禁不会解压归档、证明源码完全不存在或识别所有秘密。使用干净暂存目录和明确允许清单，不要夹带密钥、原源码/答案、明文资产副本或旧调试资料。策略文件也应放在精确发布集合之外，除非你有意将它纳入允许清单。

发布根目录及其祖先目录需要由可信构建者控制，扫描期间不得并发修改。现有 `lstat`/`fstat` 与目录清点检查能发现普通更改，但不是原子文件系统快照，也不能保证恶意父目录竞争下绝不读取根目录之外的文件。门禁不能防止检查后的替换，应配合签名清单以及可信安装/加载流程；它不能锁住任意恶意文件系统。

## 4. 配合签名发布清单

AES-GCM 认证是对称的：**拿到 AES 主密钥的人可以为同一上下文制作有效资产**。它不能独立证明发行者身份。发行认证应使用单独的 Ed25519 发行私钥和固定的可信公钥。

完成原生构建和 Authenticode 签名，准备好最终密文与验证器文件，执行发布根目录门禁，然后签署最终字节清单：

```bash
releaseguard manifest-sign --root release/App --private external/issuer-private.pem --product App --release 1 --out App-1.manifest.json
releaseguard manifest-verify App-1.manifest.json --root release/App --public issuer-public.pem --product App --release 1
```

发行私钥使用现有 `keygen` 流程创建，资产主密钥不是 Ed25519 密钥。签名私钥及其口令只留在受控签发环境；验证公钥或指纹必须通过独立可信渠道固定，不能由下载包自己决定。清单放在被清点目录之外，后续改字节需要重新生成。清单和 GCM 都不单独提供可靠的离线撤销、可信时间或防回滚。

## 验证与范围

[密码学边界实验](../benchmarks/crypto_boundary.py) 是实现验收入口，观察结果见 [2026-10-20 生成记录](results/crypto-boundary-2026-10-20.json)。本文不宣称新增测试数量、恢复耗时或 REA 防护分数。原 [v0.2 恢复证据](testing-2026-10-15.zh-CN.md) 仍然是旧合成样本的失败结果。

实际改善是避免存储可恢复口令、把资产密钥与公开程序/数据分离、认证可信资产身份，以及排除已知不应发布的内容。它们不自动改造所有业务程序，不阻止输入时观察凭证，也不能阻止功能复刻。若核心要求是让机器所有者也无法拿到某个永久凭据或算法能力，应把这部分留在受控服务端，并在那里执行授权。部署前请阅读 [安全模型](../SECURITY.md)。

## 一手参考

- [cryptography 50.0.2：Argon2id 与 HKDF](https://cryptography.io/en/50.0.2/hazmat/primitives/key-derivation-functions/)：口令验证和从随机主密钥派生使用不同 KDF；HKDF 不用于口令存储。
- [cryptography 50.0.2：认证加密](https://cryptography.io/en/50.0.2/hazmat/primitives/aead/)：AESGCM 的 nonce 要求、完整 tag 与认证失败行为。
- [RFC 9106 第 4 节](https://www.rfc-editor.org/rfc/rfc9106.html#section-4)：本项目采用第二推荐 Argon2id 配置。
- 上面的固定 REA 官方源码链接用于界定分析威胁，不等于已对本版本完成端到端实测。
