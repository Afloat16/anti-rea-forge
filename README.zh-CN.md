# Anti-REA Forge v0.7.0

[简体中文](README.zh-CN.md) · [English](README.md) · [MIT 许可证](LICENSE)

**发布 `app.js`，把 `app.js.map` 留给开发者排查报错。**

压缩 JS 时删掉的注释、变量名和排版，可能在旁边的 `app.js.map` 里完整保留。即使脚本里没有写映射地址，分析工具也能尝试同名文件，直接取回源码原文。

Anti-REA Forge 在构建阶段把产物分成两份：一份给用户，一份给内部调试。工具逐个校验公开文件与输入文件的哈希，确保 JS 字节不变。开发者仍可用私有映射把报错位置定位到原始代码，用户的应用无需增加运行库或启动检查。

## 实际防住了什么？

我们让两个未经修改的分析工具检查**同一份压缩 JS**：先给普通构建目录，再只给拆分后的公开目录。

| 工具与操作 | 普通构建（附带 map） | 只提供公开目录 |
| --- | --- | --- |
| Craft Anything · Deep 模式恢复源码 | 写出 **1 份原始文件**，SHA-256 与原文一致 | 写出 **0 份原始文件** |
| REA · JavaScript 目录分析 | 找到 **1 个来自 map 的源码节点**，内容摘要与原文一致 | 找到 **0 个来自 map 的源码节点** |

两次检查中，Craft 都能正常格式化 JS，REA 也都完整解析了它。**把私有 map 补回后，Craft 又恢复出了同一份原文。** 这项防护堵住的是通过随包映射取回源码原文的途径；已经发布的 JS 逻辑仍然可以分析。

[查看 Craft 原始结果](docs/results/craft-source-map-2026-11-09.json) · [查看 REA 原始结果](docs/results/source-map-recovery-2026-11-09.json) · [复现实验](docs/private-source-maps.md)

## 接入自己的项目

在应用的构建环境中准备好 **Python 3.10+ 和 Git**，安装经过验证的 v0.7.0 代码：

```sh
python -m pip install "git+https://github.com/Afloat16/anti-rea-forge.git@0f5688b26572a8cfb37188ebbbd037bb306c1898"
```

让构建器生成**独立的扁平 v3 映射文件**，不要使用内联 map，也不要在 JS 中写入 `sourceMappingURL` 注释。esbuild 项目可用 `--sourcemap=external`。正常构建到 `build/` 后，在对产物做 gzip 压缩或打 ZIP 包前，指定两个尚不存在的输出目录：

```sh
python -m releaseguard split-source-maps --root build --public release-web --private debug-symbols
```

- **命令成功后，只部署 `release-web/`。** 使用新的发布路径，或清除服务器和 CDN 上残留的旧 map。
- **把 `debug-symbols/` 放在站点之外。** 其中的映射保留原来的相对路径，供内部调试使用。输入目录 `build/` 保持不变，里面仍有 map，不要上传。

**只检查 `.map` 文件名还不够。** 我们用 Terser 把映射对象打进了一个普通 JS 模块。拆分器检测到里面的 `sourcesContent` 字段，指出具体文件，且没有留下任何输出目录。这项检查较严格：仅仅提到该字段的库也可能被拦截。[构建配置与支持范围](docs/private-source-maps.md)

如果这解决了你的发布问题，欢迎给项目一个 **Star**。如果你用的是另一款构建器，也欢迎[贡献一个可复现的小样本](CONTRIBUTING.md)，让下一种打包方式也得到验证。
