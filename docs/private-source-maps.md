# Deploy JavaScript without publishing its debug sources

A minified JavaScript file can be accompanied by a source map containing an
exact copy of the developer's source. Omitting the map URL from the script is
not enough if the map itself still ships. Release Guard splits a completed
build into two new directories: a public release and a private debugging copy
of its external maps. It does not execute or rewrite the application.

## Build, split, deploy

Use Python 3.10+ and install this checkout in a build environment
(`python -m pip install .`). Build into an **unpublished**, immutable directory.
Request external maps without a `sourceMappingURL` comment. For example, an
existing esbuild project can use:

```sh
esbuild src/app.ts --bundle --minify --sourcemap=external --outfile=build/app.js
python -m releaseguard split-source-maps --root build --public release-web --private debug-symbols
```

With Terser, set `sourceMap: { filename: "app.js", includeSources: true }` and
write the returned `code` and `map` separately. Leave the `url` option unset.
The [experiment](../benchmarks/source_map_recovery.mjs) includes a complete,
version-locked example. With other bundlers, verify the files your build really
produces before deployment. A linked or inline map will block this workflow;
configure the build to emit an unlinked external map, then run the split again.

For an input containing `js/app.js` and `js/app.js.map`:

| Destination | Contents | Use |
| --- | --- | --- |
| `release-web/js/app.js` | Original generated JS bytes | Upload this **public tree only** to the web root or CDN |
| `debug-symbols/js/app.js.map` | Original map, at its matching relative path | Store outside the served tree, with access limited to authorized debugging or symbolication |
| `build/` | Original build, unchanged, still containing the map | Keep in trusted staging; do not deploy it |

Both output paths must be fresh, disjoint directories with existing, trusted
parents. Use a new pair for each build. Only act on the outputs after success.
Normal errors are rolled back. A crash or an interrupted filesystem is not a
two-directory atomic transaction; discard incomplete staging before publishing.
The command does not update your host, CDN, HTTP headers or application.

The splitter applies its own fixed checks. If you use a saved project policy,
point its release root at the new public directory and run `check` or `prepare`
there as usual. Keep your private maps out of that signed public release.

### What the command checks

- Splits unpacked regular files with a `.map` suffix (case-insensitive) into the
  private tree; expects flat v3 maps. Indexed maps, binary/linker maps and other
  unsupported map layouts do not silently pass. It does not fetch source URLs.
- Checks the copied public inventory and SHA-256 hashes, runs the portable
  release scanner, and blocks recognized data such as map markers, disguised
  v3 JSON maps and private-key PEM markers. It also compares public file hashes
  with embedded source text to catch an exact loose copy.
- Operates **before compression**. Recognized archives/disabled archive
  inspection and precompressed assets covered by the policy block publication.
  It is not a decoder for every container or arbitrary encoding.
- Rejects overlapping paths, links/reparse points and special files. Uses
  bounded input and fixed checks. Keep the inputs and ancestor directories
  trusted for the duration of the build. Protect private maps with appropriate
  filesystem permissions or ACLs; they may contain the full source.

Exit **0** means both checked outputs were produced. Exit **3** means findings
blocked the split. Exit **2** means invalid/unsupported input, an I/O error or
an incomplete check. Never publish after a nonzero exit. A map-free input is
not reported as a successful mitigation by this command; use ordinary `check`
when auditing builds that did not generate maps.

### Keep production errors debuggable

Store the private output with the exact release identifier or the deployed
bundle digest. Give your debugging service that map over a private channel.
Do not upload maps to a public prefix, use the debug directory as a fallback
route, or leave older maps in a CDN cache. Check production `SourceMap` and
`X-SourceMap` response headers, as well as predictable sibling URLs such as
`/js/app.js.map`. Deploy the public directory into a **fresh** release prefix
or remove stale objects; overlaying it on yesterday's directory leaves old maps
reachable. The offline split cannot verify your live deployment.

## What was measured

The [source review](research-source-maps-2026-11-09.md) identifies the relevant
operations in REA and ArtCraft's Craft Anything. In the [recorded Craft
experiment](results/craft-source-map-2026-11-09.json), the official Linux
v0.5.0 CLI runs `js-sources-restore` in Deep mode on one project-owned fixture.
It reformatted the same bundle on every run, with complete coverage:

| What Craft received | Exact original returned |
| --- | --- |
| Ordinary release, including the adjacent `app.js.map` | 1 file with the known source SHA-256 |
| Split public release, with the same `app.js` | 0 files |
| Same public release, with the private map supplied again | 1 file with the original SHA-256 |

The [trace-mapping observation](results/source-map-recovery-consumer-2026-11-09.json)
also checks the actual source text and restores the original location from the
private map. The generated JavaScript is byte-identical and gives the same
results for four fixture inputs. This is **exact source recovery through a
specific shipped artifact**. Generated logic remains available to the user;
the experiment does not establish resistance to behavioral reconstruction,
native decompilation, runtime observation or a complete AI agent session.

### Reproduce both tool runs on Linux

Use an installed Release Guard Python environment and Node 24.22.1 (the CI
version). The npm dependencies below are for experiments only. From this checkout:

```sh
npm ci --prefix benchmarks/recovery-tools --omit=optional --ignore-scripts --no-audit --no-fund
node benchmarks/source_map_recovery.mjs --work ./map-fixture --python "$(command -v python)" --out ./rea-result.json
```

Use fresh work/report paths. This builds the synthetic fixture, invokes the
installed split command, runs the published REA CLI on ordinary and public
directories, and checks original content/positions with trace-mapping. A
provider error or incomplete graph cannot pass. For an explicit consumer-only
check, add `--consumer-only`; its report does not claim a REA run.

Download the [pinned Linux x86-64 Craft release](https://github.com/storytold/craft-anything/releases/download/v0.5.0/craft-anything-0.5.0-linux-x86_64.tar.gz),
then use the same fixture:

```sh
python benchmarks/craft_source_map_boundary.py --archive ./craft-anything-0.5.0-linux-x86_64.tar.gz --baseline ./map-fixture/baseline --public ./map-fixture/public --private ./map-fixture/private --output ./craft-result.json
```

The script verifies both the archive and the CLI member by SHA-256 before use.
Only project-owned synthetic inputs are used. The consumer and Craft results
are distinct from the REA CLI evidence; no model credentials are required.

## 中文接入

构建时生成单独的 `.map`，让它留在构建目录，不要把映射地址或内联图嵌进
JS。执行上面的 `split-source-maps` 命令后，**只发布 `release-web/`**；
`debug-symbols/` 供受限的调试或错误跟踪服务使用，原始 `build/` 也不能上线。
两个输出目录都必须是新目录，先分离，再压缩或打包。部署到已有站点时请同时
清理旧的公开 map 和 CDN 缓存，检查源映射响应头。

这一措施阻断的是用发布包中的 source map 原样取回源码。三组实验中相同工具都
正常完成、同一份 JS 都能格式化；授权调试方拿回私有图仍可恢复原文。它不需要
模型合作，也不会给应用增加启动检查、后台任务或运行库。复制和检查发生在构建
阶段，会产生磁盘和 CPU 开销。
