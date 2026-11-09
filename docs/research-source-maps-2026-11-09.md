# Two tools, one concrete disclosure: recovering original JavaScript from source maps

The spelling `creft-anything` is not a verified project identity. The closest relevant official project we found is **Craft Anything**: [ArtCraft's product page](https://getartcraft.com/apps/craft-anything) links to [`storytold/craft-anything`](https://github.com/storytold/craft-anything). We use that name below; we do not assume it is a fork of, or interoperable with, [REA](https://github.com/morluto/rea). Both inspect JavaScript artifacts independently.

## What the source establishes

| Source | Relevant behavior | Consequence for a release |
| --- | --- | --- |
| [ECMA-426 source map format](https://tc39.es/ecma426/#sec-source-map-format) | `sources` identifies original sources; optional `sourcesContent` can carry their actual text. Index maps can contain nested maps. | Minifying the JavaScript does not remove text in a separate copy of the map. A mapping without embedded text is not itself proof that the original file can be recovered. |
| [REA `SourceMapFormat.ts`, pinned commit `99d00d1`](https://github.com/morluto/rea/blob/99d00d1041e9dd66736239c5f607c7178938c118/src/javascript/sourceMaps/SourceMapFormat.ts#L293-L368) | Parses regular and indexed maps, traverses sections and associates each source with its embedded content when present. [Upstream CLI/MCP acceptance fixture](https://github.com/morluto/rea/blob/99d00d1041e9dd66736239c5f607c7178938c118/tests/acceptance/applications/blockSourceMapCli.test.ts#L14-L81) checks an ASAR block-comment map link. | Audit the contents of the artifact actually shipped. This source review does not mean our experiment ran REA's entire agent, browser or ASAR workflow. |
| [Craft Anything v0.5.0 `js_sources_restore`](https://github.com/storytold/craft-anything/blob/622d023cdfdb91c00df8b9a37c486a2a18fb0917/crates/engine/src/tools/web_tools.rs#L513-L529) | Writes eligible embedded original files into its recovery directory and labels them `original-source`. Its [map selection code](https://github.com/storytold/craft-anything/blob/622d023cdfdb91c00df8b9a37c486a2a18fb0917/crates/engine/src/tools/web_tools.rs#L557-L570) handles inline maps and relative references, and also looks for `SCRIPT_NAME.map` in its fallback branch. | A build that omits `sourceMappingURL` but still publishes `app.js.map` alongside `app.js` can still disclose the original text. Removing the comment alone does not address this path. |

The Craft snapshot above is the [v0.5.0 release tag](https://github.com/storytold/craft-anything/releases/tag/v0.5.0), commit `622d023cdfdb91c00df8b9a37c486a2a18fb0917`; the [workspace version](https://github.com/storytold/craft-anything/blob/622d023cdfdb91c00df8b9a37c486a2a18fb0917/Cargo.toml#L1-L10) matches. For tool semantics, the executed binary's release tag is the reference. REA's independently pinned [source package](https://github.com/morluto/rea/blob/99d00d1041e9dd66736239c5f607c7178938c118/package.json#L1-L6) has version `6.8.0`. A matching version label alone does not prove that another build is byte-identical to the checkout.

## Measured result: Craft Anything v0.5.0, Linux x86-64, Deep mode

The [recorded three-case run](results/craft-source-map-2026-11-09.json) used the production splitter's public/private outputs and the **unmodified official release CLI**. All three `js_sources_restore` calls exited 0, reported complete coverage, and pretty-printed the same JavaScript. A `1` in the originals column is a file whose SHA-256 equals the independently pinned original, not a resemblance score.

| Input actually available to the tool | Original files restored | Unique source-only comment in emitted files | Pretty-printed bundle |
| --- | ---: | --- | --- |
| Ordinary distribution, unlinked map alongside JS | 1 | Found | 1 |
| Public split output only | 0 | Not found | 1 |
| Public split output plus the private map, reassociated for debugging | 1 | Found | 1 |

The inspected `app.js` SHA-256 was `79a5c99baec4a8a063db6d51dc9f521f7776ace46d4f8bb1cc68c4702ca7a1e8` in every case. The original file restored by the two positive controls had SHA-256 `950aba3d70fb67f10427f86534c8dac4b17fb1d8450522f3bffdb02849664cb5`. The measured claim is limited to this exact recovery route; source-level observations about other tools above are not counted as runs of those tools.

## Method and reproduction

Test on a project-owned synthetic source with a unique, non-sensitive comment and a known file hash. Build a minified program and an external source map containing that source, with **no** `sourceMappingURL` comment in the program. Keep the copies of the public program byte-identical. A single observation of “nothing recovered” is not enough:

1. **Ordinary distribution:** the tool must inspect the minified program and recover the exact original bytes via its adjacent map. Confirm the original-file hash rather than trusting a human-readable summary.
2. **Public distribution from the splitter:** run the same tool and operation with the same permissions against the unchanged program. Require a successful completed inspection, observable readable/pretty output, and no `original-source` or source-only marker in emitted content.
3. **Debug control:** give the operator the public program plus the private map again. Require the exact original bytes to reappear. This explicitly demonstrates that distributing the private map would undo this protection.

Craft Anything's [default Clean room policy](https://github.com/storytold/craft-anything/blob/622d023cdfdb91c00df8b9a37c486a2a18fb0917/README.md#L129-L147) restricts internal inspection. The [Craft experiment](../benchmarks/craft_source_map_boundary.py) instead invokes `--deep js-sources-restore` on the same isolated synthetic fixture in all three cases. It validates the upstream CLI's version, engine, mode, coverage, input digest and emitted files. A tool error, access denial, timeout or incomplete result is never a pass. No AI model or API key is involved.

For reproducibility, supply the official [v0.5.0 Linux x86-64 tarball](https://github.com/storytold/craft-anything/releases/download/v0.5.0/craft-anything-0.5.0-linux-x86_64.tar.gz). Its SHA-256 is `d18c54ef05e5c7ef50f8c4959fee8983c0a4a1f141edc488d11f7029973c885b`; the CLI member's SHA-256 is `61beefb5fc3f3a102649a9daed94f45f2e302c3f415ea5830fbf2cc317a1f901`. The experiment checks both before use, reads only that regular archive member, and invokes the CLI without an installer, agent setup, third-party target, or network fetch. From the repository root, use a Python environment with this checkout installed. Generate fresh inputs with the [paired build and recovery experiment](../benchmarks/source_map_recovery.mjs), or reuse its retained `--work` directory. The npm packages are development tools only:

```bash
npm ci --prefix benchmarks/recovery-tools --omit=optional --ignore-scripts
node benchmarks/source_map_recovery.mjs --python /path/to/venv/bin/python \
  --out rea-observation.json --work /path/to/work
python benchmarks/craft_source_map_boundary.py \
  --archive /path/to/craft-anything-0.5.0-linux-x86_64.tar.gz \
  --baseline /path/to/work/baseline --public /path/to/work/public \
  --private /path/to/work/private --output craft-observation.json
```

## What this can and cannot protect

The intended boundary is **exact recovery through the withheld external source map**. Minified JavaScript remains readable and runnable; behavior, constants, public APIs and logic still present in the program can be analyzed independently. The comparison does not measure AI reconstruction, remove secrets used by the running program, validate an unknown release format, or demonstrate general resistance to either product. Other copies on a CDN, HTTP `SourceMap` headers, public debug servers and old deployments are separate exposure paths. Keep private maps under access control outside the public release and check deployment configuration.

**中文说明：** 本文按 ArtCraft 的官方链接，将 `creft-anything` 理解为 `storytold/craft-anything`。两套工具都能利用 source map；Craft 即使看不到 JS 注释，也会尝试同目录的 `app.js.map`。可验证的目标是拦住“通过随包 map 原样恢复源文件”这一条路径。普通样本和拿回私有 map 的样本要能恢复，公开样本仍要让工具正常处理；命令出错、默认权限拒绝、不能启动工具，都不构成防护证据。代码行为推断和等效实现仍然可能。
