# Anti-REA Forge v0.7.0

[English](README.md) · [简体中文](README.zh-CN.md) · [MIT license](LICENSE)

**Ship `app.js`. Keep `app.js.map` for debugging.**

A minified script can still ship with a readable copy of its source. If `app.js.map` contains the original text, a tool can recover comments, variable names and formatting that the build removed. Leaving the map URL out of the script doesn't help if the map is right next to it.

Anti-REA Forge splits your build into a public release and a private directory of source maps. It verifies that public files are byte-identical to their input copies. Your error tracker can still use the private maps to locate bugs; your application needs no runtime library or startup check.

## What did it stop?

We ran two unmodified analysis tools on the **same minified JavaScript**, first with its adjacent map and then from the public directory produced by the splitter.

| Tool and operation | Ordinary build (map included) | Public release |
| --- | --- | --- |
| Craft Anything · Deep source restore | Wrote **1 original file**, matching the source SHA-256 | Wrote **0 original files** |
| REA · JavaScript directory analysis | Found **1 map-backed source node** with the original content digest | Found **0 map-backed source nodes** |

Craft could still pretty-print the script, and REA fully parsed it in both runs. When we gave Craft the private map again, it restored the **same original file**. The protection covers exact source recovery through the map; the JavaScript you ship can still be analyzed.

[Inspect the Craft results](docs/results/craft-source-map-2026-11-09.json) · [Inspect the REA results](docs/results/source-map-recovery-2026-11-09.json) · [Reproduce the experiment](docs/private-source-maps.md)

## Try it in your build

From your application's build environment (**Python 3.10+ and Git**), install the tested v0.7.0 code:

```sh
python -m pip install "git+https://github.com/Afloat16/anti-rea-forge.git@0f5688b26572a8cfb37188ebbbd037bb306c1898"
```

Configure your bundler to write **separate flat v3 maps**, without an inline map or a `sourceMappingURL` comment (esbuild: `--sourcemap=external`). After building into `build/` and **before compressing** the artifacts, choose two new output directories:

```sh
python -m releaseguard split-source-maps --root build --public release-web --private debug-symbols
```

- **Deploy only `release-web/`**, and only after the command succeeds. Use a fresh deployment location or remove stale maps from the server and CDN.
- **Keep `debug-symbols/` outside every served path.** Its maps retain their relative paths for private debugging. The input `build/` is unchanged and still contains the maps.

**It catches more than filenames.** In a second test, Terser bundled the map itself into an ordinary `.mjs` module. The splitter detected the literal `sourcesContent` key, named the file and left neither output directory behind. This check is conservative: code that merely mentions the key can also be flagged. [Build settings and supported inputs](docs/private-source-maps.md)

If this solves a release problem for your team, **star Anti-REA Forge**. Have a different bundler or a packaging case we missed? [Contribute a small reproducible fixture](CONTRIBUTING.en.md).
