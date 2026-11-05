# JavaScript release check / JavaScript 发布检查

This example uses the local JavaScript/TypeScript bridge and the installed Python
core. Read the [English SDK guide](../../packages/releaseguard/README.md) or
[中文接入说明](../../packages/releaseguard/README.zh-CN.md) for setup and API details.

From the repository root, after setting `RELEASEGUARD_PYTHON` to an interpreter
with this repository installed:

```sh
node examples/javascript/scan-release.mjs --root dist --policy examples/policy-portable-release.json
```

The command writes a JSON report. Exit 0 means the configured release checks
passed, exit 3 means a completed check found a policy violation, and exit 2 means
the check could not complete. Passing is not proof that REA cannot analyze the
application. Keep the policy outside `dist`.

先把本仓库安装到所选 Python 解释器，并设置 `RELEASEGUARD_PYTHON`，再从仓库根目录
运行上述命令。检查通过返回 0，规则不符返回 3，检查未完成返回 2。策略文件应放在
`dist` 之外；通过检查不代表应用无法被 REA 分析。
