# Release Guard for JavaScript and TypeScript

[简体中文](README.zh-CN.md)

A small, dependency-free Node.js bridge to Anti-REA Forge's Python CLI. Write
ordinary JavaScript, use the included TypeScript declarations, and run the same
release checks and verification code used by the Python tools. There is no
JavaScript build step and no second cryptographic implementation to maintain.

**Node.js 22+ and Python 3.10+ are required.** Install this repository's Python
package into the interpreter you select. This package is currently a **local,
private workspace package**; the project does not claim an npm registry release.

## Install and run

From the Anti-REA Forge repository root, on Linux/macOS:

```sh
python -m venv .venv
.venv/bin/python -m pip install -e .
export RELEASEGUARD_PYTHON="$(pwd)/.venv/bin/python"
npm --prefix packages/releaseguard test
npm --prefix packages/releaseguard run test:integration
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
$env:RELEASEGUARD_PYTHON = (Resolve-Path .venv\Scripts\python.exe).Path
npm --prefix packages/releaseguard test
npm --prefix packages/releaseguard run test:integration
```

The JavaScript unit tests do not require Python or `npm install`. Integration
tests require the installed Python core. No npm dependencies are needed for
either test command.

Use the package in another local Node.js project:

```sh
npm install /absolute/path/to/anti-rea-forge/packages/releaseguard
```

The resulting dependency can use a local file reference:

```json
{
  "dependencies": {
    "@anti-rea-forge/releaseguard": "file:../anti-rea-forge/packages/releaseguard"
  }
}
```

```js
import { createReleaseGuard, ReleaseGuardError } from "@anti-rea-forge/releaseguard";

const guard = createReleaseGuard({
  python: process.env.RELEASEGUARD_PYTHON,
  timeoutMs: 30_000,
});

try {
  const report = await guard.scanRelease({
    root: "dist",
    policy: "release-policy.json",
  });
  console.log(JSON.stringify(report, null, 2));
  process.exitCode = report.exitCode; // 0: passed; 3: a configured rule failed.
} catch (error) {
  if (!(error instanceof ReleaseGuardError)) throw error;
  console.error(`${error.code}: ${error.message}`);
  process.exitCode = 2;
}
```

Start with the repository's [portable policy example](../../examples/policy-portable-release.json)
and review its rules for your release. Keep the policy outside the scanned
directory. From this repository, the [runnable example](../../examples/javascript/scan-release.mjs)
can use the bridge directly, without installing the local npm package:

```sh
node examples/javascript/scan-release.mjs --root dist --policy examples/policy-portable-release.json
```

## API

`createReleaseGuard(options?)` returns five asynchronous methods:

| Method | Required options | Optional options | Python command |
| --- | --- | --- | --- |
| `scanRelease(options, controls?)` | `root`, `policy` | — | `scan-release` |
| `audit(path, options?)` | PE file path | `strict`, `signal` | `audit` |
| `gate(options, controls?)` | `artifact`, `policy` | `root` | `gate` |
| `verifyManifest(options, controls?)` | `manifest`, `root`, `publicKey`, `product` | `release` | `manifest-verify` |
| `verifyLicense(options, controls?)` | `license`, `publicKey`, `product` | `subject`, `requiredFeatures` | `license-verify` |

`controls` accepts an `AbortSignal`, for example
`guard.scanRelease({ root, policy }, { signal: controller.signal })`.
TypeScript consumers receive declarations from [index.d.ts](index.d.ts), including
the report fields and error codes.

Client options:

| Option | Default | Accepted values |
| --- | --- | --- |
| `python` | `RELEASEGUARD_PYTHON`, then `python` | One executable path/name; never a shell command with arguments |
| `timeoutMs` | `30000` | Integer `1..600000` |
| `maxOutputBytes` | `4194304` | Integer `1024..16777216`; stdout and stderr combined |

Prefer an absolute interpreter path. Relative file arguments are resolved when
the method is called. Unknown option names, invalid feature identifiers and
invalid controls are rejected before starting Python.

## Results and errors

Successful checks return the Python JSON report plus `exitCode: 0`. Configured
policy failures from `scanRelease`, `gate`, or strict `audit` return
`ok: false` and `exitCode: 3`; they do not throw. A non-strict PE audit can have
`ok: true` and `policy_passed: false`, so use `{ strict: true }` to enforce its
warnings as failures.

Invalid signatures, missing files, invalid policies and other CLI errors throw
`ReleaseGuardError` with `code: "CLI_ERROR"` and the Python `exitCode` (normally
2). Verification methods never return a successful result for these failures.
The bridge also rejects malformed, duplicate-key, incomplete or contradictory
reports, unexpected diagnostic output, and output that exceeds its budget.

| Error code | Meaning |
| --- | --- |
| `INVALID_ARGUMENT` | Unsupported option or invalid local argument |
| `SPAWN_FAILED` | The selected interpreter could not be started |
| `CLI_ERROR` | Python reported an error; inspect `exitCode` |
| `PROTOCOL_ERROR` | Invalid UTF-8/JSON or an inconsistent report |
| `OUTPUT_LIMIT` | Combined stdout/stderr exceeded the configured byte limit |
| `TIMEOUT` | The command exceeded its time limit |
| `ABORTED` | The caller cancelled the operation |
| `PROCESS_ERROR` | The worker or its output stream failed unexpectedly |

For a `CLI_ERROR`, bounded child output is available through
`error.diagnostic`. This property is non-enumerable and is not appended to the
message; inspect it deliberately because diagnostics can contain local paths.
The bridge terminates its Python worker on cancellation, timeout, or excess
output. Increasing a limit changes the resource budget; it does not change the
scan policy.

## Trust and integration boundaries

Each invocation uses `spawn` with `shell: false`, closed stdin, separate
arguments, and `python -I -m releaseguard`. Python's isolated mode excludes the
current directory and `PYTHONPATH` from module lookup. Install the core into the
selected interpreter; setting only `PYTHONPATH=src` will not work. Interpreter
selection, installed packages and the inherited process environment must remain
under trusted build/service control.

The API provides local read-only checks. It does not run inspected application
code or expose key generation, signing, password input or capability-consumption
methods. Manifest/license verification requires a previously trusted public key
and trusted expected product/version/subject values. A local verifier can be
patched by someone controlling its runtime; keep final authorization in the
appropriate trusted service. Passing a release policy is not an REA resistance
score. The Python [security model](../../SECURITY.md) still applies.

## Contribute

Edit the plain JavaScript files in `src/`, keep `index.d.ts` consistent, and run
`npm test`. Process tests use controlled Node.js child fixtures; integration
tests exercise the installed Python CLI, signature verification, rejection
behavior and module-shadowing isolation. `test/types-smoke.ts` is a declaration
fixture for TypeScript checks. Feature work should preserve the shared Python
implementation and the distinction between a completed policy rejection and an
incomplete check.
