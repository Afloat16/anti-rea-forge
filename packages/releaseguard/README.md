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

## Configure once, check each build

The v0.6 project workflow stores editable configuration outside the application:

```sh
python -m releaseguard project-init --root dist --product Demo --out .releaseguard
python -m releaseguard check --config .releaseguard/project.json
```

Use the selected virtual-environment interpreter in place of `python` when needed.
Review `.releaseguard/policy.json` for your release. The release directory can be
built after initialization; checks require it to contain files. In a Node build
script the same check becomes:

```js
const report = await guard.checkProject({ config: ".releaseguard/project.json" });
process.exitCode = report.exitCode;
```

Run these checks in the build/release process. The workflow does not add imports,
runtime hooks, startup scans or background work to the protected application.
Scanning and hashing still cost time in the build or analysis service.

## Require authorization before an analysis tool runs

For a **cooperating, trusted analysis gateway**, `withAnalysisAuthorization()`
checks a signed, scoped grant and the exact signed release before invoking one
handler. Missing authorization stops the handler in ordinary code; it does not
depend on a language model deciding to obey a notice.

```js
// These values belong to trusted service configuration and an authenticated
// session. The model and analyzed target must not choose them.
const expected = Object.freeze({
  manifest: "/srv/releases/demo-1.0-evidence/manifest.json",
  root: "/srv/releases/demo-1.0",
  publicKey: "/srv/trust/demo-issuer.pem",
  product: "Demo",
  release: "1.0",
  subject: authenticatedSession.subject,
  audience: "internal-analysis-gateway",
  operation: "inspect",
  grant: submittedGrantPath,
});

const result = await guard.withAnalysisAuthorization(expected, async (verified) => {
  // The service fixes this handler-to-scope mapping and uses the SAME captured
  // configuration. Keep the entire release immutable until the tool finishes.
  return analysisTools.inspect(expected.root);
});
```

`authenticatedSession`, `submittedGrantPath` and `analysisTools` above are
application-provided service objects. A standalone operator-run example that
protects a fixed directory-listing tool is in
[authorized-analysis.mjs](../../examples/javascript/authorized-analysis.mjs);
its [setup guide](../../examples/javascript/README.md) includes grant issuance.

The three scopes are `inspect`, `decompile` and `instrument`; none implies another.
Every call verifies afresh, with no positive-result cache. A denied decision
throws `AUTHORIZATION_DENIED`. A worker/protocol error or cancellation before
admission also leaves the handler uncalled. An allowed handler runs once and its
result or exception propagates without a retry.

Python checks time before and after hashing. The wrapper additionally checks the
verified `validity.not_before` / `validity.expires_at` interval using the trusted
gateway's `Date.now()` immediately before callback admission. A delayed verifier
allow cannot admit work after expiry or before validity starts. Both clocks must
be trusted. Verification and callback execution remain separate operations; this
does not provide an atomic handoff or interrupt a handler already running when a
grant expires. The service owns cancellation, effects and any execution-time lease.

The handler must use the captured, immutable configuration and the same release
that was verified. The wrapper cannot inspect or rewrite tool arguments chosen
inside the handler; passing a different target inside the callback bypasses the
intended integration.

`checkAnalysis()` exposes the verifier's read-only decision for integrations that
already implement their own dispatch. A returned report alone does not stop a
tool. All tool paths must be mediated by the trusted gateway; an unmediated REA,
shell or filesystem tool can bypass this integration. This SDK does not modify
REA, control another person's agent, or make artifact text a system instruction.

The issuer key must be pinned through a trusted channel, the subject obtained
from authenticated context, and the operation fixed by the tool mapping. Grants
are reusable within their validity period (default one hour, maximum 24 hours),
have no online revocation check, and do not authenticate the analyst themselves.
The service owns those controls. A signature binds content to the pinned issuer;
it does not establish legal ownership or permissions beyond this workflow.

## API

`createReleaseGuard(options?)` returns eight asynchronous methods:

| Method | Required options | Optional options | Python command |
| --- | --- | --- | --- |
| `scanRelease(options, controls?)` | `root`, `policy` | — | `scan-release` |
| `checkProject(options, controls?)` | `config` | — | `check` |
| `checkAnalysis(options, controls?)` | `manifest`, `root`, `publicKey`, `product`, `release`, `subject`, `audience`, `operation` | `grant` | `analysis-check` |
| `withAnalysisAuthorization(options, handler, controls?)` | Same options as `checkAnalysis`, plus a callback | `grant` | `analysis-check`, then one callback if allowed |
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
policy failures from `scanRelease`, `checkProject`, `gate`, or strict `audit` return
`ok: false` and `exitCode: 3`; they do not throw. A non-strict PE audit can have
`ok: true` and `policy_passed: false`, so use `{ strict: true }` to enforce its
warnings as failures. `checkAnalysis` returns a discriminated allow/deny report:
`authorized: true`, `decision: "allow"`, `reason: "authorized"`, `exitCode: 0`, or
`authorized: false`, `decision: "deny"`, one documented denial reason, `exitCode: 3`.
Its mandatory `validity` is null until the grant signature/schema are verified,
then an immutable object containing exact UTC `not_before` and `expires_at`.
The interval is bounded to 1..86400 seconds. `withAnalysisAuthorization` turns a
denial or a failed gateway time recheck into an exception before the callback.

For manifest/license methods, invalid signatures are CLI errors. Analysis grant
signature, scope, time or release-integrity failures are explicit denied
decisions. Missing/unreadable files, malformed CLI inputs, invalid policies and
other incomplete checks throw
`ReleaseGuardError` with `code: "CLI_ERROR"` and the Python `exitCode` (normally
2). Verification methods never return a successful result for these failures.
The bridge also rejects malformed, duplicate-key, incomplete or contradictory
reports, unexpected diagnostic output, and output that exceeds its budget.

| Error code | Meaning |
| --- | --- |
| `INVALID_ARGUMENT` | Unsupported option or invalid local argument |
| `AUTHORIZATION_DENIED` | Authorization refused or is no longer current; the protected callback was not called |
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

The check methods provide local read-only inspection. The authorization wrapper
additionally invokes only the handler supplied by the trusted service after a
successful check; it does not select or launch an arbitrary command. The SDK
does not expose key generation, signing, password input or capability-consumption
methods. Manifest/license verification requires a previously trusted public key
and trusted expected product/version/subject values. A local verifier can be
patched by someone controlling its runtime; keep final authorization in the
appropriate trusted service. Passing a release policy is not an REA resistance
score. The Python [security model](../../SECURITY.md) still applies.

## Contribute

Edit the plain JavaScript files in `src/`, keep `index.d.ts` consistent, and run
`npm test`. Process tests use controlled Node.js child fixtures; integration
tests exercise the installed Python CLI, signature verification, rejection
behavior, callback admission and module-shadowing isolation. Authorization tests
cover rejection, delayed admission after expiry, cancellation, immutable context
and child spawn failures without stdio. `test/types-smoke.ts` is a declaration
fixture for TypeScript checks. Feature work should preserve the shared Python
implementation and the distinction between a completed policy rejection and an
incomplete check.
