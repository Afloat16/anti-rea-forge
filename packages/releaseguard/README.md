# Release Guard for JavaScript and TypeScript

[简体中文](README.zh-CN.md)

A small, dependency-free Node.js bridge to Anti-REA Forge's Python CLI. Write
ordinary JavaScript, use the included TypeScript declarations, and run the same
release checks and verification code used by the Python tools. There is no
JavaScript build step and no second cryptographic implementation to maintain.

**Node.js 22+ and Python 3.10+ are required.** Install this repository's Python
package into the interpreter you select. Use the matching **1.3.0 SDK and Python core**.
The SDK is distributed as an installable **GitHub Release archive** and as a local
workspace package. It remains marked private to prevent accidental npm publication;
no npm registry release is claimed.

```sh
npm install https://github.com/Afloat16/anti-rea-forge/releases/download/v1.3.0/anti-rea-forge-releaseguard-1.3.0.tgz
```

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

The project workflow, introduced in v0.6, stores editable configuration outside the application:

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
| `scanRelease(options, controls?)` | `root`, `policy` | `assetKeyFiles`, `privateInputFiles` | `scan-release` |
| `checkProject(options, controls?)` | `config` | `assetKeyFiles`, `privateInputFiles` | `check` |
| `checkAnalysis(options, controls?)` | `manifest`, `root`, `publicKey`, `product`, `release`, `subject`, `audience`, `operation` | `grant` | `analysis-check` |
| `withAnalysisAuthorization(options, handler, controls?)` | Same options as `checkAnalysis`, plus a callback | `grant` | `analysis-check`, then one callback if allowed |
| `audit(path, options?)` | PE file path | `strict`, `signal` | `audit` |
| `gate(options, controls?)` | `artifact`, `policy` | `root` | `gate` |
| `verifyManifest(options, controls?)` | `manifest`, `root`, `publicKey`, `product` | `release` | `manifest-verify` |
| `verifyLicense(options, controls?)` | `license`, `publicKey`, `product` | `subject`, `requiredFeatures` | `license-verify` |

`controls` accepts an `AbortSignal`, for example
`guard.scanRelease({ root, policy }, { signal: controller.signal })`.

`assetKeyFiles` is an optional array of at most 16 paths to external raw 32-byte
asset/code keys. Both calls forward them as separate `--asset-key-file` arguments;
they never accept inline key material. `checkProject` adds these paths to any
`asset_key_files` saved in `project.json`, with the same combined limit of 16.
An empty array does not disable configured keys. The Python core checks known raw,
hex and Base64 key representations in loose files and supported ZIP/ASAR members;
matched bytes are not returned. Missing/invalid key files are errors.

```javascript
const report = await guard.scanRelease({
  root: "dist", policy: "release-policy.json", assetKeyFiles: ["../issuer/asset.key"],
});
```
TypeScript consumers receive declarations from [index.d.ts](index.d.ts), including
the report fields and error codes.

### Private implementation references in 1.3

`privateInputFiles` accepts at most **64 external, nonempty regular files**, limited
to **8 MiB each and 64 MiB total**. Python rejects directories, globs, linked files
or ancestors, and Windows reparse points. The SDK sends separate
`--private-input-file` path arguments; it does not accept inline private contents.

```javascript
const report = await guard.scanRelease({
  root: "dist",
  policy: "release-policy.json",
  privateInputFiles: ["../service/private_quote.py", "../service/model.dat"],
  assetKeyFiles: ["../issuer/asset.key"],
});
if (!report.ok) process.exitCode = report.exitCode;
```

To require the same references on every project check, add the build-only field
to `.releaseguard/project.json`:

```json
{
  "version": 1,
  "product": "Demo",
  "root": "../dist",
  "policy": "policy.json",
  "private_input_files": ["../../service/private_quote.py"]
}
```

Configuration paths resolve relative to `project.json`. `checkProject` adds optional
`privateInputFiles` to the configured references; omitting the option or passing `[]`
does not clear them. The combined limits apply. Each scan reads the current reference
bytes and rechecks their identity and hash before completion. Missing, replaced or
modified references fail the operation. `checks.private_inputs_checked` records the
count, and a public copy yields `private_input_exposure` with its `rule_index`.

The rule matches **exact whole-file SHA-256 copies**, including renamed physical
files and inspected ZIP/ASAR members and verified unpacked siblings. It does not detect
rewritten, compiled, concatenated or fragmented versions; even an appended newline
changes the digest. Reference paths and separate reference digests are omitted from
reports, while public file/member names and public inventory hashes remain visible.
The [private-service example](../../examples/private_service/README.md) and real REA
[npm](../../docs/results/private-input-controls-v1.3.0-rea-6.9.0.json) /
[source](../../docs/results/private-input-controls-v1.3.0-rea-source.json) controls show
the intended separation and deliberately republished-copy test.

The equivalent CLI option works on `scan-release`, `check` and `prepare`; the Python
keyword is `private_input_files`. `prepare` retains reference snapshots across signing
and output creation, rechecks them after writing sidecars, and removes a new output
bundle on final verification failure. Signing remains a Python CLI/API workflow, not
an SDK method. Keep references, release files and their ancestors under trusted build
control throughout the operation; these checks are not an atomic filesystem snapshot.

### New scan profiles and completion fields

With configured `assetKeyFiles`, the core applies the independent
`canonical-marshal-integer/v1` PYC profile even if `check_private_keys` or
`check_native_metadata` is disabled. It searches canonical signed/unsigned,
big/little-endian integer representations of the known 32-byte keys without
unmarshalling or executing the inspected bytecode. Supported stable CPython 3.7–3.14
headers, a 64 MiB payload ceiling and the 16-key limit bound this check. Every
configured key interpretation needs at least 128 significant bits; short aliases,
unsupported headers and budget failures produce incomplete inspection.

| Report field | Interpretation |
| --- | --- |
| `pyc_asset_keys_checked` | Known external keys enabled the profile |
| `pyc_asset_key_files_checked` | PYC candidates inspected, including unsupported candidates and inspected archive members |
| `pyc_asset_key_scan_completed` | Completion of this exact-pattern profile; not validation of the full marshal body |
| `pyc_asset_key_profile` | `canonical-marshal-integer/v1`, or `null` without configured keys |

These fields are separate from JSON/DER's `structured_secret_scan_completed`.
A known-key match is `asset_key_exposure` with
`representation: "python-marshal-integer"`; an unsupported profile is
`structured_secret_unverifiable` / `invalid_or_unsupported_pyc_key_profile`.
Use the enabled flag and candidate count when interpreting completion. Unknown keys,
computed/split/noncanonical constants and program logic are outside this profile.
The [PYC guide](../../docs/python-pyc-key-profile.md) documents the exact boundaries.

`check_private_keys: true` also checks **one** hex/Base64 wrapper around private PEM
headers in JSON strings, including supported leading notes and Node-compatible
Base64 forms. PEM and DER wrappers share **64 candidates and 256 KiB decoded bytes
per JSON document**; each recognized candidate is limited to **256 Ki characters of
raw text and 64 KiB decoded bytes**, within the existing JSON structure limits.
Confirmed private headers produce `private_key_marker` with `json-hex-pem` or
`json-base64-pem`; recognized invalid/over-budget candidates produce
`structured_secret_unverifiable` and a false structured completion flag. This does
not recursively decode arbitrary wrappers or prove that every marked key is valid.
Public-key PEM and certificates are allowed by this private-key rule.

Native scans separately report exact embedded LLVM sections as
`native_compiler_metadata`. The PE/ELF `gate` policy defaults
`require_no_compiler_metadata` to `true`; intentional compiler-data distribution
requires explicitly setting it to `false`, without disabling other requirements.
That native-only field cannot be passed in a portable policy; `scanRelease` uses
the broader `check_native_metadata` switch. Raw/wrapped standalone LLVM bitcode is
recognized but unsupported (`native_metadata_unverifiable`,
`native_metadata_scan_completed: false`), including renamed archive members.
Legitimate JIT applications may require such IR, and an opt-out does not conceal it.
Eligible ordinary Linux ELF compiler records can be separated with
[split-elf-debug](../../docs/private-elf-debug.md); PE/Mach-O records are detected
without automatic rewriting. See the [portable guide](../../docs/portable-release.md)
for exact section names, budgets and scan-to-sign usage.

### Client options

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
