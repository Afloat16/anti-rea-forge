# v0.6 validation — 2026-11-05

## Scope

This version adds build-only project preparation and explicit authorization for
cooperating analysis handlers. It does not evaluate a third-party model's refusal
rate or claim a completed REA/provider/host resistance result. The REA review is
pinned to `92f332652d352e60b550567adf2399d83d8ebe78`; the project baseline is
`32c7fefd6ae492d86de391875512c6d4870866dd` (v0.5 / PR #2).

## Local checks completed before the execution environment disconnected

| Check | Observed result |
| --- | --- |
| Python full suite at the pre-final revision | 428 run, 427 passed, 1 skipped in 136.127 s |
| Skip | `/proc/self/smaps` unavailable on the local host |
| Python environment | Python 3.12.14, cryptography 50.0.2, GCC 13, CMake 4.4.4 |
| JavaScript unit/process tests at the pre-final revision | 59 passed |
| Real Python bridge integration | 8 passed as a suite; the added standalone example passed separately (1 test) |
| TypeScript declarations | TypeScript 5.9.3, strict NodeNext, passed |
| Independent signed-authorization controls | 10 expected allow/deny cases passed |
| Synthetic build-only observation | All 10 controls passed; target bytes, size, mtime and mode were unchanged |

The final local host became unavailable. Files were recovered from the completed
edit contents and GitHub's fixed base through the Git Data API. **The local
counts do not validate the reconstructed final tree.** Additional changes include
root-link rejection tests, authenticated validity metadata, an immediate JS clock
check before the handler and failed-spawn handling without stdio. Their complete
validation is the final GitHub Actions run recorded in the pull request.

No skipped local native inspection is represented as a passing memory-hardening
result. No local TypeScript 7 result is claimed; its pinned 7.0.2 check runs in CI.

## Required final remote checks

The existing CI runs the actual committed files on:

- Ubuntu, Python 3.10 and 3.13, including native/CMake regression and wheel build.
- Windows, Python 3.12, including MSVC component tests and example build.
- JavaScript/real Python integration on Ubuntu Node 22, Windows Node 24 and macOS Node 24.
- TypeScript 7.0.2 strict declaration checking on the Linux JS job.
- The new authorization/build-only tests and synthetic observation.

The pull request records the exact successful commit and run URL after completion.
Workflow artifacts named `analysis-boundary-<os>-<python>` retain synthetic
observations only; no private keys or grants are uploaded.

## What the tests establish

New controls cover actual Ed25519 signatures, independent scopes, manifest/context
binding, no-grant/forged/expired/wrong-key denials, strict bounded formats, complete
release rehashing, no allow cache, hash-time expiry, and no target execution.
Project checks exercise cwd-independent config, fresh outputs, scan/sign identity,
failure before publication and unchanged application files. SDK checks require
zero callback calls on denied/error/cancelled/expired paths and one call on allow,
without retrying handler errors. Resource-exhaustion spawn failures retain a
classified error.

Independent review found and corrected two onboarding defects: project identifiers
could pass setup but fail grant issuance, and resolving a release-root symlink
could silently pin an old version. The new workflow validates identifiers early
and rejects linked roots.

## Performance observation and limits

The [recorded synthetic run](results/analysis-boundary-2026-11-05.json) used two
files totaling 4,194,469 bytes (a 4 MiB payload plus a synthetic script), with three
preflight repetitions. On that host, the scan took about 42.81 ms, scan-plus-sign
preparation about 43.02 ms, allowed preflight median 6.69 ms and missing-grant
preflight median 0.60 ms. These are local pre-final observations, not promised
throughput or a final-revision application benchmark.

No application workload was executed. Unchanged hashes and metadata support
“the workflow does not rewrite the application,” not a universal speed guarantee.
Build/gateway work still consumes CPU and I/O. The gateway must control its actual
handler, caller identity, trusted key and immutable snapshot; direct tool calls,
later file replacement, online revocation and legal ownership are outside this
implementation. Expiry prevents new admission, not termination of a running handler.

## First remote run and fixture correction

[Run 41992566631](https://github.com/Afloat16/anti-rea-forge/actions/runs/41992566631) tested the reconstructed tree. All three JS unit/process and real Python integration steps passed, as did TypeScript 7.0.2 on Linux. The macOS and Windows portable subsets exposed one test expectation comparing an unresolved temporary path with the scanner's resolved path. macOS `/var` and Windows short path names refer to the same canonical directories. The follow-up resolves the expected path in that assertion, retaining the moved-project check and leaving scanner behavior unchanged. This initial run is not recorded as a successful full matrix.
