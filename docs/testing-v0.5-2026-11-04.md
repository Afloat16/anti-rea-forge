# v0.5 validation — 2026-11-04

This report records implementation checks for portable release inspection and the
JavaScript/TypeScript bridge. It does **not** record an end-to-end REA attack, a new
decompilation benchmark or a cracking-resistance success rate. The historical successful
recoveries remain in the repository.

## Scope and environment

The change starts from Anti-REA Forge commit
`91c07c52250bc8bfa18796cb351f105e8edb5865`. The upstream review pins REA source commit
`89317a39fab23df81efa4331311d09d2110377bd` (source package version 6.8.0); REA itself was
read as source, not executed as an agent/provider/model pipeline during this validation.

| Component | Local version / setting |
| --- | --- |
| Python | 3.12.14, installed checkout in a virtual environment |
| Cryptography | 50.0.2 |
| Node.js | 24.22.1 |
| GCC/G++ | 13.3.0, Linux |
| CMake / CTest | 4.4.4; executable selected with `RELEASEGUARD_CMAKE` |
| TypeScript declaration check | 5.9.3 JavaScript compiler |
| Package under test | `open-release-guard` 0.5.0; local JS workspace package 0.5.0 |

## Results

| Check actually executed | Result |
| --- | --- |
| Existing Python/native suite before the implementation changes | **331 run: 330 passed, 1 skipped** |
| Complete Python/native suite with v0.5 | **377 run: 376 passed, 1 skipped** |
| Portable scanner and CLI tests, included in the preceding total | **46 passed**, no skips: 39 scanner regressions and 7 CLI integration tests |
| JavaScript unit/process-boundary tests | **44 passed**, no skips |
| JavaScript integration against the installed Python CLI | **5 passed**, no skips |
| Independent malformed ZIP controls, separate from test counts | **4/4 rejected** after review and fixes |
| TypeScript declarations and negative type examples | **Passed** using TypeScript 5.9.3 with strict NodeNext settings |
| Python wheel | Built, installed into a second environment and exercised successfully |
| npm package dry run | Passed; 10 packaged files, including declarations and MIT license; no registry publication |
| CI configuration | YAML parsed; existing Python matrix retained and three JS integration jobs added |

The sole Python skip is
`test_live_flags_independently_match_linux_smaps`: this host does not provide
`/proc/self/smaps`. The native allocation, lock, wipe, guard-page and other existing tests
still ran. The skip is an environment limit, not a protection pass.

TypeScript 7.0.2 was also attempted locally. Its native compiler could not start because
the host lacks `/proc/self/exe` (`vfs: failed to get executable path`). The JavaScript-based
5.9.3 compiler completed the declaration check. CI includes a pinned TypeScript 7.0.2
check on its Linux runner; this local report does not claim that CI result in advance.

### CI follow-up

The first CI run on commit `3cdd3e2e35507d681d629afc72e1c538dbfa59ad` passed both Linux
Python jobs, the Linux/macOS JavaScript jobs, and the TypeScript 7.0.2 declaration step.
Windows exposed a test-fixture problem: its ZIP writer normalized a requested backslash
name into a safe slash-separated name before writing the archive, so that particular
negative test did not contain the intended malformed input.

The regression now writes the same literal backslash bytes into both local and central
ZIP headers on every platform and verifies those bytes before scanning. The scanner's
existing original-name validation is retained; the check is not disabled or skipped.
The 46 portable/CLI tests were rerun locally after the fixture correction. The subsequent
exact-commit CI results remain available from [PR #2](https://github.com/Afloat16/anti-rea-forge/pull/2/checks).

## Commands

Run from the repository root after installing the Python core into `.venv`:

```bash
RELEASEGUARD_CMAKE=/path/to/cmake .venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m unittest tests.test_distribution tests.test_distribution_cli -v
npm test --prefix packages/releaseguard
RELEASEGUARD_PYTHON=/absolute/path/to/.venv/bin/python npm run test:integration --prefix packages/releaseguard
tsc --noEmit --strict --module NodeNext --moduleResolution NodeNext --target ES2022 packages/releaseguard/test/types-smoke.ts
.venv/bin/python -m pip wheel . --no-deps --no-build-isolation --wheel-dir ../package-validation
npm pack --dry-run --json ./packages/releaseguard
```

The actual wheel and npm checks used their respective package directories. The
TypeScript command used an explicitly installed 5.9.3 compiler in a temporary tool
directory; there is no compiler or npm runtime dependency added to the JS SDK.

## Security-relevant regression coverage

The portable checks exercised ordinary JS/Python files without a native artifact;
literal matches in five encodings and across read boundaries; PEM/source-map markers;
no matched-content echo; exact inventories; paths, extensions and denied hashes;
file replacement/growth; links/FIFOs; empty releases; and strict policy parsing.

Archive controls covered renamed and nested ZIPs, expansion/entry/depth budgets,
central-directory allocation bounds, malformed DEFLATE, CRC and size disagreement,
duplicate and colliding paths, traversal, unsupported encryption/compression, ZIP64,
data descriptors and deliberately unscanned archives.

Independent review found and fixed four additional boundary problems before this
version was submitted:

| Synthetic control | Required result and observed outcome |
| --- | --- |
| Two concatenated ZIPs; the first contains a compressed synthetic PEM marker | Reject the prefixed/concatenated layout instead of scanning only the final ZIP — rejected |
| A directory entry with compressed content and a forged zero expanded length | Validate actual bounded output even for a directory — rejected |
| Unicode Path extra mapping an apparently public path to `.env` | Reject the alternate-path field consistently, including on Python versions that ignore it — rejected |
| A central-directory member claiming a nonzero disk number | Reject the multi-disk member — rejected |

The scanner verifies local and central metadata, actual bounded expansion, CRC, stream
completion, descriptors and contiguous member boundaries. It deliberately rejects SFX
prefixes, concatenated archives, unused inter-member data and Unicode Path override
fields. These are explicit support restrictions, not assertions that every valid ZIP
variant is accepted.

The JavaScript tests exercised separated arguments, option-like values, whitespace and
shell metacharacters, invalid/duplicate JSON fields, malformed UTF-8, report/exit-code
contradictions, bad inputs, spawning failures, cancellation, output caps, timeouts and
abnormal worker termination. Integration tests used real clean/blocked scans, invalid
policies, signed manifests/licenses, wrong trusted context and changed release bytes.
An untrusted `releaseguard.py` in both cwd and `PYTHONPATH` did not run under `-I`.

## Package checks

The tested wheel's `releaseguard/distribution.py`, `releaseguard/cli.py` and native
`secure_buffer.hpp` matched the checkout byte-for-byte. Its metadata reported 0.5.0.
After installing the wheel into a second virtual environment:

- A clean synthetic JS release returned exit 0.
- Adding a compressed source map under a non-`.map` member name returned exit 3 with
  `source_map_marker`.
- The runnable JavaScript example used that installed wheel and also returned exit 3.

[Machine-readable observations](results/validation-v0.5-2026-11-04.json) include the
tested source hashes, wheel hash, counts and scope flags. Build timestamps can change a
wheel hash; the record describes the tested artifact, not a reproducible-build claim.

## Limits and CI

Local execution covered Linux/Python 3.12/Node 24. Windows, macOS, Python 3.10/3.13 and
Node 22 are covered by configured CI jobs, not by the local counts above. The actual
[Actions results](https://github.com/Afloat16/anti-rea-forge/actions) for the PR commit
are separate evidence. Windows DLL ABI, real customer applications and adversarial
parent-directory races remain outside this validation.

Only recognized stored/deflated ZIP containers are expanded. Detected unsupported
archives block release; unknown/proprietary containers can still contain encoded data
outside the heuristic scan's understanding. Deployment-time HTTP source-map headers,
remote/CDN content and arbitrary secret formats are not covered. See the
[integration guide](portable-release.md) and [source review](rea-source-review-2026-11-04.zh-CN.md).

Passing these checks does not establish confidentiality of shipped code, runtime
plaintext protection against hooks, or trustworthy authorization in a modified client.
