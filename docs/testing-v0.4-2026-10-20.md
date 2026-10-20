# v0.4 runtime-boundary validation — 2026-10-20

This revision adds native memory hygiene and trusted-service request authorization. Functional checks passed within the scope below. It does **not** establish a probability of defeating REA, prevent observation of live client plaintext, or complete a REA agent/provider/model evaluation.

## Local results

Environment: Linux x86-64, Python 3.12.14, cryptography 50.0.2, GCC 13.3.0 and CMake 4.4.4. The [machine-readable record](results/validation-v0.4-2026-10-20.json) includes SQLite and wheel details.

| Check | Observation |
| --- | --- |
| Full unittest discovery | **331 run: 330 passed, 1 skipped, no failures/errors**, 23.597 seconds |
| Native buffer | Real C++17 unoptimized, optimized and LTO builds; both guards fault in isolated children; required locking failure rejects construction; clear/destruction wipe the owned rounded pages before unlocking/releasing |
| Native failure injection | Partial `mprotect`, required `mlock` and required `MADV_DONTDUMP` failures clean up once; tests observe mapped owned memory before release, never freed memory |
| Independent mapping observation | `/proc/self/smaps` unavailable in this host: skipped, not counted as an observed OS mapping flag or a core-dump experiment |
| Real CMake integration | Existing executable/shared-library/C interfaces still pass; the new secure-buffer example is built, gated and included in CTest |
| Capability API and CLI | Real Ed25519 signatures and SQLite state; malformed/schema/domain/time/context/request/encoding inputs rejected; exclusive private outputs and missing/corrupt database failures checked |
| Replay and clock boundaries | Persistent replay rejected after reopening; expired-row purge cannot revive a token through clock rollback; capacity failure does not evict live consumed nonces |
| Independent server fixture | **32 independent store instances: 1 accepted, 31 rejected, 1 handler call** for the same capability; missing/forged capability and request swaps never reach the handler |
| Distribution | v0.4.0 wheel built; capability module, both C++ headers and CMake resource bytes match the source checkout |

The full suite includes 28 capability API tests, 6 capability CLI tests, 10 independent replay regressions, 10 server-benchmark tests, 13 native-buffer tests and 5 Frida-result classification tests, alongside 259 existing tests. The single skip is part of the 13 native-buffer tests. These counts describe implementation verification, not cracking attempts or a security audit.

An additional [independent process/lock probe](../benchmarks/capability_process_boundary.py) ran successfully in 2.157 seconds, separately from the 331 tests. Its [record](results/capability-process-2026-10-20.json) shows **6 spawned processes: 1 authorization, 5 replay refusals, 1 persisted nonce**. A real SQLite write lock held a two-second token until expiry; admission then failed with clock floor and nonce count both still zero. These are owned synthetic fixtures, not a deployed service or REA evaluation.

## Defects found and corrected during review

An initial schema query used SQL `LIKE 'sqlite_%'` to omit internal objects. Its underscore wildcard could hide an unexpected trigger, including one that deleted consumed nonces. Merely changing to a literal-prefix filter also left manually inserted reserved-name objects unchecked. The final validator accepts **exactly the entire expected SQLite schema**, without ignoring names. Independent regressions check both cases and reject them before consumption.

The initial timestamp was sampled before waiting for the database lock. A queued request could otherwise cross its expiry boundary while using the stale sample. The final implementation samples trusted time again inside the serialized transaction, rechecks validity there and then applies its persisted clock floor. A deterministic regression covers expiry during admission. Cleanup errors and SQLite builds without an extension-loading API also fail safely or use the supported disabled-by-default path.

The [first cross-platform CI run](https://github.com/Afloat16/anti-rea-forge/actions/runs/39365423858) passed on Linux/Python 3.10 and 3.13. Windows exposed 24 cleanup errors: test-fixture `with sqlite3.connect(...)` blocks committed transactions without closing their connections, leaving database files locked during temporary-directory removal. Fixture connections and the independent process-probe reads now explicitly close after their transaction context exits. The production replay-store connection manager already closes its connections and was unchanged by this fix. Check the exact subsequent commit in Actions for the final Windows/MSVC result.

## Actual Frida attempt

The [real Frida report](results/frida-buffer-2026-10-20.json) and [reproducer](../benchmarks/frida_buffer_observe.py) use **Frida 17.23.2**, matching the optional dependency in the reviewed REA source. Only a newly compiled, project-owned fixture is accepted; it uses a public synthetic pattern, not a credential.

The GCC `-O2` fixture compiled and its independent uninstrumented control exited 0. Two real instrumentation attempts then failed:

- Spawn returned `NotSupportedError: target exited with status 1`.
- Attach returned `ProcessNotFoundError: unable to find process with pid 27`, although the owned process was alive immediately before attach.

No hook or memory observation completed. The exact underlying OS cause was not established, and no permissions or tracing policy were changed. The outcome is **`environment_or_instrumentation_failure` / `protection_outcome=not_evaluated`**. The five classification tests validate reporting behavior; they are not five successful Frida runs. A successful run of this fixture would be expected to demonstrate that live plaintext is readable, then the same still-owned allocation is zero after clearing. That is a boundary observation, not an anti-Frida pass.

## Reproduce

Install the project and a supported native compiler/CMake, then run from the checkout:

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python benchmarks/dynamic_boundary.py --out dynamic-boundary.json
python benchmarks/capability_process_boundary.py --out capability-process.json
python -m pip wheel . --no-deps --wheel-dir dist
```

The optional Frida experiment needs a separate Frida 17.23.2 installation and compatible permissions. It accepts no external executable, PID or script:

```bash
python -m pip install frida==17.23.2
python benchmarks/frida_buffer_observe.py --out frida-buffer.json
```

Dynamic-boundary exit 0 means its synthetic functional checks passed. Frida-buffer exit 0 means its expected **live-read and post-clear** observations completed; exit 2 means setup/instrumentation failure or an incomplete/contradictory result. Both output paths must be new. Use `RELEASEGUARD_CMAKE` when CMake is outside PATH. Local testing used an absolute `PYTHONPATH` to the checkout's `src` directory for compiler subprocesses.

## Scope and next work

The [server fixture report](results/dynamic-boundary-2026-10-20.json) forces a Python client boolean. It exercises the same server enforcement path regardless of that value, and demonstrates that a valid delegated capability remains usable. It does not run a native branch hook, network authentication, TLS, a deployed authorization service or a TEE. At-most-once authorization consumption is not exactly-once business execution. Database restore/rollback, independent replay replicas and an actively controlled authorized session remain outside this guarantee. Full-store validation is bounded but is not a production-throughput result.

Linux and Windows/MSVC CI must be checked for the **exact published commit** in [Actions](https://github.com/Afloat16/anti-rea-forge/actions); their results are separate from local counts. Windows dump exclusion is not implemented, and Windows DLL ABI/real-application resistance remains untested. Earlier [successful native secret recovery](testing-2026-10-15.zh-CN.md) and [v0.3 results](testing-2026-10-20.md) remain valid negative evidence. The [runtime guide](runtime-protection.md) explains integration and five formal 2024–2026 research sources without claiming to reproduce their systems.
