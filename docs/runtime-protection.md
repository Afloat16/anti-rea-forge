# Runtime boundaries in v0.4.0

[English](runtime-protection.md) · [简体中文](runtime-protection.zh-CN.md)

Anti-REA Forge adds two explicit integration components: a C++17 allocation that reduces avoidable secret exposure, and short-lived, request-bound authorization that a trusted service consumes once. Neither makes an attacker-controlled client confidential. A debugger, injected script or hook that can observe an authorized operation may still obtain its inputs and outputs.

The Python distribution remains `open-release-guard`; the CLI and import package remain `releaseguard`. These components do not deploy authentication, TLS, an authorization server, a TEE or a native asset-decryption SDK. See the [cryptographic integration guide](crypto-protection.md) for password verifiers, sealed assets and release gates, and the [security policy](../SECURITY.md) for the wider trust boundary.

## What the inspected REA source can do

The reviewed tree is commit [`d72021b0dabedcc6fbc7bc6e0286fd359c604271`](https://github.com/morluto/rea/tree/d72021b0dabedcc6fbc7bc6e0286fd359c604271). Its [`package.json`](https://github.com/morluto/rea/blob/d72021b0dabedcc6fbc7bc6e0286fd359c604271/package.json) declares source package version **6.7.0** and optional dependency **Frida 17.23.2**. This identifies source dependencies, not a verified npm publication or a completed REA attack against this revision.

The fixed [tool contracts](https://github.com/morluto/rea/blob/d72021b0dabedcc6fbc7bc6e0286fd359c604271/src/contracts/fridaToolContracts.ts), [instrumentation manager](https://github.com/morluto/rea/blob/d72021b0dabedcc6fbc7bc6e0286fd359c604271/src/frida/FridaInstrumentationManager.ts), [tool registration](https://github.com/morluto/rea/blob/d72021b0dabedcc6fbc7bc6e0286fd359c604271/src/server/registerFridaTools.ts) and [Frida guide](https://github.com/morluto/rea/blob/d72021b0dabedcc6fbc7bc6e0286fd359c604271/docs/frida-instrumentation.md) expose attach and spawn sessions, caller-supplied scripts and captured script messages. A spawned process can remain paused while a script is loaded, before resuming execution. Script paths refer to scripts read by the tool; loading a script is not a restriction to passive observation. Frida's official [JavaScript API](https://frida.re/docs/javascript-api/#interceptor) includes memory access and function interception/replacement.

Those operations still depend on the optional binding, platform policy, target permissions and architecture. REA's one-shot instrumentation timeout and message-capture budget do not limit what an injected script can read. Its persistent sessions are a separate lifecycle. A provider/model error, permission denial, timeout, truncation or cleanup failure leaves the experiment blocked or incomplete; it does not establish protection. Static Ghidra byte reads and the passive JavaScript runtime provider should not be described as a successful native runtime dump.

| Threat | Relevant integration | Remaining boundary |
| --- | --- | --- |
| Attach to a running process or instrument a spawned process before its main code | Keep sensitive work and issuer keys outside the client; reduce unnecessary local secret lifetime | Page guards and local debugger detection do not exclude a script executing with the target's authority |
| Read an injected script, hook a function, inspect or replace a comparison | Do not distribute reusable issuer secrets; authorize the real operation on the server | Literal masking, local verifier checks and local public-key pinning can be patched in a controlled client |
| Change a local “authorized” branch or forge the client's success response | The trusted service verifies its own authenticated context and performs the protected operation itself | A local check cannot force a remote service decision; an entirely offline feature remains patchable |
| Reuse a valid signed token | Bind the exact request and context, bound its lifetime, then atomically record consumption in persistent server state | A stolen valid bearer token can still be consumed first for its original request |
| Capture an ordinary core dump or leave an unused secret in an owned native buffer | Check locking/dump status and explicitly clear a narrowly scoped `secure_buffer` | Dump exclusion does not block in-process hooks, arbitrary debugger reads, host snapshots or copies elsewhere |
| Observe plaintext while a legitimate function uses it | Minimize its lifetime; return only the necessary result from a controlled service | Data legitimately present in an attacker-controlled process is not made unobservable by these APIs |

## 1. Own and clear a bounded native allocation

The standalone header is [`releaseguard/secure_buffer.hpp`](../src/releaseguard/data/include/releaseguard/secure_buffer.hpp). It requires C++17 and supports Linux and Windows. The existing CMake integration supplies the packaged include directory; `native-init` also copies the header into its generated `include` directory. A build seed is not required for this class. The [native build guide (Chinese)](native-build.zh-CN.md) covers the existing CMake interface.

```cpp
#include <releaseguard/secure_buffer.hpp>

// Application-defined functions: neither should retain a copy or log the secret.
void fill_secret(unsigned char* output, std::size_t size);
void use_secret(const unsigned char* input, std::size_t size);

void handle_secret() {
    releaseguard::secure_buffer_options options{};
#if defined(__linux__)
    options.require_dump_exclusion = true;
#endif
    releaseguard::secure_buffer secret(32, options);
    fill_secret(secret.data(), secret.size());
    use_secret(secret.data(), secret.size());
    secret.clear();
}
```

This is an integration sketch: `fill_secret` and `use_secret` belong to the application, and must follow its error and concurrency policy. Construction accepts **1–1,048,576 bytes**, rejects other sizes with `std::length_error`, and throws `std::system_error` after cleanup when a required OS protection fails. The object cannot be copied or moved. `data()` is available only on an lvalue; the caller still owns pointer lifetime and synchronization.

`secure_buffer_options` defaults to `require_lock=true` and `require_dump_exclusion=false`. Supported protections are attempted even when optional. Inspect `protection_status()`, which returns `locked`, `dump_excluded`, `guard_pages`, and a `dump_exclusion` kind; do not infer them from a successful optional allocation.

| Mechanism | Linux | Windows | Meaning |
| --- | --- | --- | --- |
| Allocation and guards | `mmap`/`mprotect`; inaccessible pages on both sides | Reserved inaccessible pages surrounding a committed payload | The payload requests read/write, not executable access. Guards surround the **page-rounded** payload; an overrun into its padding need not fault |
| Memory lock | `mlock` | `VirtualLock` | Reports whether the OS lock succeeded. It is not protection from debugger access, privileged inspection or every snapshot/hibernation mechanism |
| Dump exclusion | `MADV_DONTDUMP`, kind `linux_madv_dontdump` when accepted | **Not implemented**: `dump_excluded=false`, kind `none`; no WER integration | Linux excludes these pages from cooperating core-dump generation, not arbitrary reads or in-process hooks |
| Clearing | Volatile writes over the whole page-rounded payload | `SecureZeroMemory` over the whole page-rounded payload | `clear()` and destruction clear this owned allocation before unlocking/unmapping; they do not erase other copies |

On Windows, requesting `require_dump_exclusion=true` fails; `VirtualLock` is never reported as dump exclusion. Linux lock limits or policy can also make the default required lock fail. Choose explicit failure handling for your application, and avoid silently downgrading a required protection. The Linux dump scope follows the OS [`MADV_DONTDUMP` contract](https://man7.org/linux/man-pages/man2/madvise.2.html).

Keep allocations short-lived and, where possible, produce a secret directly into the owned pages. Copying a Python `bytes`, a `std::string` or a library output into this object leaves the original copy to its own lifetime. Clearing does not erase registers, caller buffers, allocator history, library-internal copies, previously written swap or logs. The Python password, asset and capability APIs use managed objects and **do not guarantee zeroization**. This class neither transparently wraps those APIs nor prevents a hook from reading its live payload.

## 2. Consume authorization in a trusted service

The APIs in `releaseguard.capabilities` sign capabilities with Ed25519 using a separate signature domain from release manifests and offline licenses. The issuer must first authenticate and authorize the subject according to server policy. Issuing a token for every unauthenticated request would merely sign the attacker's choices.

```python
from releaseguard.capabilities import ReplayStore, issue_capability, consume_capability

# Provision ONCE in a controlled server directory; never initialize on a miss.
ReplayStore.create(server_database_path, max_entries=10000)

# Issuer service: all identity/policy values and request bytes are trusted inputs.
document = issue_capability(
    issuer_private_key,
    subject=authenticated_subject,
    audience="export-service",
    product="MyApp",
    operation="export",
    request=authorized_request_bytes,
    ttl_seconds=60,
)

# Resource service: reconstruct expected context from its own authenticated request.
store = ReplayStore(server_database_path, max_entries=10000)
claims = consume_capability(
    document, pinned_issuer_public_key, store,
    subject=authenticated_subject,
    audience="export-service",
    product="MyApp",
    operation="export",
    request=actual_request_bytes,
)
# Only after successful committed consumption:
perform_protected_operation(actual_request_bytes, subject=authenticated_subject)
```

The paths, keys, authenticated identity, request bytes and business function above are supplied by the integration. Initialization and routine consumption are separate deployment stages; `ReplayStore(path)` requires an existing validated database. The store opens connections per operation; it is not used as a context manager.

The entry points are:

```text
issue_capability(private, *, subject, audience, product, operation,
                 request: bytes, ttl_seconds=60, now=None) -> dict
consume_capability(document, public, store, *, subject, audience, product,
                   operation, request: bytes, now=None) -> dict
ReplayStore.create(path, max_entries=10000) -> ReplayStore
ReplayStore(path, max_entries=10000)
```

The lifetime must be an integer in **1–300 seconds**; request bytes are bounded to **1 MiB**. The four identity/context strings must be nonempty NFC text of at most 128 UTF-8 bytes, without surrounding whitespace or disallowed control/format characters. The envelope contains exactly `format`, `claims`, and `signature`; its format is `open-release-guard-capability/v1`. Signed claims contain `version` (1), `subject`, `audience`, `product`, `operation`, random `jti`, `request_sha256`, `iat`, and `exp`. They are readable claims, not encrypted data. Treat the signed document as a credential and avoid publishing it in logs or issues. Rejection raises `releaseguard.core.GuardError`.

Use a pinned issuer public key or a trusted server-controlled key registry. Never load a replacement key from the token or an untrusted download alongside it. The private issuer key stays in the issuer's controlled environment; it must not be embedded in a client, a build seed, an asset or a distributed config file. A trusted verifier must also enforce the right key for its product and policy. Key compromise requires revocation/rotation and an application-specific outstanding-token policy.

The service supplies its expected `subject`, `audience`, `product` and `operation`; it must not adopt those values from token claims or client flags. It hashes the exact bytes of the request it will execute. There is no automatic HTTP or JSON canonicalization: define an unambiguous application encoding and bind the resource, payload, session or challenge needed to identify one authorized action. Hashing a client-provided summary while executing a different request defeats the binding. Reconstruct this context after authentication, within the trusted service.

Both APIs accept a timezone-aware `datetime` as `now` for a trusted time source and deterministic tests; the default is the server's current UTC time. Never pass a client timestamp or the token's own time fields as the verifier's clock. Use maintained server time, not the controlled client's wall clock.

### Replay state and failure handling

The persistent SQLite store uses atomic consumption so concurrent consumers sharing the same valid store cannot both consume the same authorization. Consumption must commit **before** the service grants access or starts the protected action. Invalid signatures, wrong context and wrong request bytes must not be treated as permission to proceed.

The store retains a persisted clock floor and rejects an observed rollback instead of purging based on a rolled-back time. Invalid signature/context/request/time checks do not advance it; an otherwise valid attempt can advance it even when replay or capacity causes refusal. Expired entries may be pruned only after a permitted time advance. This requires trusted server time and intact state; a database clock floor is not a hardware time source. Restoring an older database or an entire machine snapshot can restore consumed tokens and earlier clock state.

Keep the database and its ancestors under trusted server control, without concurrent replacement, on storage with working SQLite locking and durability. File checks detect ordinary replacement; they do not secure a malicious filesystem owner or stop state rollback. Protect Windows directories with an appropriate ACL; POSIX store files are private (`0600`). A missing database must fail closed rather than silently creating empty replay state. `max_entries` is persisted and must match when reopening; a full live-entry set is refused rather than evicted to admit a replay. Corruption, lock contention, capacity exhaustion and storage errors need explicit operational handling; do not bypass verification when state is unavailable. Independent databases on multiple replicas permit one consumption per replica. Use an architecture with shared authoritative replay state or a separately evaluated distributed protocol; SQLite is not itself that protocol.

Each consumption validates the bounded database, including its existing records. The default capacity is 10,000 and the configurable maximum is 1,000,000; these are resource bounds, not validated production throughput targets. Assess latency, contention and storage growth for your deployment before using it as an online service dependency.

This provides **at-most-once authorization consumption**, not exactly-once business execution. A crash after consumption and before completing the operation can leave the authorization spent. Design idempotency, durable job state and recovery with the business transaction. A holder of a stolen valid bearer capability may win the race for its original request. Short expiry and exact binding constrain that use; they do not identify the holder or prevent theft. Transport authentication, TLS, client/session controls, rate limits and application authorization remain deployment responsibilities. The audience and scope rationale is consistent with [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html); this project is not an OAuth implementation or a compliance claim.

### CLI integration sketch

These commands are for a controlled issuer/resource-service environment. They do not authenticate a user or operate a remote service by themselves. Prepare trusted directories outside the checkout and published release; the private key must already exist under the existing issuer-key workflow. `request.bin` represents server-approved exact request bytes, not a client-supplied authorization decision.

```bash
releaseguard replay-store-init --out server-state/replay.db
releaseguard capability-issue --private issuer/issuer-private.pem --subject customer-001 --audience export-service --product MyApp --operation export --request server-work/request.bin --ttl 60 --out server-work/capability.json
releaseguard capability-consume server-work/capability.json --public server-config/issuer-public.pem --store server-state/replay.db --subject customer-001 --audience export-service --product MyApp --operation export --request server-work/request.bin
```

Issuer key unlocking uses `getpass` or the existing `RELEASEGUARD_PASSPHRASE` secret-manager input; there is no plaintext passphrase flag. Output creation refuses replacement. Repeating consumption of the same token is an error. The CLI's success JSON records consumption only: it does not execute the protected business action. Use the API inside the service's enforcement path rather than accepting a client-reported CLI result.

## Research informing the boundary

The native design also draws on maintained open-source secure-memory guidance: [libsodium](https://doc.libsodium.org/memory_management) documents guarded allocations, explicit clearing and the need to check locking; [OpenSSL secure heap](https://docs.openssl.org/3.6/man3/OPENSSL_secure_malloc/) documents initialization and protection status, including degraded protection and ordinary-allocation fallback in some conditions. These references motivate explicit required protections and actual status reporting. This header is an independent, limited OS wrapper and does not inherit either project's review or guarantee protection for library-internal copies or live hooks.

The following are primary research sources from 2024–2026. Their reported systems, assumptions and measurements are separate from this project. We have **not implemented or reproduced their defenses or attacks**, and do not transfer their timings or probabilities into a REA resistance score.

- **Stateful Least Privilege Authorization for the Cloud — USENIX Security 2024.** Leo Cao, Luoxi Meng, Deian Stefan and Earlence Fernandes. [Venue](https://www.usenix.org/conference/usenixsecurity24/presentation/cao-leo) · [paper](https://www.usenix.org/system/files/usenixsecurity24-cao-leo.pdf). It enforces attenuated bearer-token privileges using server-side policies and action history. This supports examining state and narrow authority together. Our exact-request capability and SQLite replay store do not reproduce its WebAssembly/OAuth framework or inherit its evaluation.
- **HECKLER: Breaking Confidential VMs with Malicious Interrupts — USENIX Security 2024.** Benedict Schlüter, Supraja Sridhara, Mark Kuhne, Andrin Bertschi and Shweta Shinde. [Venue](https://www.usenix.org/conference/usenixsecurity24/presentation/schl%C3%BCter) · [paper](https://www.usenix.org/system/files/usenixsecurity24-schluter.pdf). Malicious host interrupts can affect confidential-VM control flow. The engineering lesson is to examine host/guest interfaces and the trusted computing base, rather than treat anti-debugging as isolation. This is not a demonstration against this project; the paper's TDX positioning experiments include application instrumentation.
- **CounterSEVeillance: Performance-Counter Attacks on AMD SEV-SNP — NDSS 2025.** Stefan Gast, Hannes Weissteiner, Robin Leander Schröder and Daniel Gruss. [Venue](https://www.ndss-symposium.org/ndss-paper/counterseveillance-performance-counter-attacks-on-amd-sev-snp/) · [paper](https://www.ndss-symposium.org/wp-content/uploads/2025-1038-paper.pdf). Host-visible counters leak secret-dependent behavior in the evaluated setting. Memory encryption alone does not establish freedom from side channels. This does not establish that every present-day TEE configuration is vulnerable.
- **TEEcorrelate: An Information-Preserving Defense against Performance-Counter Attacks on TEEs — USENIX Security 2025.** Hannes Weissteiner, Fabian Rauscher, Robin Leander Schröder, Jonas Juffinger, Stefan Gast, Jan Wichelmann, Thomas Eisenbarth and Daniel Gruss. [Venue](https://www.usenix.org/conference/usenixsecurity25/presentation/weissteiner) · [paper](https://www.usenix.org/system/files/usenixsecurity25-weissteiner.pdf). Its aggregation and counter-value decorrelation target particular observable channels. It is not a generic random-delay recipe, an anti-Frida feature or a guarantee against plaintext dumps.
- **BreakFAST: Confused Deputy Attack on Infinity Fabric to Break AMD SEV-SNP — IEEE S&P 2026.** Philipp Giersfeld, Benedict Schlüter and Shweta Shinde. [Official accepted-paper list](https://www.ieee-security.org/TC/SP2026/accepted-papers.html) · [author paper](https://www.shwetashinde.org/publications/breakfast_oakland26.pdf). A platform trust-chain flaw shows why firmware, host interfaces and attestation assumptions need review. It does not prove all TEEs broken; the paper's proposed mitigations were not implemented and validated by its authors.

Moving confidential work to a server changes which host must be trusted; it does not make that server invulnerable. Its outputs and observable behavior can still inform black-box functional replication. A TEE can alter the threat model only with an appropriate platform, updated firmware, attestation/key-release policy, small trusted code base and explicit side-channel assumptions. This version ships no TEE integration. Replacing an algorithm or adding debugger checks does not repair a client that already holds the secret or plaintext.

## Evidence and further work

The [earlier validation record (Chinese)](testing-2026-10-15.zh-CN.md) and [v0.3 observations](testing-2026-10-20.md) record recovery from project-owned synthetic samples, including runtime plaintext recovery. Those failures remain relevant. Source review and functional API tests do not reverse them or establish an end-to-end REA protection pass. Consult the [v0.4 validation report](testing-v0.4-2026-10-20.md) and [Actions run for the exact commit](https://github.com/Afloat16/anti-rea-forge/actions) for measured platform coverage; this guide does not assign a cracking probability or claim an unrun platform test.

A [real Frida 17.23.2 attempt](results/frida-buffer-2026-10-20.json) compiled a project-owned C++ fixture with GCC 13.3 at `-O2`; its independent control exited successfully. Spawn failed with `NotSupportedError: target exited with status 1`. Attach failed with `ProcessNotFoundError: unable to find process with pid 27`, although the owned process was still alive immediately before attach. No hook or memory-read observation completed, and the exact underlying OS cause was not established. The record is `environment_or_instrumentation_failure` with `protection_outcome=not_evaluated`, not a protection pass. It does not run the REA agent/model/provider pipeline.

Contributions are welcome for reproducible, authorized experiments, Windows validation, failure handling and narrow threat-model improvements. Use only your own or authorized samples, record tool versions and blocked stages, and report recovered secrets as a protection failure. Follow [CONTRIBUTING](../CONTRIBUTING.md) and [SECURITY](../SECURITY.md); do not submit real issuer keys, tokens, passwords or customer data.
