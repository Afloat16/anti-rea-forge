# Native unlock tokens: what the Ghidra experiment measures

**The asset is a reusable input accepted by the unmodified program.** Reading
the program, finding its verifier, patching a branch and recovering an accepted
input are different outcomes. A successful decompilation is expected here; it
is a prerequisite for a meaningful experiment, not an adverse result.

## Why change the comparison

The [earlier native fixture](results/testing-2026-10-15/fixture/fixture.cpp)
stored an expected value in a reversible literal mask, decoded it, and passed
the decoded bytes to `strcmp`. The [archived investigation](testing-2026-10-15.zh-CN.md)
used Ghidra's pseudocode **and** ELF constants to reconstruct the reference. It
was not a plain string search. The [replay script](results/testing-2026-10-15/ghidra/recover_sample_literal.py)
hard-codes addresses and constants from that specific ELF. Running it unmodified
against an unrelated ELF would test those addresses, not the protection.

For a new application-owned **opaque random token**, the issuer can instead
draw 32 bytes from an operating-system entropy source and generate a public
SHA-256 verifier. The caller keeps the token in a separate private file and
ships only the verifier. At unlock time, the native program checks the input
format, hashes the candidate using the scheme's domain prefix, and compares
the resulting 32 bytes with the expected digest. The public digest and the
code implementing the comparison are deliberately discoverable.

This design depends on a random token, not secrecy of the prefix, comparator
or hash algorithm. The fast verifier permits offline guessing. Do not use it
for human passwords, short serial numbers, or a pre-existing low-entropy
secret. A domain prefix is public protocol separation, not a secret key.

The portable release scan checks file contents for the issued token format by
default. It flags the prefix followed by 64 lowercase hex digits, including
when embedded in larger data, across read boundaries and in supported ZIP
members. It covers UTF-8, UTF-16 LE/BE and UTF-32 LE/BE representations. This
identifies a **shape**, not a token accepted by a specific verifier; a deliberate
test decoy can also match. Reports do not copy matched payload bytes into
findings, but do include paths, archive member names and file digests. Never use
the token as a filename. Encoded, transformed and fragmented secrets are not
exhaustively detected. The explicit policy switch is `check_native_tokens`.

## What qualifies as a measured result

1. Run an identified official Ghidra distribution on project-owned native
   fixtures. Preserve the tool identity and each binary's digest. Require
   successful analysis of the target program, completed decompilation of the
   relevant function and nonempty pseudocode. Reject timeouts, incomplete reads,
   truncated scans and empty candidate enumeration caused by tool failures.
2. Give the analysis script the executable and the public candidate format.
   Do not give it the issued token, ground-truth digest used as a search oracle,
   private output directory, source template containing the correct literal,
   or a harness-provided address of the correct candidate.
3. Run the **same** candidate probe on each side. A reference-literal control
   must yield an input that actually unlocks the unchanged executable. A
   token-shaped, invalid decoy should remain recoverable on the protected side:
   this rules out the trivial explanation that the scanner stopped reading.
4. Replay extracted candidates and positive/negative functional inputs against
   the original program. Verify exact accepted/denied outputs and exit status,
   and unchanged binary identity. The protected fixture must still accept
   its separately held genuine credential. If a developer deliberately embeds
   the real credential again, candidate recovery should work again.

Report how candidates were obtained: a string found in **Ghidra's loaded
memory** is not necessarily in the **decompiled C text**. Report the number of
accepted recovered inputs, not just whether the source token's bytes matched a
marker. The resulting claim applies to the named build, credential format and
probe. It is not a measurement of all possible Ghidra analyses, nor a rerun
of the historical masked-literal reconstruction.

## What remains visible

The candidate must exist while an authorized user supplies it; a debugger,
input hook or process owner can observe a legitimate entry. A digest comparison
does not protect that input or all preceding code from timing observation. A
local user may patch the check, replace the digest or program, or copy a stolen
token. This verifier provides no revocation, per-user binding, proof of
possession, or authority over remote operations. Use a trusted server when the
protected operation must remain enforceable despite a modified client.

### Primary references

- [Ghidra DecompileResults](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html):
  distinguishes completed results, errors, timeouts and the returned decompiled
  function text.
- [Python secrets](https://docs.python.org/3/library/secrets.html): how random
  bytes and hexadecimal tokens are generated.
- [OpenSSL EVP digest API](https://docs.openssl.org/3.5/man3/EVP_DigestInit/):
  digest operations and their return values.
- [OpenSSL CRYPTO_memcmp](https://docs.openssl.org/3.5/man3/CRYPTO_memcmp/):
  equality returns zero; comparison time depends on length rather than
  contents. That property applies to this fixed-length comparison, not the
  entire application.
