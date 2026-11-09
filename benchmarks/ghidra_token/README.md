# Ghidra native token extraction and replay

This experiment asks a narrow question: can Ghidra find a complete, reusable
token matching the public token grammar in the delivered ELF? It does not ask
whether an analyst can understand or patch a local branch.

## Reproduce

Use Linux x86-64, JDK 25, g++, OpenSSL development headers/libcrypto, unzip
and Python with this checkout installed. Download the official
[Ghidra 12.2 release ZIP](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build);
the probe checks its size and the SHA-256 published on the release page before
extracting it to a temporary directory. From the repository root:

```sh
python benchmarks/ghidra_token/probe.py --archive /path/to/ghidra_12.2_PUBLIC_20261016.zip --python "$(command -v python)" --out ghidra-token-observation.json
```

The report must be a new file. On hosts without shell process substitution,
`--direct-java` uses the VM options returned by the unmodified distribution's
`LaunchSupport` and its official `ghidra.app.util.headless.AnalyzeHeadless`
entry point; set `JAVA_HOME` to the JDK. The normal launcher is
`support/analyzeHeadless`. A preverified installation can instead be selected
with `--ghidra-home`; in that mode the report explicitly does not claim an
archive hash was checked during the run.

## What must happen for a pass

The installed issuer generates one fresh random 256-bit token. The driver
builds three project-owned fixtures with the same compiler options, admission
interface, independent same-format invalid example, and program outputs:

| ELF | How it authorizes | Expected accepted candidates |
| --- | --- | ---: |
| Embedded reference | Compares the input with the clear token compiled into the ELF | 1 |
| Verifier only | Uses the generated public verifier; the clear token never enters its fixture header | 0 |
| Verifier + accidental plaintext | Uses the same real verifier, but also includes the clear token in a diagnostic literal | 1 |

The same Java post-script runs after normal automatic analysis of each ELF. It
scans initialized, loaded memory blocks for the public token pattern and also
extracts complete literals from the decompiler's C for the named fixture and
verifier functions. A real admission function must decompile with the expected
comparison/verifier call. The script gets no correct token, expected digest,
source file or precomputed address. It discovers the public digest by symbol
in the verifier binaries; the driver independently checks the 32 observed bytes
and their references afterward. Symbols are intentionally retained to facilitate
inspection, not concealed to force a negative result.

The driver replays every distinct candidate through the unchanged program's
stdin. All fixtures must accept the legitimate token; the wrong example and
malformed input must be denied. On both verifier fixtures the observed digest,
reformatted as a valid-looking token, must be denied as well. Missing candidate
controls, timeouts, wrong input hashes or incomplete gate decompilation cannot
produce a passing report. Credentials, candidate strings and raw pseudocode
stay in a temporary workspace; the retained report contains counts and hashes.

The [recorded observation](observation-2026-11-09.json) covers these exact
fixtures. The ordinary comparison is a plaintext control, **not a rerun of the
historical RG_TEXT decoder reconstruction**. Runtime interception of a legitimate
user's input, alternate static reconstruction, bypassing a patchable local
decision and protection of general program logic are separate questions.
