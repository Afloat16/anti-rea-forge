# Publish native code with private debugging symbols

## Release a Linux executable or shared library

Build an ordinary linked ELF with static symbols. Enable DWARF (for example, `-g` with your normal optimization settings) if you want file and line information internally. On the build machine, install GNU binutils and this checkout with Python 3.10 or newer.

```sh
python -m pip install .
python -m releaseguard split-elf-debug ./build/myapp \
  --public ./release-linux --private ./private-symbols \
  --private-name calculate_internal_quote
```

Use fresh, separate directories under existing, trusted parents and an immutable input. Supply ASCII linker spellings for names you want checked. Repeat `--private-name` for more names or omit it to split standard static symbols and debug sections without a name policy. The check requires each selected spelling to occur in the private file and looks for its bytes throughout the public file in ASCII, UTF-16 and UTF-32 (both byte orders). A lingering diagnostic string, exported name or matching substring can block publication.

Deploy only `release-linux/myapp`. Restrict access to the full build, the private symbol directory, CI artifacts and any symbol server. The public ELF retains a basename and CRC in `.gnu_debuglink`, and can retain its build ID. These let a debugger associate the release with any matching debug file it can access. On a private debugging machine, use the associated file for source-level diagnosis. Pass a link-time address from the matching release.

```sh
addr2line -f -C -e private-symbols/myapp.debug 0x08049000
```

For PIEs and shared libraries, use the link-time address after accounting for the load bias. Run the split before signing, packaging or adding file capabilities. Preserve your normal end-to-end tests for each produced artifact. The tool checks the program headers and loadable segment contents, allowing the ELF header fields that describe the new section table to differ. It leaves the build input intact. The application carries no new runtime component. Build scanning and copying take time and memory.

The command accepts ordinary ET_EXEC/ET_DYN files up to 64 MiB. It rejects missing static symbols, recognized supplementary debug metadata, trailing payloads and altered loadable bytes. Exit 0 creates both outputs. Exit 3 reports configured residual names, and exit 2 reports invalid input or a tool failure. Deploy only after exit 0. Use this on trusted build products under your own control. Dynamic exports, unwind data, language-specific reflection metadata and application strings can still identify code. Separate DWARF packages, custom ELF containers and applications that inspect their entire on-disk image require their own packaging checks.

## Embedded LLVM IR in 1.3

`clang -fembed-bitcode=all` can ship full LLVM IR and compiler-command records next
to native instructions. GNU `strip --strip-all` can remove static symbols while
leaving `.llvmbc` and `.llvmcmd` intact. The public binary can therefore run normally
and still expose private function/local names, `source_filename` and typed operations
to `llvm-dis`. LLVM also defines `.llvm.lto` for ELF FatLTO material. See the
[native bitcode wrapper specification](https://llvm.org/docs/BitCodeFormat.html#native-object-file-wrapper-format)
and [FatLTO documentation](https://llvm.org/docs/FatLTO.html).

Version 1.3 separates those three exact ELF section names in addition to the existing
debug/type sections. Start from the original linked ELF with static symbols, then use
the same `split-elf-debug` command above. Compiler records are accepted only when all
of these conditions hold:

- Each name occurs once and the section is `SHT_PROGBITS`.
- `SHF_ALLOC`, writable/executable and other unsupported flags are absent; only the
  optional `SHF_EXCLUDE` flag is allowed.
- The section has no link, info or entry-size semantics, and its bytes overlap no
  file-backed program segment. Clearing `SHF_ALLOC` alone does not make mapped IR safe
  to remove.
- The private debug sidecar retains each section's exact size and SHA-256. Both the
  bitcode and command-line records must survive, and none of the recognized compiler
  sections may remain public.
- Existing ELF identification, execution/program-header and `PT_LOAD` byte-preservation
  checks pass, allowing only the documented section-table header changes.

Unsupported flags, allocated/mapped records, duplicate sections, lost or changed
private bytes, and altered execution contents abort the split without publishing the
new output directories. The original input remains unchanged. This preserves one
ordinary native load image; applications that interpret their own file or use bitcode
as runtime input need an application-specific build workflow.

The private sidecar now holds compiler IR as well as debugging material. Keep it,
any extracted `.bc`/`.ll` files, and the original compiler output outside the served
release. The source spelling policy remains a byte check: `--private-name` is not an
LLVM parser, and arbitrary encoded names need the independent recovery controls below.
The tool leaves the native instructions available for disassembly and decompilation.

### Paired compiler/reader control

The [recorded owned fixture](results/llvm-metadata-recovery-v1.3.0.json) used actual
Clang 19.1.7 compilation, GNU linking and LLVM 19 `llvm-dis`, with debug generation
disabled (`-g0`). The official v1.2 wheel allowed its split public ELF; `llvm-dis`
recovered four private function/local names, the source path and arithmetic. In the
v1.3 split public ELF the embedded sections are absent. The private sidecar and a
control with bitcode added back both recover those four names. Reintroducing only
`.llvmcmd` also makes the new gate reject the artifact.

The original, v1.2 public and v1.3 public programs all return **48, 85 and 122** for
the same three fixture inputs. Their `.text` bytes and dynamic-symbol listings match.
These observations isolate an avoidable IR disclosure channel; they do not measure
general machine-code recovery or REA/model success rates. PE/Mach-O coverage here is
structural detection, with no Windows/macOS native-runtime claim.

From a checkout with the candidate core installed, real Clang/LLVM tools and GNU
binutils, reproduce against an environment installed from the official v1.2 wheel:

```sh
python benchmarks/llvm_metadata_recovery.py \
  --llvm-bin /usr/lib/llvm-18/bin \
  --baseline-python /path/to/v1.2-env/bin/python \
  --baseline-wheel /path/to/open_release_guard-1.2.0-py3-none-any.whl \
  --work /tmp/rg-llvm-corpus --out /tmp/rg-llvm-result.json
```

Both output paths must be new. The driver checks the official wheel SHA-256 and
every installed baseline package file, and rechecks package inventories before
completion. The Linux LLVM 18 CI job requires the same actual producer/reader controls;
missing tools are failures in that job. The bitcode-wrapper control uses Clang's Darwin
IR target without claiming a linked or executed macOS program.

### Metadata gates and intentional opt-outs

`scan-release` reports recognized compiler sections as `native_compiler_metadata`.
The PE/ELF `gate` independently defaults `require_no_compiler_metadata` to `true`;
setting only the older debug/symbol requirements to `false` does not disable this new
requirement. A native policy can explicitly set `require_no_compiler_metadata: false`
for intentional compiler-data distribution. Other native requirements still apply.
The portable policy uses the broader `check_native_metadata: false` instead; native
policy fields are not accepted by the portable scanner.

The same scanner detects PE `.llvmbc`/`.llvmcmd` and Mach-O
`__LLVM,__bitcode`/`__cmdline`/`__bundle`; the ELF splitter does not rewrite those formats.
Standalone raw/wrapped LLVM bitcode, even renamed or nested in inspected ZIP/ASAR,
is recognized but unsupported: `native_metadata_unverifiable`,
`unsupported_standalone_metadata` and `native_metadata_scan_completed: false`.
This is a decision to block direct IR publication. Such files can be valid JIT inputs;
their signatures do not prove a malformed program, and opting out does not conceal IR.

## Put the restricted operation behind a service-side check

An attacker who controls a binary can change its return value. For a service-backed operation, have the service authenticate the caller, choose the route and handler, bind the exact request bytes, and consume a short-lived issuer-signed capability before execution.

```python
from releaseguard.capabilities import run_authorized_operation

def issue_export(request_bytes, supplied_grant, authenticated_customer):
    return run_authorized_operation(
        supplied_grant, trusted_issuer_public_key, server_replay_store,
        subject=authenticated_customer, audience="exports", product="myapp",
        operation="create-export", request=request_bytes, handler=create_export,
    )
```

Here the public key, replay store, authenticated identity and handler come from the service. Only the trusted issuer can issue capabilities after checking entitlement. The handler receives the exact byte string verified against the grant. Successful consumption spends the capability even if the handler later fails. This guards admission once. Coordinate durable business effects with the application's transaction or idempotency design. Verification, replay storage and handler execution belong to the service. [Capability issuance and replay-store setup](runtime-protection.md)

## Reproduce the two-engine observation

The fixture is an i386 Linux ELF with one randomly named local function and one exported public entry. Run the commands below from a checkout with Release Guard installed. On GNU/Linux install GCC and binutils. The freestanding fixture needs a kernel that runs i386 Linux programs or an explicit `--emulator /path/to/qemu-i386` on the prepare and analysis commands. For Ghidra use the pinned release and the supported JDK referenced in the [Ghidra setup](../benchmarks/ghidra_token/README.md).

```sh
python benchmarks/native_symbol_controls.py prepare /tmp/rg-corpus
python benchmarks/native_symbol_controls.py ghidra /tmp/rg-corpus \
  --archive /path/to/ghidra_12.2_PUBLIC_20261016.zip --out /tmp/rg-ghidra.json
```

For the pinned IDA Freeware 5.0 observation, use a Windows workstation licensed for the intended use. The [vendor-authorized distribution](https://www.scummvm.org/news/20180331/) is for noncommercial use. The installer SHA-256 is `e3a5e1f2334f68f14f5ee81c3fcc44121cb24f514be78dfc30805ceee0de6029`. The adapter also checks the installed program and kernel hashes. Open IDA interactively before the first batch job, complete its license dialog and dismiss the one-time About panel. Then close IDA. Copy the three fixture ELFs and their manifest to the Windows workstation. Point the adapter to the local installation and use a fresh output directory.

```powershell
$env:RG_IDA_BIN = 'C:\IDA Free\idag.exe'
$fixture = Get-Content -Raw corpus/fixture.json | ConvertFrom-Json
New-Item -ItemType Directory ida-reports
foreach ($case in 'baseline','public','restored') {
  python benchmarks/elf_symbols/ida_symbol_probe.py "corpus/$case/app" "ida-reports/$case.json" $fixture.private_entry $fixture.public_entry
  if ($LASTEXITCODE -ne 0) { throw "IDA analysis failed for $case" }
}
```

Bring the three JSON records back to Linux and check them against the *same* corpus. The Linux replay uses the exported entry address reported by each analyzer, maps it to a file offset and patches only a disposable copy of the synthetic fixture.

```sh
python benchmarks/native_symbol_controls.py ida /tmp/rg-corpus \
  --observations /path/to/ida-reports --out /tmp/rg-ida.json
python benchmarks/native_symbol_controls.py compare \
  --ghidra /tmp/rg-ghidra.json --ida /tmp/rg-ida.json --out /tmp/rg-dual.json
```

The unstripped, public and deliberately restored ELFs must have identical machine code, identical test exits and matching per-case hashes across both analyzers. The restored control adds back just the name recovered from the private debug file. Each analyzer receives the private entry address to isolate the name-recovery question. The receipt test uses a fresh request, ephemeral keys and two local subprocesses modeling different trust policies. The test driver verifies the signatures on every receipt and counts real handler calls. It does not simulate a compromised service, a full network transport, an arbitrary analyst or current commercial IDA versions.


### Recorded run

On the project-owned November 9, 2026 fixture, Ghidra 12.2 ran from its SHA-256-verified official archive using the Java headless entry point. IDA Freeware 5.0.0.879 analyzed identical input hashes on Windows. A fresh scratch database was used for each input. QEMU i386 executed the ELFs during the recorded Linux replay. The [Windows observation log](https://github.com/Afloat16/anti-rea-forge/actions/runs/42617577454/job/129161188137), [pinned one-off observer and exact fixture files](https://github.com/Afloat16/anti-rea-forge/tree/e8c2386dab4b2930ce6430fcc54765480ad174aa/cases), and [paired report with measured names, addresses, hashes and receipt outcomes](results/native-elf-controls.json) identify the evidence behind the README. The checked-in Windows adapter performs the same IDA queries after first-run setup. It analyzes locally using the owner's installation.

## CTF/BTF type metadata in 1.0

Ordinary GNU strip can retain private type names even after the static symbol table
is gone. The splitter now preserves eligible `.ctf`, `.SUNW_ctf`, `.BTF`, `.BTF.ext`,
`.BTF.base` and `.gdb_index` sections in the private debug file and explicitly removes
them publicly. Only unique, non-allocated PROGBITS sections are accepted. Each private
section must retain its exact size and SHA-256, and the original runtime-segment
checks still apply. Allocated/duplicate type sections and already externalized
debug references remain rejected. Start from the original linked ELF with static
symbols, not an already stripped binary. [Actual GCC/strip/split controls](../tests/test_elf_type_metadata.py)
