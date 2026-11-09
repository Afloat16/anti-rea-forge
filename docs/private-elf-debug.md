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
