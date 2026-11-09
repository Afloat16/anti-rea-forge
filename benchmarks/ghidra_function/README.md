# Ghidra function recovery observations

The runner imports a complete project-owned x86 ELF into Ghidra 12.2, runs the default automatic analysis, and independently locates the global `rg_compute` symbol. Its public contract is `uint32_t rg_compute(uint32_t)`. The actual inferred prototype remains in the report and decompiled C.

```sh
JAVA_HOME=/path/to/working/jdk25 python benchmarks/ghidra_function/probe.py /path/to/sample.elf \
  --ghidra-home /path/to/verified/ghidra_12.2_PUBLIC --direct-java \
  --out observations/sample
```

Run from the repository root. Alternatively, pass `--archive /path/to/ghidra_12.2_PUBLIC_20261016.zip`. The existing `ghidra_token.probe.get_ghidra` helper verifies the official archive size and SHA-256 before extraction. `launch_command` supplies the official headless entry point. A supplied extracted distribution is recorded as caller-verified in `run.json`.

## Exported material

- `decompiled.c` contains the unedited C returned by Ghidra's decompiler.
- `function.json` contains the analyzer's input SHA-256, version, inferred signature, function body ranges, complete recognized instructions, undecoded ranges, basic-block CFG, direct callees, computed transfer sites, outgoing flows, and out-of-body data references. Original function bytes include their offsets in the imported ELF. The `loaded_hex` field records the analyzed memory bytes, and `loaded_function_byte_changes` counts differences from the original bytes.
- `run.json` exists after successful validation and records provenance, output hashes, counts, and the import setting.
- `console.log`, `headless.log`, and `script.log` retain diagnostics, including failed runs.

The analysis input contract consists of a neutral-named ELF copy, the fixed public target symbol, and the output directory. A later recovery worker can receive `decompiled.c` alone, or an explicitly chosen observation bundle. The scorer retains the source, private reference, expected values, and hidden test inputs separately.

The ELF import explicitly enables Ghidra's documented `applyRelocations` loader setting. All default automatic analyzers remain enabled. Each original byte is read through Ghidra's file-provenance API and independently compared with the ELF at the reported file offset. Loaded memory bytes are separately read from the program database, and every instruction must match those loaded bytes. This preserves normal relocation-aware analysis while retaining evidence of the original executable and any loaded-byte differences.

The runner requires the full-analysis and post-analysis completion markers and rejects unexplained `ERROR` log entries. It records one precisely matched environment diagnostic when Java cannot query cache `FileStore` metadata. The shipped Ghidra 12.2 `Base-src.zip`, `ghidra/formats/gfilesystem/FileCache.java` lines 119–125 and 585–592, shows that this condition skips the cache free-space precheck. Its full log lines remain in `run.json`.

The exporter records direct callees, every recognized out-of-body data reference, outgoing flows, and computed transfers. The runner summarizes their counts and records computed transfers with no resolved targets. Recovery of a function that uses callees or external data requires their corresponding bodies or data contents, or a declared scope restriction. The current single-function contract assumes a self-contained computation. Review these dependency fields before supplying a reduced recovery bundle.

## Whole-program material

Add `--include-program` for interpreter helpers, descriptor tables, and other cross-function dependencies. The original target observations remain available alongside the additional artifacts.

- `program.c` contains the original decompiler output for every recognized nonexternal function. Each function has an address boundary comment.
- `program.json` contains the complete recognized function inventory and a result for every inventory entry, including its name, entry, body ranges, called entries, completion status, diagnostic, and C byte range/hash. Failed or timed-out functions retain explicit result records. The runner rejects an omitted helper.
- `program-warnings.json` records warnings found directly in every hash-verified C slice, indexed by function and local C line. It includes unrecovered jump tables, indirect jumps treated as calls, truncated control flow, bad-instruction diagnostics, `halt_baddata()` calls, and other emitted warning comments. The original C bytes remain the reconstruction input.
- `program-memory.json` lists all memory blocks and their read/write/execute, loaded, and initialized attributes. Every initialized loaded byte has a database value. File-backed ranges also have original bytes and input file offsets. Synthetic loaded ranges retain their actual database bytes and an explicit unbacked-byte count. The runner checks complete block coverage and every file-backed allocated ELF section.
- `program.elf` is a byte-identical copy of the analyzed executable for independent inspection.

`run.json` hashes every exported artifact and retained log. It records recognized functions, API-completed decompilations, explicit function failures, per-function C warnings, allocated-file-byte coverage, loaded-byte changes, and unbacked memory. `api_completed_functions` measures Ghidra's `decompileCompleted()` return status. A completed API call can emit an unrecovered jump table or truncated control flow, so those observations retain their warnings and require independent reconstruction. The reconstruction worker receives the full executable alongside the observation bundle. Its independent reconstruction and private-input score determine the observed recovery result.

## Acceptance

The probe establishes a recorded analysis observation. A recovery attempt must produce a separately compiled implementation and match the original executable on private test inputs, including branch boundaries and independently generated cases. Compilation failure, analyzer failure, timeout, shorter pseudocode, symbol disappearance, and unreadable output must remain distinct measurement outcomes. Independent reconstruction and functional scoring complete the recovery experiment.

The focused validator regressions run through `python -m unittest tests.test_ghidra_function_probe`. Genuine Ghidra execution uses the command above and is recorded separately from these Python validation tests.

## Primary API references

- [Ghidra DecompInterface](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html)
- [Ghidra BasicBlockModel](https://ghidra.re/ghidra_docs/api/ghidra/program/model/block/BasicBlockModel.html)
- [Ghidra AddressSourceInfo](https://ghidra.re/ghidra_docs/api/ghidra/program/database/mem/AddressSourceInfo.html)
- [Ghidra Instruction](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html)
