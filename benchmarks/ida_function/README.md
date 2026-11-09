# IDA 9.x function observation adapter

## Validation status

This adapter has undergone Python syntax checks and engine-independent validator tests. Actual execution with IDA 9.x and Hex-Rays remains pending in a legally licensed environment. The historical IDA 5 measurements have their own adapter and provenance. This directory currently contains the implementation and static tests.

## Run with a compatible engine

Use an installed IDA 9.x edition that exposes IDAPython and the appropriate Hex-Rays decompiler. The adapter queries the running kernel version, waits for all automatic-analysis queues, finds the public `rg_compute` symbol, and enumerates every recognized function outside external-import segments. It records the outcome of `init_hexrays_plugin()` and the actual Hex-Rays version. An unavailable decompiler produces explicit `unavailable` results for every function.

Place a copy of the project-owned x86 ELF in a fresh working directory, then run the installed engine. Use new paths for the database and observation directory.

```sh
/path/to/idat -A -L/path/to/work/ida.log \
  -o/path/to/work/analysis \
  "-S/path/to/repo/benchmarks/ida_function/export_functions.py /path/to/new-observation" \
  /path/to/work/sample.elf
```

The output directory is the script's only argument. The target's public ABI is `uint32_t rg_compute(uint32_t)`. The evaluator retains source, expected outputs, and hidden inputs in its separate scoring environment.

## Export and validation

- `functions.json` records the input SHA-256 from both the IDA database and the original ELF, kernel/Hex-Rays versions, complete recognized function inventory, function chunks, instructions, code/data references, CFG, original database bytes, loaded bytes, file offsets, C ranges, and every helper's observation/decompilation status.
- `program.c` contains the complete pseudocode returned for the inventoried functions. IDA display-color tags are removed through `ida_lines.tag_remove`; function text is otherwise retained. Structured warnings from `cfunc.get_warnings()` retain their address, ID, and full text.
- `decompiled.c` contains the target's pseudocode, with its success/failure recorded in the matching function entry.
- `program.elf` preserves the complete original input for independent analysis, including global tables and unrecognized code.
- `run.json` records byte-validation results, API-returned C counts, helper failures, warnings, adapter hashes, and output hashes.

Every exported code byte must be loaded in the actual IDA database. The exporter obtains its original value through `get_original_byte()`, checks the input file offset and inverse mapping through `get_fileregion_offset()`/`get_fileregion_ea()`, and compares that original value with the input ELF. The independent validator repeats byte comparison, chunk coverage, and instruction-to-loaded-memory checks. A mapping or original-byte mismatch remains an explicit observation failure. The target must pass its byte checks for a validated run report.

The original-byte API describes the value before IDA patches. Loader behavior and file-region mappings require confirmation during the pending genuine-engine run. A helper whose bytes cannot be validated remains in the inventory with an observation error. Decompiler failures and unavailable Hex-Rays sessions likewise retain explicit per-function records. `api_completed_functions` measures returned C objects, and warnings remain part of the observation. Independent reconstruction and private-input scoring determine semantic recovery.

## Static checks

```sh
python -m unittest discover -s benchmarks/ida_function -p 'test_*.py' -v
```

These tests use synthetic report structures to exercise the validator. The genuine-engine completion marker is emitted only by the IDAPython exporter after its runtime checks.

## Official API references

- [IDA 9.0 command-line switches](https://docs.hex-rays.com/9.0/user-guide/configuration/command-line-switches)
- [Official IDAPython automation examples](https://docs.hex-rays.com/9.0/developer-guide/idapython/idapython-examples)
- [Automatic analysis queues](https://python.docs.hex-rays.com/ida_auto/index.html)
- [Input-file hash metadata](https://python.docs.hex-rays.com/ida_nalt/index.html)
- [File-region mappings](https://python.docs.hex-rays.com/ida_loader/index.html)
- [Original and loaded database bytes](https://python.docs.hex-rays.com/ida_bytes/index.html)
- [Hex-Rays initialization, C output and structured warnings](https://python.docs.hex-rays.com/ida_hexrays/index.html)
