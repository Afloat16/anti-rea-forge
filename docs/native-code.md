# Native function transformations

`native-obfuscate` builds a Linux relocatable object from LLVM 18 IR. Four profiles provide control-flow transformations, instruction virtualization, and authenticated encryption of the VM instructions required to execute selected functions. Each requested function must receive verified coverage before the build can succeed.

[简体中文 integration guide](native-code.zh-CN.md)

| Profile | Plugin and pipeline | Supported platform |
| --- | --- | --- |
| `flatten` | eshard, `function(flattening),verify` | Linux x86 and x86-64 |
| `split-flatten-substitution` | eshard, `function(split-basic-blocks,flattening,substitution),verify` | Linux x86 and x86-64 |
| `virtualize` | Amice, VM-only configuration through `default<O2>` | Linux x86-64, experimental |
| `sealed-virtualize` | Amice VM plus external-key authenticated storage and generated C++17 loader | Linux x86-64, experimental |

The input translation unit determines the transformation scope. The plugin processes every eligible definition in that unit. Repeated `--function` arguments identify functions whose transformation is required for the build to succeed. Put the intended functions in a dedicated translation unit and retain the ordinary application build for other units.

## Execute encrypted function instructions

The `sealed-virtualize` profile converts self-contained scalar-integer functions into a VM representation and encrypts the bytecode, descriptor records and randomized descriptor guards. The release contains null VM storage pointers and a cleared ready flag. A separately delivered random 32-byte key opens the payload directly in an owned `secure_buffer` mapping. The loader verifies authentication, length and SHA-256, makes the mapping read-only, binds its storage pointers and finally enables the wrappers. Each locked wrapper returns zero. The application must check the initialization result because zero can also be a valid function result.

The protection target is the release before external key delivery. An authorized process holds plaintext VM instructions and descriptors. A reader of that process memory can obtain them. Public ABI, interpreter operations, program sizes and format metadata remain observable. The current implementation supports independent scalar-integer computation units with widths 1, 8, 16, 32 and 64. Original globals, module-level assembly, external native calls, pointers, vectors, floating-point operations and unsupported ABI attributes cause a build failure.

Use the official Amice LLVM 18 Linux artifact below. Its source revision is `19b6c473ee8a59d66a91d3b7c2d460bb6af7c99e`, released as `v0.1.6-beta.1` under Apache-2.0. The integration clears inherited `AMICE_*` and `LLVM_OBF_*` configuration and selects the built-in VM profile with a module runtime. [Pinned Amice source](https://github.com/fuqiuluo/amice/tree/19b6c473ee8a59d66a91d3b7c2d460bb6af7c99e)

```sh
python -m pip install .
curl --fail --location -o amice-llvm18.so \
  https://github.com/fuqiuluo/amice/releases/download/v0.1.6-beta.1/libamice-llvm18-linux-x86_64.so
echo 'aa4527516a03ddbdc4034e68dece3190110dfe8ff34a4d1a8284e896a733a882  amice-llvm18.so' | sha256sum --check

python -m releaseguard asset-keygen --out ../private-code-key.bin
/usr/lib/llvm-18/bin/clang -O2 -fPIC -g0 \
  -fno-unroll-loops -fno-vectorize -fno-slp-vectorize \
  -emit-llvm -c sensitive.c -o sensitive.bc
python -m releaseguard native-obfuscate \
  --input sensitive.bc --out sealed-function \
  --llvm-bin /usr/lib/llvm-18/bin \
  --plugin amice-llvm18.so \
  --plugin-sha256 aa4527516a03ddbdc4034e68dece3190110dfe8ff34a4d1a8284e896a733a882 \
  --function rg_compute --profile sealed-virtualize \
  --key-file ../private-code-key.bin \
  --product myapp --release v1 --module-id compute
```

The new directory contains `protected.o`, `report.json` and five generated C++ integration files.

| Generated file | Purpose |
| --- | --- |
| `releaseguard_native_code.hpp` | Initialization and clearing interface |
| `releaseguard_native_code.cpp` | Authentication, owned mapping and storage-pointer lifecycle |
| `releaseguard_native_code_asset.hpp` | Ciphertext and public authentication parameters |
| `releaseguard_sealed_asset.hpp` | HKDF/AES-GCM reader with direct-buffer decryption |
| `releaseguard_secure_buffer.hpp` | Guarded mapping, page protections and cleanup |

The report's `code_seal.format` is `open-release-guard-sealed-native-code/v2`. Each storage entry has an `offset_bytes` within the authenticated payload. Bytecode has byte alignment, while descriptor and expected-guard tables have eight-byte alignment. Padding is included in the encrypted payload and its complete digest. The format identifier also participates in the module-symbol and C++ namespace hash. This separates the pointer-storage ABI from bundles produced with the earlier unversioned symbol formula. A compiled regression requires mixed-layout linking to fail. Regenerate and link the object, loader and headers together for this format.

Read `code_seal.cpp_namespace` from the report and use that namespace for initialization and clearing. Link the object and `releaseguard_native_code.cpp` with the application's C++17 code and `-lcrypto`.

```cpp
#include "releaseguard_native_code.hpp"
extern "C" unsigned rg_compute(unsigned);

// Define RG_CODE_NAMESPACE from report.json's code_seal.cpp_namespace.
namespace protected_code = RG_CODE_NAMESPACE;

bool run_computation(const releaseguard::native_asset_key& external_key,
                     unsigned input, unsigned& result) {
    if (!protected_code::initialize_native_code(external_key)) return false;
    result = rg_compute(input);
    protected_code::clear_native_code();
    return true;
}
```

An application source containing this integration can select the generated namespace at build time.

```sh
RG_CODE_NAMESPACE="$(python -c 'import json; print(json.load(open("sealed-function/report.json"))["code_seal"]["cpp_namespace"])')"
c++ -std=c++17 -O2 -Isealed-function \
  "-DRG_CODE_NAMESPACE=$RG_CODE_NAMESPACE" your_application.cpp \
  sealed-function/releaseguard_native_code.cpp sealed-function/protected.o \
  -lcrypto -o application
```

Initialize with exclusive ownership before starting workers. Clear after all workers have joined. A failed reinitialization revokes the previous VM storage. Separate generated modules use separate namespaces, ready flags and owned mappings. The caller owns the external key's lifetime and cleanup. Run the existing `scan-release --asset-key-file` check against the final release staging directory. [Release-key check](native-assets.md)

### Protected mapping lifecycle

1. Initialization clears the previous ready flag and storage bindings, then releases the old mapping. It allocates a page-rounded anonymous payload between inaccessible guard pages and requires successful `mlock` and `MADV_DONTDUMP` operations. The Linux loader also requires `MADV_WIPEONFORK` before decryption. Failure to acquire a required protection leaves initialization unsuccessful.
2. `open_native_asset_into` decrypts directly into this mapping. The generated loader uses that allocation throughout authentication, length checking and SHA-256 verification, avoiding a complete plaintext `std::vector` intermediate.
3. After all checks pass, the loader requires a successful change to read-only access. It then binds each VM storage pointer at its aligned `offset_bytes` and sets ready last. The mapping requests data-page permissions throughout its lifetime.
4. `clear_native_code` clears ready and revokes every storage pointer before releasing the mapping. Cleanup restores write permission, wipes the page-rounded payload, unlocks it and unmaps the reservation. If restoring write permission fails, cleanup still unlocks and unmaps the allocation. An explicit userspace wipe cannot be guaranteed on that failure path.

After `fork`, the child inherits zero-filled VM storage through `MADV_WIPEONFORK`. The required nonzero descriptor guards keep child computations locked until the child initializes its own mapping. The parent continues using its authenticated mapping. Initialization and clearing require exclusive ownership in each process.

During an authorized session the mapping contains readable plaintext VM instructions and descriptors. Locking, dump exclusion, guard pages and read-only access govern the allocation's OS behavior. A process-memory reader with sufficient access can still obtain the authorized contents. Dump exclusion applies to cooperating OS dump mechanisms.

VM profiles reject `--seed`. The sealed profile creates fresh authenticated encryption parameters and randomized descriptor guards. Reports record build identities and coverage, while application-specific functional and recovery evaluations retain their own result fields.

## Build the pinned plugin

The integration was tested with Ubuntu LLVM 18.1.3 and eshard/obfuscator-llvm commit `be910da9267b40cbe6ae8c946eb2ef008f6e55f4`. The upstream plugin uses the University of Illinois/NCSA license. Preserve its license and notices when redistributing it. [Pinned upstream source](https://github.com/eshard/obfuscator-llvm/tree/be910da9267b40cbe6ae8c946eb2ef008f6e55f4)

On Ubuntu 24.04, install LLVM 18 development packages, a C++ compiler and CMake, then build the plugin from the recorded revision.

```sh
sudo apt-get install clang-18 llvm-18-dev cmake
git clone https://github.com/eshard/obfuscator-llvm.git obfuscator-llvm
git -C obfuscator-llvm checkout --detach be910da9267b40cbe6ae8c946eb2ef008f6e55f4
cmake -S obfuscator-llvm -B obfuscator-build \
  -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR=/usr/lib/llvm-18/lib/cmake/llvm
cmake --build obfuscator-build --parallel 2
python -m pip install .
```

`opt` and `llc` must report the same LLVM 18 numeric version. The input, plugin, toolchain and build parent directories must be trusted and stable. Loading an LLVM plugin executes native code in the build process. `--plugin-sha256` is the expected digest established from the builder's verified plugin artifact.

## Transform a dedicated translation unit

Given an existing project with `sensitive.cpp` and `main.cpp`, compile the selected unit to optimized bitcode. The example assumes its C-linkage function is named `rg_compute`. Use the LLVM linkage name for C++ functions, including their mangled name when applicable.

```sh
export RG_LLVM_BIN=/usr/lib/llvm-18/bin
export RG_PLUGIN="$PWD/obfuscator-build/libLLVMObfuscator.so"
export RG_PLUGIN_SHA="$(sha256sum "$RG_PLUGIN" | cut -d ' ' -f 1)"

"$RG_LLVM_BIN/clang++" -O2 -fPIC -g0 \
  -fno-unroll-loops -fno-vectorize -fno-slp-vectorize \
  -emit-llvm -c sensitive.cpp -o sensitive.bc

python -m releaseguard native-obfuscate \
  --input sensitive.bc --out protected-function \
  --llvm-bin "$RG_LLVM_BIN" \
  --plugin "$RG_PLUGIN" --plugin-sha256 "$RG_PLUGIN_SHA" \
  --function rg_compute --profile split-flatten-substitution \
  --seed 25a1a5627b7c435c807caf102f4e4c31

"$RG_LLVM_BIN/clang++" -O2 main.cpp protected-function/protected.o -o application
```

The output directory must be new. A successful build writes `protected.o` and `report.json`. Temporary input and transformed IR copies are removed when the command returns. The object contains machine code, so subsequent linking keeps the protected unit outside any link-time LLVM IR optimization pipeline.

The optional build seed is exactly 32 hexadecimal digits. Omitting it generates a seed and records it in the report. Repeated builds with the same input, compiler, plugin and seed were checked for identical normalized IR and object hashes. Inherited `LLVM_OBF_*` variables are cleared before execution.

## Required coverage and failure behavior

The command checks the input and plugin digests, parses and verifies IR through the real `opt`, checks supported target triples and function bodies, and invokes the recorded pass pipeline. Control-flow profiles require each requested function's body to change and acquire a new dispatcher. VM profiles require a replacement wrapper, connected private runtime and bytecode/descriptor storage, and absence of a normalized copy of the original function body. The sealed profile requires VM coverage for every retained original function. A requested function that is absent or silently skipped causes a build error. Generated objects must be relocatable ELF of the requested x86 class and machine type.

The supported scope is intentionally explicit.

- Exception-handling instructions, indirect terminators, `callbr`, coroutine instructions, `musttail`, `blockaddress`, and unsupported function attributes cause rejection.
- The `flatten` profile requires at least two basic blocks in every requested function.
- A multi-block function must have a branch or switch terminator in its entry block. An upstream defect changed a legal function returning `9` into one returning `27` by redirecting entry into an unreachable block. Both profiles now have a real LLVM regression test for rejecting this input.
- The arithmetic profile accepts scalar integer and pointer IR with integer widths of 1, 8, 16, 32 or 64 bits. Vector and floating-point IR, explicit `undef`, `poison`, `freeze`, atomic read-modify-write operations, fences and vararg instructions cause rejection.
- Preflight checks cover the whole input unit because the plugin can transform unrequested functions. Control-flow profiles allow unrequested `optnone` functions to remain unchanged. Requested `optnone` functions and every `optnone` function in a VM input unit cause rejection.
- Input, plugin, normalized IR and generated object sizes each have a 64 MiB budget. Tool processes have finite timeouts. Input identity changes and output-directory races abort publication.

Build reports contain per-function hashes, basic-block counts, coverage flags, tool versions, plugin digest, seed and object digest. The following fields preserve the evaluations still needed for the particular application.

```json
{
  "transformation_applied": true,
  "functional_evaluation": "not_performed",
  "recovery_evaluation": "not_performed"
}
```

## Actual function recovery experiment

The evaluation uses a project-owned `uint32_t rg_compute(uint32_t)` function with generated constants, branches, rotations and a bounded loop. The baseline and transformed objects are linked into the same stdin/stdout driver. Source, IR, test inputs and expected outputs stay outside the materials supplied to an independent recovery worker.

The initial two transformed programs each matched the original on 81,924 inputs. Ghidra 12.2 then completed its normal automatic analysis on the exact recorded ELF files. The function probe verified original file bytes, loaded memory bytes and decoded instruction coverage.

| Build | Recognized instructions | CFG blocks | Undecoded target bytes |
| --- | --- | --- | --- |
| Baseline | 43 | 13 | 0 |
| Flatten | 144 | 36 | 0 |
| Split, flatten and substitution | 224 | 57 | 0 |

The baseline, combined split/flatten/substitution build and an Amice instruction-virtualized build were independently reconstructed as ordinary C. Each submitted implementation matched all 1,081,924 hidden evaluations. The VM reconstruction took 310 seconds in this attempt and used original-file disassembly to supplement the decompiler output. The production `virtualize` wrapper subsequently reproduced the exact VM object and ELF hashes used in that experiment. [Observation and hashes](results/native-code-recovery.json) · [Published source and independent reconstructions](../benchmarks/function_recovery/README.md)

The VM run completed 24 decompiler API calls. Fourteen functions contained diagnostics, including one unrecovered jump table, one indirect jump treated as a call and six truncated control-flow reports. The function runner now records these warnings per function. Its whole-program inventory includes every recognized function, complete initialized memory and a byte-identical ELF, which also permits an analyst to inspect code absent from the recognized-function inventory.

In-process measurements on this source instance used three warmups and seven samples of one million dependent calls. Median time per call was 16.91 ns for the baseline, 35.24 ns for flattening, 47.34 ns for the combined profile and 4,425.94 ns for virtualization. The report retains every sample and matching checksums. The intervals include loop arithmetic and exclude process startup, compilation and output.

Recovery success requires a separately compiled implementation that produces the correct outputs on private reference inputs and independently generated additional inputs. Analyzer failures, incomplete dependencies, timeouts and unfinished reconstructions remain separate recorded outcomes. Complete initialized data and helper functions must accompany a virtualized function when evaluating recovery of its behavior.

The pinned upstream implementation describes control-flow flattening and arithmetic substitution. Their actual resistance depends on the resulting program and the reconstruction procedure. The upstream Obfuscator-LLVM FAQ also discusses limits against skilled reverse engineering. [eshard plugin](https://github.com/eshard/obfuscator-llvm) · [Obfuscator-LLVM FAQ](https://github.com/obfuscator-llvm/obfuscator/wiki/FAQ)

## Historical sealed-code observations and hardening

The first encrypted-code sample underwent an independent reconstruction attempt using only its ELF, genuine Ghidra exports, generated public loader files and the open protection implementation. The worker followed an instruction-enforced input allowlist on a shared filesystem. It tried 247,070 distinct candidate keys as both master keys and package keys, for 494,140 authentication attempts, with zero successful decryptions. It recovered one eight-byte descriptor guard from a public reversible check. The root evaluator confirmed that value against the private decrypted payload. [Initial automated controls](results/native-code-sealed-initial.json) · [Initial independent assessment](results/native-code-sealed-review-initial.json)

The v1 repair replaced each descriptor guard with an independent nonzero random word and sealed its expected comparison value in another storage array. The runtime requires a matching nonzero value. The recorded private-payload check confirmed that the recovered word differed from the repaired v1 payload. Cleared-state tests forced ready to one and verified that the function still returned zero. Actual compiler regressions also covered retained globals, module assembly, dropped prologue instructions, linker metadata, arbitrary source filenames and compiler-identification strings. [Historical hardening record](results/native-code-hardening.json)

The repaired v1 source instance was rebuilt and analyzed again by Ghidra 12.2 on 2026-11-09. Every case's allocated file bytes were validated against the original ELF. The encrypted ELF has SHA-256 `d4586625d21eb6e870cd7a15a121ac60c0885289019ef1a2bcd03b809c8e2a90`. The following results describe that historical sample. The v2 protected-mapping implementation has its own validation status below.

| Case | Distinct contiguous 32-byte candidates | Successful key decryptions | Functional result with the correct key |
| --- | --- | --- | --- |
| Plaintext VM | 23,842 | 0 | All 82,014 evaluations matched |
| Encrypted VM with an external key | 30,982 | 0 | All 82,014 evaluations matched |
| Same encrypted VM with its key deliberately embedded | 31,046 | 1 | Recovered key replay matched all 82,014 evaluations |

Replacing the externally visible gate with a successful return produced locked zero outputs for the encrypted case. Every one of its 82,014 values differed from the private function reference. The forced GCM-final-success control still rejected a wrong key, while the correct key produced all reference outputs. Recompiled ciphertext-tamper and wrong-context controls both rejected initialization. These automated observations cover the exact procedures in `benchmarks/sealed_code_controls.py`. [Repaired-sample results](results/native-code-sealed-controls.json)

A second independent reconstruction subtask for the repaired v1 sample was blocked by the execution layer's automatic safety review for possible cybersecurity risk. Its post-fix reconstruction status is incomplete. Actual modern IDA 9.x/Hex-Rays execution remains pending. The prior IDA 5.0 data experiment retains its separate i386 sample and scope. [Modern IDA adapter](../benchmarks/ida_function/README.md)

Additional real LLVM execution checked 24 signed/unsigned multiplication, division, remainder, shift, comparison and switch functions at 32 and 64 bits. All 26,264 defined input pairs matched the ordinary LLVM baseline. The five-width regression matrix separately covers i1, i8, i16, i32 and i64. [Arithmetic observations](results/native-code-integer-semantics.json)

## Protected-mapping validation status

Machine-readable results record the source hashes, exact local toolchain and remaining engine coverage. [Protected-mapping results](results/native-code-memory.json)

The v2 mapping implementation completed the following local and CI checks.

| Check | Completed result |
| --- | --- |
| Generated-loader tests with LLVM 19.1.7 C API | 13 compiled tests passed, with 8 IR modules parsed, verified and emitted as PIC objects |
| `secure_buffer` regressions | 16 tests passed |
| Native asset reader and direct-buffer decryption regressions | 21 tests passed |
| IDA report adapter and validator | 10 engine-independent tests passed |
| Mandatory LLVM 18/Amice regression suite in the first v2 CI | 145 tests passed with zero skips |
| Full CI matrix | Nine jobs passed, including Windows native tests and genuine Ghidra analysis |

The LLVM 19 experiment replaced only the compiled test class's object-emission method. It retained the real C++ compiler, linker, loaded functions and existing assertions. Its coverage includes aligned read-only, locked and dump-excluded storage, process-write faults, revoked bindings, cleanup, integer ABIs, forked-child zeroing, both global-object link orders, ten loader OS-failure scenarios and mixed-layout link rejection. The IDA validator now requires every completed function's entry to belong to its verified byte ranges and to match a verified instruction start. [Loader regressions](../tests/test_native_code_seal.py) · [Memory regressions](../tests/test_secure_buffer.py) · [IDA validator regressions](../benchmarks/ida_function/test_validation.py)

The preserved v2 Ghidra controls were built from commit `f8f9df6528cd1a1e2a996ca657a74df7a8a08f18` in the first successful CI run for this change. The encrypted ELF has SHA-256 `06a7beea6437001a73d5a6cb0ddefec82c11041d008b5416d08d5ef502fe73e0`. Each case evaluated 82,014 inputs, containing 81,968 distinct values. [CI run](https://github.com/Afloat16/anti-rea-forge/actions/runs/44092281985) · [Preserved v2 controls](results/native-code-memory-controls.json)

| v2 case | Distinct contiguous 32-byte candidates | Successful key decryptions | Correct-key output differences |
| --- | --- | --- | --- |
| Plaintext VM | 23,268 | 0 | 0 |
| Encrypted VM with external key | 34,646 | 0 | 0 |
| Deliberately embedded-key control | 34,711 | 1 | 0 |

The recovered control key reproduced all 82,014 reference outputs. Patching the outer gate with a wrong key left all encrypted outputs locked at zero. Forced GCM-final success with a wrong key, modified ciphertext and wrong context were rejected. Ghidra completed its decompilation API for 136 recognized functions in each encrypted program, with warnings retained in the raw report. This API count describes returned decompiler objects.

A subsequent validation regression rejects `speculatable` helpers and affected callers, because nullable storage bindings invalidate that promise. The machine-readable record binds the final local source hashes separately from the preserved CI sample. [Memory-mapping change and CI](https://github.com/Afloat16/anti-rea-forge/pull/9)

Modern IDA/Hex-Rays engine execution and independent reconstruction of v2 remain pending. The historical recovery records above retain their original sample identities and outcomes.
