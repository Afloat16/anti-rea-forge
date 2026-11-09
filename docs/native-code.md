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

The `sealed-virtualize` profile converts self-contained scalar-integer functions into a VM representation and encrypts the bytecode, descriptor records and randomized descriptor guards. The release contains zero-initialized VM storage. A separately delivered random 32-byte key opens the complete authenticated payload, verifies its length and SHA-256, initializes every storage region, and finally enables the wrappers. Each locked wrapper returns zero. The application must check the initialization result because zero can also be a valid function result.

The protection target is the release before external key delivery. An authorized process holds plaintext VM instructions and descriptors. A reader of that process memory can obtain them. Public ABI, interpreter operations, program sizes and format metadata remain observable. The current implementation supports independent scalar-integer computation units with widths 1, 8, 16, 32 and 64. Original globals, module-level assembly, external native calls, pointers, vectors, floating-point operations and unsupported ABI attributes cause a build failure.

Use the official Amice LLVM 18 Linux artifact below. Its source revision is `19b6c473ee8a59d66a91d3b7c2d460bb6af7c99e`, released as `v0.1.6-beta.1` under Apache-2.0. The integration clears inherited `AMICE_*` and `LLVM_OBF_*` configuration and selects the built-in VM profile with a module runtime. [Pinned Amice source](https://github.com/fuqiuluo/amice/tree/19b6c473ee8a59d66a91d3b7c2d460bb6af7c99e)

```sh
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

The new directory contains `protected.o`, `report.json` and four generated headers/sources. Read `code_seal.cpp_namespace` from the report and use that namespace for initialization and clearing. Link the object and `releaseguard_native_code.cpp` with the application's C++17 code and `-lcrypto`.

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

Initialize with exclusive ownership before starting workers. Clear after all workers have joined. A failed reinitialization clears the previous VM storage. Separate generated modules use separate namespaces, ready flags and storage. The caller owns the external key's lifetime and cleanup. Run the existing `scan-release --asset-key-file` check against the final release staging directory. [Release-key check](native-assets.md)

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

The command checks the input and plugin digests, parses and verifies IR through the real `opt`, checks supported target triples and function bodies, invokes the recorded pass pipeline, and verifies each requested function's body change and newly introduced dispatcher. A requested function that is absent or silently skipped causes a build error. Generated objects must be relocatable ELF of the requested x86 class and machine type.

The supported scope is intentionally explicit.

- Exception-handling instructions, indirect terminators, `callbr`, coroutine instructions, `musttail`, `blockaddress`, and unsupported function attributes cause rejection.
- The `flatten` profile requires at least two basic blocks in every requested function.
- A multi-block function must have a branch or switch terminator in its entry block. An upstream defect changed a legal function returning `9` into one returning `27` by redirecting entry into an unreachable block. Both profiles now have a real LLVM regression test for rejecting this input.
- The arithmetic profile accepts scalar integer and pointer IR with integer widths of 1, 8, 16, 32 or 64 bits. Vector and floating-point IR, explicit `undef`, `poison`, `freeze`, atomic read-modify-write operations, fences and vararg instructions cause rejection.
- Preflight checks cover the whole input unit because the plugin can transform unrequested functions. Unrequested `optnone` functions may remain unchanged. A request for an `optnone` function fails.
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

## Sealed-code observations and hardening

The first encrypted-code sample underwent an independent reconstruction attempt using only its ELF, genuine Ghidra exports, generated public loader files and the open protection implementation. The worker followed an instruction-enforced input allowlist on a shared filesystem. It tried 247,070 distinct candidate keys as both master keys and package keys, for 494,140 authentication attempts, with zero successful decryptions. It recovered one eight-byte descriptor guard from a public reversible check. The root evaluator confirmed that value against the private decrypted payload. [Initial automated controls](results/native-code-sealed-initial.json) · [Initial independent assessment](results/native-code-sealed-review-initial.json)

The sealer now replaces each descriptor guard with an independent nonzero random word and seals its expected comparison value in another storage array. The runtime requires a matching nonzero value. The old recovered word differs from the new private payload. Cleared-state tests force ready to one and verify that the function still returns zero. Actual compiler regressions also cover retained globals, module assembly, dropped prologue instructions, linker metadata, arbitrary source filenames and compiler-identification strings. [Hardening record](results/native-code-hardening.json)

The repaired source instance was rebuilt and analyzed again by Ghidra 12.2. Every case's allocated file bytes were validated against the original ELF.

| Case | Distinct contiguous 32-byte candidates | Successful key decryptions | Functional result with the correct key |
| --- | --- | --- | --- |
| Plaintext VM | 23,842 | 0 | All 82,014 evaluations matched |
| Encrypted VM with an external key | 30,982 | 0 | All 82,014 evaluations matched |
| Same encrypted VM with its key deliberately embedded | 31,046 | 1 | Recovered key replay matched all 82,014 evaluations |

Replacing the externally visible gate with a successful return produced locked zero outputs for the encrypted case. Every one of its 82,014 values differed from the private function reference. The forced GCM-final-success control still rejected a wrong key, while the correct key produced all reference outputs. Recompiled ciphertext-tamper and wrong-context controls both rejected initialization. These automated observations cover the exact procedures in `benchmarks/sealed_code_controls.py`. [Repaired-sample results](results/native-code-sealed-controls.json)

A second independent reconstruction subtask was blocked by the execution layer's automatic safety review for possible cybersecurity risk. Its post-fix reconstruction status is incomplete. The modern IDA 9.x adapter passed eight engine-independent tests, with actual IDA/Hex-Rays execution pending because this workspace has no runnable compatible engine. The prior IDA 5.0 data experiment retains its separate sample and scope. [Modern IDA adapter](../benchmarks/ida_function/README.md)

Additional real LLVM execution checked 24 signed/unsigned multiplication, division, remainder, shift, comparison and switch functions at 32 and 64 bits. All 26,264 defined input pairs matched the ordinary LLVM baseline. The five-width regression matrix separately covers i1, i8, i16, i32 and i64. [Arithmetic observations](results/native-code-integer-semantics.json)
