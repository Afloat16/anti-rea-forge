# Native encrypted data assets

Seal selected data before compilation and deliver its random 256-bit key independently to an authorized application. The generated C++17 headers embed the ciphertext, salt, nonce and trusted application context. Opening the asset uses OpenSSL HKDF-SHA256 and AES-256-GCM, with authentication checked before plaintext is returned.

The format is the existing `open-release-guard-sealed-asset/v1` Python format. Each plaintext asset can contain up to 1 MiB. The native reader accepts a caller-supplied raw 32-byte key. The application chooses how an authorized user obtains that key and how it consumes the decrypted data.

## Build the example

Run these commands from the repository root on Linux with Python 3.10+, a C++17 compiler and OpenSSL development headers and libcrypto. Use a new directory for each generated output. The input in this example is a small project-owned text resource.

```sh
python -m pip install .
mkdir -m 700 ../asset-issuer
python -c 'from pathlib import Path; Path("../asset-issuer/data.txt").write_text("private reference data\n", encoding="utf-8")'
python -m releaseguard asset-keygen --out ../asset-issuer/key.bin
python -m releaseguard asset-seal ../asset-issuer/data.txt \
  --key-file ../asset-issuer/key.bin \
  --product myapp --release v1 --purpose reference-data --asset-id table \
  --out asset.json
python -m releaseguard native-asset-export asset.json \
  --product myapp --release v1 --purpose reference-data --asset-id table \
  --out generated-asset
mkdir release-asset
c++ -std=c++17 -O2 -Igenerated-asset examples/native-asset/read.cpp \
  -lcrypto -o release-asset/read-asset
./release-asset/read-asset < ../asset-issuer/key.bin
```

The last command prints the original data. The example uses binary stdin for the key and binary stdout for the result. It exits with status `0` after successful authenticated output, `3` for authentication failure and `2` for invalid input or an I/O error. Replace its stdout consumer with the application's data-processing code. [Complete example](../examples/native-asset/read.cpp)

| Material | Location and use |
| --- | --- |
| `key.bin` and original data | Private issuer environment, with controlled access |
| `asset.json` | Public sealed envelope passed to the build |
| `generated-asset/releaseguard_asset.hpp` | Generated public arrays and `open_embedded_asset` wrapper |
| `generated-asset/releaseguard/sealed_asset.hpp` | Shared native HKDF/AES-GCM reader |
| `release-asset/read-asset` | Deployable example, plus the matching libcrypto runtime dependency |

The issuer performs `asset-seal` with the key. The build performs `native-asset-export` using only the envelope and the expected context. These steps can run in separate environments. Export validates the envelope's structure. Authentication happens when the native reader receives the external key.

Keep all four context values fixed by trusted application configuration. Changing the product, release, purpose or asset identifier causes authentication to fail. The identifiers use the existing format's NFC and length rules. This native profile additionally limits the complete HKDF info to 1,024 bytes. [Format implementation](../src/releaseguard/sealed.py)

## Call the reader

```cpp
#include "releaseguard_asset.hpp"

bool read_reference(const releaseguard::native_asset_key& external_key,
                    std::vector<unsigned char>& plaintext) {
    return releaseguard::open_embedded_asset(external_key, plaintext);
}
```

The generic `open_native_asset(key, view, output)` entry accepts a `native_asset_view` containing the salt, nonce, ciphertext and expected AAD. The generated header creates this view. Its asset arrays and wrapper have translation-unit-local linkage. Include one generated asset header per translation unit. Different translation units can use different generated assets and expose application-specific wrapper names.

At the start of a call, the reader cleanses and clears any previous output. It decrypts into temporary storage, checks every EVP operation and the final GCM tag, then returns the authenticated bytes. An authentication failure returns `false` with an empty output. Allocation failures follow the C++ allocator's exception behavior. The caller owns the input key and successful output, including their lifetime and cleanup. [Native reader](../src/releaseguard/data/include/releaseguard/sealed_asset.hpp)

For CMake, add the generated directory as a private include path and link `OpenSSL::Crypto` after `find_package(OpenSSL REQUIRED COMPONENTS Crypto)`. The checked native interoperability environment uses GCC and OpenSSL 3 on Linux. Python CLI and release scanning also run in the project's Windows test matrix.

## Check the final release for an accidentally included key

Use the key only on the trusted release-checking machine. The optional `--asset-key-file` argument checks the final staging directory against that exact key and can be repeated for up to 16 keys.

```sh
python -c 'from pathlib import Path; Path("asset-policy.json").write_text("{\"version\":1}\n", encoding="utf-8")'
python -m releaseguard scan-release \
  --root release-asset --policy asset-policy.json \
  --asset-key-file ../asset-issuer/key.bin
```

The checker searches physical files and supported nested ZIP members, including matches across read chunks. It checks raw key bytes, lowercase and uppercase hexadecimal, standard and URL-safe Base64 with or without padding, and each textual representation in UTF-8, UTF-16 LE/BE and UTF-32 LE/BE. A match creates an `asset_key_exposure` finding. Reports include the path, key index and encoding while keeping matched key contents out of findings. The command exits `3` on release findings and `2` on invalid inputs.

The Python API exposes the same optional argument.

```python
from releaseguard.distribution import scan_release

report = scan_release(
    "release-asset", "asset-policy.json",
    asset_key_files=["../asset-issuer/key.bin"],
)
```

These are exact-representation checks. Fragmented keys, mixed-case hexadecimal, source-language byte lists and transformed values require additional project-specific checks. Use trusted, stable paths for issuer files and the release snapshot. A key copied into a filename can also become visible in a report path.

## Reproduce the native controls

The paired ELF32 run completed with Ghidra 12.2 and IDA Freeware 5.0.0.879. Both recovered the plaintext control and the intentionally embedded key, including a successful native replay. For the encrypted-only program, Ghidra tested 18,024 distinct contiguous 32-byte candidates and IDA tested 18,121. Both recorded zero exact payload recoveries. The same programs passed the actual patch and forced-authentication-success comparisons. [Machine-readable observation](results/native-asset-controls.json) · [Completed workflow](https://github.com/Afloat16/anti-rea-forge/actions/runs/42624953223)

The fixture generator creates three complete programs with fresh synthetic values. One contains the original 32-byte data, one contains only its encrypted representation, and one deliberately includes the actual key. All three accept the legitimate key and return the exact original bytes. A public decoy verifies that each analyzer can read ordinary 32-byte data.

Each analyzer receives only an isolated program and the extraction script. The script locates the exported gate itself and exports initialized database bytes. A separate verifier checks the bytes against the ELF mappings and requires coverage of every allocated, file-backed section. It joins adjacent blocks and tries every distinct contiguous 32-byte window as a payload and as a decryption key. A recovered key must open the public envelope and succeed against the unmodified native program.

The patch experiment modifies the gate entry reported by each tool. A second control uses a fixture-only `LD_PRELOAD` override to force `EVP_DecryptFinal_ex` to return success. The observer records the actual output hash, exit status and a correct-key control. Exact payload recovery is the success criterion.

On Linux, install the project, JDK 25, GNU binutils, g++ and OpenSSL development files. For the paired experiment also install the i386 C++ and libcrypto development/runtime packages. On Ubuntu 24.04 these include `g++-multilib` and `libssl-dev:i386` after enabling the i386 package architecture. Download the official Ghidra 12.2 archive. The runner verifies its pinned SHA-256 before extraction.

```sh
python benchmarks/native_asset_controls.py prepare asset-corpus --bits 32
python benchmarks/native_asset_controls.py ghidra asset-corpus \
  --archive /path/to/ghidra_12.2_PUBLIC_20261016.zip \
  --out ghidra-assets.json
```

For Ghidra-only x86-64 reproduction, use `--bits 64`. CI runs that variant on every pull request and on main. The paired historical IDA experiment uses the same ELF32 files produced above. [Native fixture runner](../benchmarks/native_asset_controls.py)

On a Windows test host with the pinned, legitimately installed IDA Freeware 5.0 build, set `RG_IDA_BIN` to its `idag.exe` and `RG_IDA_CONFIRM_FREEWARE=1` after checking that your noncommercial use meets its license. Run one IDA instance at a time. Copy the three public `app` files to this host and create an `ida-reports` directory.

```powershell
python benchmarks/sealed_native/ida_asset_probe.py asset-corpus/plaintext/app ida-reports/plaintext.json
python benchmarks/sealed_native/ida_asset_probe.py asset-corpus/encrypted/app ida-reports/encrypted.json
python benchmarks/sealed_native/ida_asset_probe.py asset-corpus/key_leak/app ida-reports/key_leak.json
```

Return the three reports to the Linux host with the original corpus. The verifier uses the private test-driver values to check exact outcomes and emits a compact report that omits extracted raw blocks.

```sh
python benchmarks/native_asset_controls.py ida asset-corpus \
  --observations ida-reports --out ida-assets.json
python benchmarks/native_asset_controls.py compare \
  --ghidra ghidra-assets.json --ida ida-assets.json \
  --out native-asset-controls.json
```

Ghidra runs automatic analysis and decompiles the gate. IDA 5.0 runs automatic analysis and disassembles it. To preserve original ELF bytes for exact comparison, the Ghidra loader uses `applyRelocations=false`, and the IDA loader uses `IDA_NORELOC=1` and `IDA_ELF_PATCH_MODE=0`. IDA 5.0 omits some ELF metadata by default. The IDC adapter reads the input's bounded program-header table and uses IDA's documented segment creation and `loadfile` APIs to import only missing file-backed `PT_LOAD` ranges into its database. Existing loaded bytes are preserved. The report records each added address range and file offset, and the final extraction reads bytes back through IDA's `Byte` API. Its synthetic external-symbol segment is recorded separately. The coverage checker continues to require all original allocated file-backed sections. [Ghidra extraction](../benchmarks/sealed_native/ExtractAssetBytes.java) · [IDA adapter](../benchmarks/sealed_native/ida_asset_probe.py) · [Shared byte verifier](../benchmarks/sealed_native/elf_bytes.py) · [IDA loader options](https://docs.hex-rays.com/8.4/user-guide/user-interface/menu-bar/windows/environment-variables)

## Cost and scope

The recorded Linux x86-64 measurement opens a synthetic 1 MiB asset in the same process, with five warmups and 25 measured calls. The median is 189.860 microseconds, with a minimum of 188.698 and maximum of 1,456.005. Each result is compared with the full reference plaintext after the timed operation. The measurement includes HKDF, AES-GCM, allocations and cleansing the previous output. Process startup, external-key retrieval, compilation and output comparison are outside the timed interval. Compiler, library, host and all samples are recorded. Run `python benchmarks/native_asset_cost.py --out native-asset-cost.json` to measure your own host. [Timing record](results/native-asset-cost.json)

The confidential object here is selected data whose random key stays outside the public release. The executable's instructions remain available for analysis. During legitimate use, the process possesses the key and plaintext, so a process owner can inspect them. The recorded extraction and patch controls apply to the stated tool versions, fixtures and procedures. Supporting arbitrary program logic, licensed-user memory inspection or a different IDA version would require their own design and evaluation. [Open-source design references](research-native-data-2026-11-09.md)
