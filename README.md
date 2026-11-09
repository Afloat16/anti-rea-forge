# Anti-REA Forge v0.10.0

[English](README.md) · [简体中文](README.zh-CN.md) · [MIT license](LICENSE)

**Ship encrypted native data and supply its key independently to authorized users.**

Anti-REA Forge now opens authenticated data in C++17 with OpenSSL. The build receives a sealed envelope and the application's expected context. A separately supplied random 256-bit key is required to recover the data. Release checks catch accidental inclusion of that key in common representations.

## Can Ghidra and IDA recover the embedded data?

Both tools analyzed the same three complete Linux i386 executables generated for this project. Each executable can return the same fresh 32-byte resource when given the correct key. The observer checks exact output bytes and verifies every allocated, file-backed ELF section exported through the analyzer database.

| Program supplied | Ghidra 12.2 | IDA Freeware 5.0 |
| --- | --- | --- |
| Original resource embedded as plaintext | Recovered original data | Recovered original data |
| Encrypted resource, key kept outside the release | Zero successful data or key recoveries | Zero successful data or key recoveries |
| Encrypted resource with the actual key deliberately embedded | Recovered key, replayed it against the program and read original data | Recovered key, replayed it against the program and read original data |

The extraction procedure tries every distinct contiguous 32-byte candidate in the exported initialized bytes against the public envelope. Ghidra decompiles the gate and IDA disassembles it. IDA's documented additional-file loading API supplements metadata ranges omitted by its default ELF loader. Each added range is recorded, and every resulting byte is checked against the input. [Paired observations](docs/results/native-asset-controls.json) · [Reproduction and loader settings](docs/native-assets.md#reproduce-the-native-controls)

## Does patching the program recover the data?

The harness patches the gate address discovered independently by each tool. With the wrong key, the plaintext control returns the original data after patching. The encrypted program returns no data.

A second fixture-only override forces OpenSSL's final authentication check to report success. The encrypted program then exits successfully and emits 32 bytes, but their SHA-256 differs from the original resource. Supplying the actual key to that same modified program still returns the exact original. The intentionally embedded-key release also triggers the production `asset_key_exposure` check. [Native experiment](benchmarks/native_asset_controls.py)

The protection target is selected data with an independently held key. The executable's instructions remain available for analysis. During legitimate use, the process possesses both the key and plaintext. The recorded results cover the stated tools, Linux i386 fixtures and extraction/patch procedures. [Design references and scope](docs/research-native-data-2026-11-09.md)

## Use it in a native build

Run from this repository on a Linux build machine with Python 3.10+, a C++17 compiler and OpenSSL development files. This example assumes your private `../asset-issuer` directory already contains `data.bin`, with a maximum size of 1 MiB. Use fresh output paths.

```sh
python -m pip install .
python -m releaseguard asset-keygen --out ../asset-issuer/key.bin
python -m releaseguard asset-seal ../asset-issuer/data.bin \
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

The last command outputs the original resource. In your application, include the generated header and call `releaseguard::open_embedded_asset(external_key, output)`. Deliver the key through your authorization flow and keep the issuer directory private. Run `scan-release --asset-key-file` on the final staging directory before publication. [Complete integration and release-check commands](docs/native-assets.md)

The recorded 1 MiB opening-cost test measured a median of **189.860 microseconds** across 25 calls after five warmups on one Linux x86-64 host. It includes HKDF, AES-GCM, allocations and cleansing the previous output. External-key retrieval and process startup are outside the measurement. The full report retains all samples, including the 1,456.005-microsecond maximum. [Timing record](docs/results/native-asset-cost.json)

Existing integrations cover private ELF debugging information, service-side authorization, external C++ unlock tokens and JavaScript source maps. [Private ELF symbols and service operations](docs/private-elf-debug.md) · [Native tokens](docs/native-tokens.md) · [Private source maps](docs/private-source-maps.md)

If this solves a release problem for your team, **star the project** or contribute a reproducible fixture of your own. [Contributing](CONTRIBUTING.en.md)
