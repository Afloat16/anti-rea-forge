# Anti-REA Forge v0.9.0

[English](README.md) · [简体中文](README.zh-CN.md) · [MIT license](LICENSE)

**Ship native code with private debug symbols kept in-house. Keep restricted operations behind a service you control.**

A user can patch a local client to report success. Anti-REA Forge separates private symbol metadata at build time and lets a Python service require a one-use signed capability before calling a sensitive handler. The programs, credentials and services below are project-owned simulations. Both analysis tools ran on the same three ELF files.

## Can the analyzers recover the developer's function name?

We gave each analyzer the private function address so it could inspect the same instructions in every case. The source identifier contained a fresh random value. A separate public entry remained exported for both tools to locate independently.

| Linux i386 ELF supplied | Ghidra 12.2 | IDA Freeware 5.0 |
| --- | --- | --- |
| Original symbols and debugging information | Exact source name | Exact source name |
| Public ELF alone | `FUN_08049000` | `sub_8049000` |
| Public ELF with just the name restored from the private debug file | Exact source name again | Exact source name again |

The three programs had identical `.text` hashes and gave identical results for three inputs. Ghidra decompiled the function and IDA disassembled it. An analyst can still infer behavior from the instructions. This control measures recovery of the developer's exact name from the distributed metadata. [Paired tool observations](docs/results/native-elf-controls.json)

## Can a patched client perform a restricted operation?

Both tools located the same exported entry by name. At each tool's reported address, the harness patched six bytes in a disposable copy. Its return code changed from `39` to the fixture's approval value, `42`. Two separate service processes then exercised different trust policies. The harness verified the signature on every receipt.

| Service decision | Observed outcome |
| --- | --- |
| Trust the client status | The original client was denied. The patched client obtained a signed receipt. |
| Verify on the service, with a missing grant, an attacker-signed grant or a changed request | All three attempts produced zero handler calls. |
| Verify a genuine capability for the exact request from the same patched client | One signed receipt. Reusing that capability was denied. |

Run the restricted operation on an independently controlled service. An offline client can still be patched. The joint observation covers these tool versions and project-owned 32-bit x86 fixtures. [Design and reproduction](docs/private-elf-debug.md#reproduce-the-two-engine-observation)

## Use it in a build

Install on a Linux build machine with GNU binutils and Python 3.10+. This example assumes you have a linked, symbol-bearing `build/myapp` and want to check the internal name `calculate_internal_quote`.

```sh
git clone https://github.com/Afloat16/anti-rea-forge.git
python -m pip install ./anti-rea-forge
python -m releaseguard split-elf-debug build/myapp \
  --public release-linux --private private-symbols \
  --private-name calculate_internal_quote
```

**Deploy only `release-linux/myapp`.** Keep `private-symbols/myapp.debug` for internal crash diagnosis. If the selected name survives in an export, diagnostic string or wide string, the command reports the name and refuses publication. Splitting happens at build time and adds no application runtime component. [Supported inputs and private debugging](docs/private-elf-debug.md)

On the service, supply the trusted issuer key, authenticated user and route. The handler receives the exact request bytes after the capability has been verified and consumed.

```python
from releaseguard.capabilities import run_authorized_operation

receipt = run_authorized_operation(
    grant, trusted_issuer_public_key, replay_store,
    subject=authenticated_user, audience="exports", product="myapp",
    operation="create-export", request=request_bytes, handler=create_export,
)
```

[Service integration example](docs/private-elf-debug.md#put-the-restricted-operation-behind-a-service-side-check)

Other release tools cover [external C++ unlock tokens](docs/native-tokens.md) and [private JavaScript source maps](docs/private-source-maps.md). If this solves a release problem for your team, **star the project** or [contribute a reproducible fixture of your own](CONTRIBUTING.en.md).
