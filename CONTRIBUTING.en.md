# Contributing to Anti-REA Forge

[English](CONTRIBUTING.en.md) · [简体中文](CONTRIBUTING.md)

You can contribute with **Python, JavaScript, TypeScript types, JSON policies or documentation**.
C++ knowledge is only needed for the native components. Keep a change focused on one
observable behavior and include a small, synthetic example that demonstrates it.

## Choose a small first change

| Area | Start here | Useful contributions |
| --- | --- | --- |
| Python release checks | `src/releaseguard/distribution.py`, `tests/test_distribution.py` | Add a bounded disclosure check or a regression for a packaging edge case |
| Private source maps | `src/releaseguard/split_maps.py`, `tests/test_split_maps.py` | Add a real packaging counterexample; reproduce the [paired recovery controls](docs/private-source-maps.md) |
| Build setup and analysis authorization | `src/releaseguard/project.py`, `src/releaseguard/analysis.py` | Improve setup or verify an authorization boundary using synthetic signed inputs |
| JavaScript / TypeScript | `packages/releaseguard/` | Improve the CLI bridge, types, subprocess handling or examples |
| JSON policies | `examples/policy-portable-release.json` | Document a real packaging workflow and its expected files |
| Native integration | `src/releaseguard/data/`, `tests/test_cmake_integration.py` | Test CMake, C++ lifetimes and compatibility |
| Research | `docs/rea-source-review-2026-11-04.zh-CN.md` | Verify a pinned upstream capability and propose a measurable defense |
| Documentation | The two READMEs and `docs/portable-release.md` | Fix a command, explain an error or translate a focused section |

These are contribution suggestions, not assigned or pre-created issues. A small fix can
go directly into a pull request; a new protection scheme benefits from an issue explaining
the threat model, compatibility cost and how its claimed effect can be tested.

## Python development

Python 3.10 or newer is required. From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest tests.test_distribution tests.test_distribution_cli -v
```

In Windows PowerShell, activate with `.\.venv\Scripts\Activate.ps1`. These portable
scanner tests do not need a C/C++ compiler, REA, a model API key or a native decompiler.

The new build/authorization path is also compiler-free:

```bash
python -m unittest tests.test_project tests.test_analysis tests.test_analysis_cli -v
```

See [integration](docs/analysis-authorization.md). Keep authority in trusted code;
test that a denied request never reaches the handler. Target notices are data and
must not be presented as a way to override model instructions.

Run the complete Python suite when changing shared code:

```bash
python -m unittest discover -s tests -v
```

The full suite also exercises project-owned native fixtures. Linux CMake integration
needs GCC/G++, CMake and CTest. If CMake is outside `PATH`, set `RELEASEGUARD_CMAKE`
to its full executable path. Report the actual test and skip counts; a missing tool
does not establish that a check passed.

## JavaScript and TypeScript development

The SDK uses standard JavaScript ESM, a checked-in TypeScript declaration file and
Node's built-in test runner. It has **no npm runtime dependencies or build step**.
Use Node.js 22 or newer:

```bash
npm test --prefix packages/releaseguard
```

The [package guide](packages/releaseguard/README.md) describes its exact commands,
integration tests and API. The SDK launches an installed Python core using isolated
mode; set `RELEASEGUARD_PYTHON` to the absolute path of the virtual environment's
Python executable for real integration. On Windows this is `.venv\Scripts\python.exe`;
on Linux/macOS it is `.venv/bin/python`.

Keep the JavaScript layer focused on safe invocation and ergonomic types. New rules
belong in the Python core so the CLI, CMake and JavaScript callers share one decision.
Do not create a second implementation of the signature or replay protocol in the bridge.
The npm package is a local workspace package; no registry publication is implied.

## Native development

Linux example:

```bash
cmake -S examples -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

For Windows/MSVC, configure with `cmake -S examples -B build -A x64`. Select the
virtual environment explicitly with `-DPython3_EXECUTABLE=...` if CMake finds another
Python interpreter. Verify public exports, calling conventions and existing callers
before changing DLL interfaces.

## What belongs in a pull request

- Explain the input or workflow that fails, what changes and the resulting behavior.
- For security-relevant behavior, include a regression that fails before the fix.
- List commands actually run, their outcomes, skips and untested platforms.
- Keep the CLI, `releaseguard` import name and existing v1 document formats compatible.
- Use synthetic data. Never include production keys, passphrases, customer licenses or
  other people's private binaries. Follow [SECURITY.md](SECURITY.md) for sensitive reports.
- Follow the [code of conduct](CODE_OF_CONDUCT.md) and contribute material you may
  distribute under the project's [MIT license](LICENSE).

## Evidence and protection claims

Read the [historical experiment](docs/testing-2026-10-15.zh-CN.md): independent static
analysis and runtime observation recovered the synthetic sample's secret. Those failures
remain relevant. A passing release scan verifies configured checks on the inspected bytes;
it does not measure resistance to decompilation, memory hooks or client-side patching.

For a new reverse-engineering experiment, identify the owned/authorized sample, exact
tool commits, provider/model, budgets, artifact hashes, analysis inputs and success criterion.
Keep successful recovery, timeout, environment failure and untested cases separate.
Do not attack analysis tools, tailor a sample to evade a test probe, or discard failed
protection results. Reproducible counterexamples are useful contributions.
