# Independent native reconstruction controls

These project-owned sources preserve the completed function-recovery experiment of 2026-11-09. `fixture.c` and `driver.c` are the original reference. `baseline.c`, `mixed.c` and `virtualized.c` were independently written from the corresponding public ELF and genuine Ghidra output in separate worker conversations.

The fixture source was held back during reconstruction and published after all three workers completed. Workers shared a filesystem and followed explicit input-access instructions. The root evaluator compiled the submitted implementations and checked 1,081,924 outputs against the original executable. All three reconstructions matched every evaluation. [Recorded observation](../../docs/results/native-code-recovery.json)

| Candidate | Input supplied to its worker | Observed working time |
| --- | --- | --- |
| `baseline.c` | Ordinary ELF and its Ghidra function output | About 85 seconds |
| `mixed.c` | Split/flatten/substitution ELF and its Ghidra function output | About 112 seconds |
| `virtualized.c` | VM ELF, full recognized-function C and initialized-memory export | 310 seconds |

The VM worker supplemented incomplete decompiler output with static disassembly of the provided ELF. It decoded the VM representation and produced ordinary C integer operations. Its implementation has no dependency on the original executable or interpreter. The recorded durations include each worker's analysis and self-testing and represent one attempt per condition.

## Recheck the submitted implementations

The binary interface consumes little-endian 32-bit inputs and emits one little-endian 32-bit result per input. Run from the repository root with a C compiler and Python.

```sh
set -eu
mkdir native-recovery-check
cc -std=c11 -O2 benchmarks/function_recovery/fixture.c \
  benchmarks/function_recovery/driver.c -o native-recovery-check/reference
for candidate in baseline mixed virtualized; do
  cc -std=c11 -O2 -Wall -Wextra -Werror \
    "benchmarks/function_recovery/$candidate.c" \
    benchmarks/function_recovery/driver.c \
    -o "native-recovery-check/$candidate"
done
python - <<'PY'
from pathlib import Path
import random
import struct
import subprocess

work = Path('native-recovery-check').resolve()
values = list(range(65536)) + [0xffffffff, 0xfffffffe, 0x80000000, 0x7fffffff]
rng = random.Random(20261109)
values += [rng.getrandbits(32) for _ in range(1000000)]
payload = struct.pack(f'<{len(values)}I', *values)

def evaluate(name):
    run = subprocess.run([str(work / name)], input=payload,
                         capture_output=True, check=True, timeout=60)
    assert not run.stderr and len(run.stdout) == len(payload)
    return run.stdout

reference = evaluate('reference')
for name in ('baseline', 'mixed', 'virtualized'):
    assert evaluate(name) == reference, name
    print(name, len(values), 'matching evaluations')
PY
```

The published recheck uses a fresh reproducible input set. The historical hidden set is identified by its digest in the observation report. `benchmarks/native_code_controls.py` generates new randomized source instances, builds every configured profile, scores a separately supplied C candidate and measures in-process cost.
