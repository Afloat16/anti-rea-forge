# CPython configured-key integer inspection

Version 1.3 adds the `canonical-marshal-integer/v1` release profile. It detects
canonical integer encodings of explicitly configured 32-byte asset keys in
recognized PYC files, including members of inspected ZIP and ASAR containers.
This read-only check changes no executable bytes. It does not make Python
algorithms, names, filenames or ordinary constants confidential.

## Official format references

The following values were checked against the CPython project's exact release
tags on 2026-11-18. These are framing references, not a claim that one interpreter
can execute all of these bytecode versions. The executable recovery experiment
uses CPython 3.12.14, magic 3531.

| CPython tag | Magic integer | Official definition |
| --- | ---: | --- |
| `v3.7.0` | 3394 | [`Lib/importlib/_bootstrap_external.py`](https://github.com/python/cpython/blob/v3.7.0/Lib/importlib/_bootstrap_external.py) |
| `v3.8.0` | 3413 | [`Lib/importlib/_bootstrap_external.py`](https://github.com/python/cpython/blob/v3.8.0/Lib/importlib/_bootstrap_external.py) |
| `v3.9.0` | 3425 | [`Lib/importlib/_bootstrap_external.py`](https://github.com/python/cpython/blob/v3.9.0/Lib/importlib/_bootstrap_external.py) |
| `v3.10.0` | 3439 | [`Lib/importlib/_bootstrap_external.py`](https://github.com/python/cpython/blob/v3.10.0/Lib/importlib/_bootstrap_external.py) |
| `v3.11.0` | 3495 | [`Lib/importlib/_bootstrap_external.py`](https://github.com/python/cpython/blob/v3.11.0/Lib/importlib/_bootstrap_external.py) |
| `v3.12.0` | 3531 | [`Lib/importlib/_bootstrap_external.py`](https://github.com/python/cpython/blob/v3.12.0/Lib/importlib/_bootstrap_external.py) |
| `v3.13.0` | 3571 | [`Lib/importlib/_bootstrap_external.py`](https://github.com/python/cpython/blob/v3.13.0/Lib/importlib/_bootstrap_external.py) |
| `v3.14.0` | 3627 | [`Include/internal/pycore_magic_number.h`](https://github.com/python/cpython/blob/v3.14.0/Include/internal/pycore_magic_number.h) |

All eight versions' `_classify_pyc` implementations require a 16-byte header and
reject flags outside bits 0 and 1. Consequently the profile accepts flags 0, 1,
2 and 3; it does not incorrectly reject the uncommon value 2. The 3.14 import
module obtains its magic from the token defined in the header above; its
[header classification](https://github.com/python/cpython/blob/v3.14.0/Lib/importlib/_bootstrap_external.py)
uses the same framing rule.

CPython's [`v3.7.0` marshal writer](https://github.com/python/cpython/blob/v3.7.0/Python/marshal.c)
and [`v3.14.0` marshal writer](https://github.com/python/cpython/blob/v3.14.0/Python/marshal.c)
define LONG as type `l`, optionally carrying the `0x80` reference flag, with a
signed digit count and little-endian base-2^15 digits. The scanner generates
those exact records for signed/unsigned and big/little-endian reconstruction.
Repeated marshal references must have an earlier defining record; the scanner
does not follow reference indexes.

## Completion and boundaries

- Candidate recognition requires CR LF after a little-endian magic integer in
  3000..3999. The eight stable magics above enter the profile. Other candidates,
  including 3666, fail as unsupported; other prefixes are outside this profile.
- The profile requires a top-level code-object tag but does not validate or
  unmarshal its body. A completed scan means the bounded pattern search ended,
  not that the bytecode is safe or well formed.
- Each signed/unsigned, big/little interpretation of a configured key must have
  at least 128 significant bits. A short interpretation causes incomplete
  inspection, even when another interpretation is long. This is a pattern
  ambiguity threshold, not an estimate of key entropy.
- At most 16 configured keys and 64 MiB per PYC payload are supported. Reads use
  64 KiB chunks with overlap. Short reads, size changes, unsupported headers and
  exceeded budgets fail the release gate with `structured_secret_unverifiable`.
- `pyc_asset_key_scan_completed` is separate from JSON/DER completion. Findings
  reveal only the configured key's index and a fixed representation label.
  Unknown keys, computed/split values, noncanonical integers and arbitrary
  encodings remain outside the exact-pattern profile.

## Reproducible recovery controls

[`python_key_recovery.mjs`](../benchmarks/python_key_recovery.mjs) invokes real
REA and the [trusted fixture helper](../benchmarks/python_key_recovery.py).
Its 12 disclosure fixtures cover four signed/endian forms with marshal versions
2 and 4, plus four leading-zero cases. REA's reported integers alone generate
candidate keys, which must authenticate an owned AES-GCM ciphertext and match
the expected plaintext. The official v1.2 wheel's installed package bytes are
checked before and after the comparison.

The [npm 6.9.0 report](results/python-key-recovery-v1.3.0-rea-6.9.0.json) and
[source-build report](results/python-key-recovery-v1.3.0-rea-source.json) each
observe 12 recoveries, 12 releases allowed by v1.2 and 12 rejected by v1.3 with a
completed PYC profile. Both standalone PYC and executable ZIP applications are
checked. The same ordinary public program stays executable and inspectable.
The two REA distributions and packaging variants repeat the same fixtures;
they are not additional independent attack samples.

Two controls remain separate from that denominator: an unconfigured embedded
key is still recoverable and passes the configured-key gate, while the
recoverable short signed integer is rejected as incomplete. Neither is counted
as proof of algorithm confidentiality or as a successful detected disclosure.
