# Public client, private operation

This owned example shows a build and service integration boundary. Deploy only
`public/` to users. Deploy `service/` with your existing trusted application.
The example source is public teaching material; replace it with your own logic
in a separately controlled service repository.

## Check the public layout

From the repository root, with Release Guard 1.4 or later installed:

```sh
releaseguard check --config examples/private_service/project.json --format text
releaseguard prepare --config examples/private_service/project.json \
  --private /trusted/issuer.pem --release 1.0.0 --out /trusted/new-release-evidence
```

The checked project declares all three server source files as
`private_input_files`. Their paths resolve relative to `project.json`. Complete
unchanged copies in public files, supported ZIP members or ASAR payloads are rejected
even after renaming, adding headers/footers or concatenating a bundle. A file allowlist
also rejects unexpected public paths.
The private inputs must remain unchanged through scanning, signing and the
final publication check. Failed final checks remove the new sidecar bundle.

At most 64 explicit regular files are accepted, each containing 1 byte to 8 MiB
and together at most 64 MiB. References must stay outside the public release;
links, reparse points, directories, special files and missing inputs fail.
Trusted build operators must control their ancestor directories. This is an
ordinary file identity and hash recheck, not an atomic filesystem snapshot.
No source is imported or executed by the release scanner.

Additional files can be supplied with repeatable `--private-input-file` flags
on `scan-release`, `check` or `prepare`; they add to saved configuration. The
JavaScript SDK accepts `privateInputFiles` on `scanRelease` and `checkProject`.
An empty extra list never disables configured references. Reports provide a
reference count and rule indices, without listing private source paths or a
separate reference digest. The existing public inventory still includes public
file hashes, including the hash of an accidentally published exact copy.

## Connect the existing service

`public/client.mjs` accepts a host-provided `send` function. It sends the exact
UTF-8 JSON bytes and a capability through your application's existing
authenticated transport. It contains no implementation of `quote`.

At service startup, load the trusted issuer public key and open an existing
durable `ReplayStore`. Create the store once when provisioning; do not replace
it when the application restarts. Call `make_quote_handler` from
`service.entry` with these trusted objects. For each request, call its returned
handler with:

```python
result = handle(
    authenticated_subject=session.subject,
    request=exact_request_bytes,
    capability=untrusted_capability_document,
)
```

`session.subject` comes from the service's authenticated session, never a field
asserted in the client body. Keep `audience`, `product`, `operation`, issuer
key and the selected handler fixed in trusted configuration. Issue the
capability for those same values and the exact request bytes. A valid grant is
consumed durably before the private operation runs; replay or a changed request
is rejected. An exception in the operation still spends that grant.

## What this demonstrates

Keeping implementation bytes out of the client prevents tools from extracting
those absent bytes from that client. REA can still inspect and modify the public
client. A modified client cannot create a valid issuer signature or replenish a
consumed nonce in the separately controlled service.

The file reference check detects **exact complete private contents**, including
contents inside larger payloads. Compilation, translation, minification, encoding
or partial copying remain outside that byte profile. It does not automatically partition an application
or prove semantic confidentiality. Review your build graph, keep the private
service out of public build inputs, and list all private files relevant to the
release. Authorized users still observe outputs and may learn behavior from
them. Authentication, transport, quotas, request validation and service access
control remain duties of the host application.

The [bounded content profile](../../docs/private-input-content.md) explains candidate
budgets and the separate incomplete-inspection result. Initialize your own project
with repeatable `project-init --private-input-file` options to save validated references
without hand-editing configuration-relative paths.

The repository's existing `benchmarks/elf_symbols/patch_control.py` runs a real
native client patch against a separate service process. This example reuses
`run_authorized_operation`; it adds no new HTTP/RPC protocol or analyzer-specific
behavior.

## Reproduce the publication comparison

After installing the development core and the repository's pinned REA tools:

```sh
node benchmarks/private_input_controls.mjs --python /trusted/candidate/python \
  --baseline-python /trusted/baseline/python \
  --baseline-wheel /trusted/open_release_guard-1.2.0-py3-none-any.whl \
  --out private-input-controls.json
```

This runs REA on three newly created owned directories: an accidental private
source copy, the public client alone, and a restored private copy. It requires
complete analysis of every JavaScript file, checks exact source digests, and
runs the configured production gate and the public `prepare` path. The
baseline interpreter and wheel are optional as a pair. When supplied, the
official v1.2.0 wheel SHA-256 and every installed package file are verified;
candidate and baseline package inventories are checked again at completion. A second
control changes the private source and shows that live file references reject
the new copy even when an older manual digest has become stale.

Supply `--rea-source /trusted/rea --rea-source-commit FULL_COMMIT` to test a
source-built REA checkout instead of the pinned npm distribution. Supply
`--work /trusted/new-evidence-directory` to retain inputs and complete raw
analyzer output. The report expressly records that this publication comparison
does not rerun the separate native patch/authorization benchmark.
