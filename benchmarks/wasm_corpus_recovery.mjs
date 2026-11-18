/**
 * Five authored Wasm programs, executable behavior oracles, actual REA recovery,
 * and a separately reported v1.1 linker-symbol disclosure regression control.
 * Every normal program is measured before / public / privately restored.
 * Requires the pinned WABT asset and an installed, verified official v1.1 wheel;
 * no downloads, third-party target execution or provider-error success scores.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { selectReaRuntime } from "./rea_runtime.mjs";
import { fixtures, linkerFixture } from "./wasm_corpus_fixtures.mjs";

const WABT_VERSION = "1.0.42";
const WABT_SOURCE = "ff0ef7e0009402740c805a9744c09b05be063e48";
const WABT_ASSET = "https://github.com/WebAssembly/wabt/releases/download/1.0.42/wabt-1.0.42-linux-x64.tar.gz";
const WABT_ASSET_SHA = "84895407a6bbb80e918f33b16b2fb2206021c150b6bc9ff6f761263a745ab131";
const WABT_TOOLS = {
  "wasm-validate": "6b722ed0df68204cfc7a8effdf1fc2ddeac2d184bd211cdf7fdfa5f9d49d3eb5",
  "wasm-objdump": "dad264def1a3b7755859c5bf48227f01259a95fa82b7c38358b12b9e70b27a41",
  "wasm2wat": "4322d652f650c1ee117b549c9722f42fc93eb4676ff046d60ba033b5639697a5",
  "wat2wasm": "9e9ec8f737c890553951defcb1ee7f82de99fcafa32bef54990de27413794e7f",
};
const BASELINE_WHEEL_SHA = "5040a0f33c6b5a640302af4983556abdcab1918e845f4bac4010ec2fa2233086";
const PUBLIC_NOTE = "Anti-REA Forge authored corpus: public notice retained verbatim.";
const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const { values: args } = parseArgs({ options: {
  tools: { type: "string" }, "wabt-bin": { type: "string" },
  python: { type: "string", default: "python" }, "baseline-python": { type: "string" },
  "baseline-wheel": { type: "string" }, out: { type: "string" }, work: { type: "string" },
  "rea-source": { type: "string" }, "rea-source-commit": { type: "string" },
} });
assert.equal(process.platform, "linux", "This executable profile is Linux x64");
assert.equal(process.arch, "x64", "This executable profile is Linux x64");
assert(args["wabt-bin"], "--wabt-bin is required; no implicit downloads or unpinned fallback");
assert(args["baseline-python"] && args["baseline-wheel"],
  "The linker regression needs --baseline-python installed from the official --baseline-wheel");
const wabtBin = resolve(args["wabt-bin"]);
const baselineWheel = resolve(args["baseline-wheel"]);
const tools = resolve(args.tools ?? join(dirname(fileURLToPath(import.meta.url)), "recovery-tools"));
const dependencyLock = await readFile(join(tools, "package-lock.json"));
const reaRuntime = await selectReaRuntime({ tools, source: args["rea-source"], sourceCommit: args["rea-source-commit"] });
const work = args.work ? resolve(args.work) : await mkdtemp(join(tmpdir(), "releaseguard-wasm-corpus-"));
if (args.work) await mkdir(work);
const temporary = join(work, "runtime-tmp");
await mkdir(temporary);

function command(program, argv, { exit = 0, allowStderr = false } = {}) {
  const result = spawnSync(program, argv, { cwd: work, encoding: "utf8", shell: false,
    timeout: 120_000, maxBuffer: 16 * 1024 * 1024, killSignal: "SIGKILL",
    env: { ...process.env, TMPDIR: temporary, REA_WABT_BIN_DIRECTORY: wabtBin } });
  if (result.error || result.signal || result.status !== exit) {
    throw new Error(`Command failed: ${program} ${argv[0]} (exit ${result.status}, signal ${result.signal}): ` +
      `${result.error ?? ""} ${(result.stdout ?? "").slice(0, 1500)} ${(result.stderr ?? "").slice(0, 1500)}`);
  }
  if (!allowStderr) assert.equal(result.stderr, "", "Unexpected stderr is not protection evidence");
  return result;
}
const run = (program, argv, options) => command(program, argv, options).stdout;
const cli = (python, argv, exit = 0) => JSON.parse(run(python, ["-I", "-m", "releaseguard", ...argv], { exit }));

async function verifyWabt() {
  for (const [tool, expected] of Object.entries(WABT_TOOLS)) {
    const path = join(wabtBin, tool);
    assert.equal(sha(await readFile(path)), expected, tool + " executable identity");
    assert.equal(run(path, ["--version"]).trim(), WABT_VERSION, tool + " version");
  }
}

// Check the installed baseline package against the exact previously published
// wheel, rather than trusting a version string from an arbitrary interpreter.
async function verifyBaseline() {
  assert.equal(sha(await readFile(baselineWheel)), BASELINE_WHEEL_SHA);
  return JSON.parse(run(args["baseline-python"], ["-I", "-c", `
import hashlib, importlib.metadata, json, pathlib, releaseguard, sys, zipfile
root = pathlib.Path(releaseguard.__file__).resolve().parent
with zipfile.ZipFile(sys.argv[1]) as wheel:
    files = sorted(n for n in wheel.namelist() if n.startswith("releaseguard/") and not n.endswith("/"))
    expected = {n[len("releaseguard/"):] for n in files}
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
    assert actual == expected, "Installed baseline files differ from official wheel"
    inventory = hashlib.sha256()
    for name in files:
        data = wheel.read(name)
        assert (root / name[len("releaseguard/"):]).read_bytes() == data, "Installed baseline bytes differ"
        inventory.update((name + " " + hashlib.sha256(data).hexdigest() + "\\n").encode())
version = importlib.metadata.version("open-release-guard")
assert version == releaseguard.__version__ == "1.1.0"
print(json.dumps({"version": version, "verified_package_files": len(files), "package_inventory_sha256": inventory.hexdigest()}))
`, baselineWheel]));
}

function leb(value) {
  const output = [];
  do { const part = value & 127; value >>>= 7; output.push(part | (value ? 128 : 0)); } while (value);
  return Buffer.from(output);
}
function customSection(name, text) {
  const key = Buffer.from(name), payload = Buffer.concat([leb(key.length), key, Buffer.from(text)]);
  return Buffer.concat([Buffer.from([0]), leb(payload.length), payload]);
}
// Independent reader for this fixed corpus, not a general module validator.
// The actual WABT provider and Node engine independently validate every side.
function sections(bytes) {
  assert(bytes.subarray(0, 8).equals(Buffer.from([0, 97, 115, 109, 1, 0, 0, 0])));
  const rows = [];
  let offset = 8;
  while (offset < bytes.length) {
    const start = offset, id = bytes[offset++];
    let size = 0, shift = 0, more;
    do {
      assert(offset < bytes.length && shift < 35);
      const value = bytes[offset++]; size += (value & 127) * 2 ** shift; more = value & 128; shift += 7;
    } while (more);
    const payloadStart = offset; offset += size; assert(offset <= bytes.length);
    rows.push({ id, start, payload_start: payloadStart, end: offset, bytes: bytes.subarray(start, offset) });
  }
  return rows;
}
const coreBytes = bytes => Buffer.concat([bytes.subarray(0, 8), ...sections(bytes).filter(s => s.id !== 0).map(s => s.bytes)]);

function executeOwnFixture(fixture, bytes, { names, notice = true }) {
  assert.equal(WebAssembly.validate(bytes), true);
  const module = new WebAssembly.Module(bytes), context = {};
  assert.deepEqual(WebAssembly.Module.imports(module), fixture.imports);
  assert.deepEqual(WebAssembly.Module.exports(module), fixture.exports);
  assert.equal(WebAssembly.Module.customSections(module, "name").length, names ? 1 : 0);
  if (notice) {
    const notices = WebAssembly.Module.customSections(module, "public-notice");
    assert.equal(notices.length, 1);
    assert.equal(Buffer.from(notices[0]).toString(), PUBLIC_NOTE);
  }
  return fixture.execute(new WebAssembly.Instance(module, fixture.imported?.(context) ?? {}), context);
}

async function examine(fixture, file, bytes, expectedNames, expectedMetadata, evidenceFile) {
  const raw = run(process.execPath, [reaRuntime.entry, "inspect-wasm-artifact", file, "--format", "json"]);
  await writeFile(evidenceFile, raw, { flag: "wx" });
  const evidence = JSON.parse(raw);
  assert.equal(evidence.operation, "inspect_wasm_artifact");
  assert.equal(evidence.provider?.id, "wabt-artifact");
  assert(!Object.hasOwn(evidence, "error"));
  if (args["rea-source"]) {
    assert.equal(evidence.evidence_format, 2);
    assert.equal(evidence.subject?.identity?.kind, "file");
    assert.equal(evidence.subject.identity.sha256, sha(bytes));
    assert.equal(evidence.subject.identity.format, "file");
    assert.equal(evidence.subject.identity.selection, null);
  } else {
    assert.equal(evidence.subject?.digest?.sha256, sha(bytes));
    assert.equal(evidence.subject.format, "file");
  }
  assert.equal(evidence.subject.local_path, file);
  const result = evidence.normalized_result;
  assert.equal(result.artifact.path, file);
  assert.equal(result.artifact.sha256, sha(bytes));
  assert.equal(result.artifact.bytes, bytes.length);
  assert.equal(result.validation, "valid");
  assert.equal(result.interface?.state, "complete", "Partial interface is not a successful experiment");
  assert.deepEqual(result.interface.issues, []);
  assert.deepEqual(result.interface.entries.map(({ direction, module, name, kind, index, signature, issue }) =>
    ({ direction, module, name, kind, index, signature, issue })), fixture.interface);
  assert.equal(result.imports.length, fixture.imports.length);
  assert.equal(result.exports.length, fixture.exports.length);
  assert.deepEqual(result.custom_section_warnings, []);
  assert.equal(result.debug_name_metadata, expectedMetadata);
  assert.equal(result.wat.representation, "decoded-wat");
  assert.equal(result.wat.sha256, sha(result.wat.text));
  for (const opcode of fixture.visibleOpcodes) assert(result.wat.text.includes(opcode), "Code must remain decoded: " + opcode);
  const recovered = {};
  for (const [channel, text] of Object.entries({ wat: result.wat.text, details: result.details, complete_evidence: raw })) {
    assert.equal(typeof text, "string");
    recovered[channel] = fixture.privateNames.filter(name => text.includes(name)).length;
    assert.equal(recovered[channel], expectedNames, `${fixture.id}: ${channel} recovery oracle`);
  }
  assert.deepEqual(result.sections.map(s => ({ start: s.start, end: s.end, bytes: s.bytes })),
    sections(bytes).map(s => ({ start: s.payload_start, end: s.end, bytes: s.end - s.payload_start })));
  assert.equal(result.tool_profile.source, "https://github.com/WebAssembly/wabt");
  assert.equal(result.tool_profile.release, WABT_VERSION);
  assert.equal(result.tool_profile.source_commit, WABT_SOURCE);
  assert.equal(result.tool_profile.commands.length, 3);
  assert.deepEqual(result.tool_profile.commands.map(c => c.tool).sort(), ["wasm-objdump", "wasm-validate", "wasm2wat"]);
  for (const profile of result.tool_profile.commands) {
    assert.equal(profile.sha256, WABT_TOOLS[profile.tool]);
    assert.equal(profile.version_banner.trim(), WABT_VERSION);
  }
  assert.equal(result.network_fetch, "not-performed");
  assert.equal(result.runtime_execution, "not-performed");
  assert.deepEqual(await readFile(file), bytes, "Analyzed input changed");
  return { exit_code: 0, operation: evidence.operation, provider: evidence.provider.id,
    artifact_sha256: result.artifact.sha256, artifact_bytes: result.artifact.bytes,
    evidence_id: evidence.evidence_id, evidence_stdout_sha256: sha(raw), evidence_stdout_bytes: Buffer.byteLength(raw),
    validation: result.validation, interface_state: result.interface.state,
    decoded_sections: result.sections.length, debug_name_metadata: result.debug_name_metadata,
    private_identifiers_recovered: recovered, wat_sha256: result.wat.sha256,
    wat_bytes: Buffer.byteLength(result.wat.text), checked_opcodes_visible: fixture.visibleOpcodes,
    custom_section_warnings: [] };
}

async function createDirectories(parent, names) {
  await mkdir(parent);
  const directories = {};
  for (const name of names) { directories[name] = join(parent, name); await mkdir(directories[name]); }
  return directories;
}

async function measureFixture(fixture, policy) {
  const root = join(work, fixture.id);
  const directories = await createDirectories(root, ["baseline", "public", "private", "private-restored", "evidence"]);
  const wat = join(root, "fixture.wat"), input = join(directories.baseline, "module.wasm");
  await writeFile(wat, fixture.wat, { flag: "wx" });
  run(join(wabtBin, "wat2wasm"), ["--debug-names", wat, "-o", input]);
  const before = Buffer.concat([await readFile(input), customSection("public-notice", PUBLIC_NOTE)]);
  await writeFile(input, before);
  assert.equal(fixture.privateNames.filter(name => before.includes(Buffer.from(name))).length, fixture.privateNames.length);
  const publicFile = join(directories.public, "module.wasm"), privateFile = join(directories.private, "original.wasm");
  const split = cli(args.python, ["split-wasm-debug", "--input", input, "--public", publicFile, "--private", privateFile]);
  assert.equal(split.ok, true);
  const publicBytes = await readFile(publicFile), privateBytes = await readFile(privateFile);
  assert.deepEqual(await readFile(input), before);
  assert.deepEqual(privateBytes, before, "Private restore must be byte-exact");
  assert.deepEqual(coreBytes(publicBytes), coreBytes(before), "All standard sections must stay byte-exact");
  assert.deepEqual(publicBytes, Buffer.concat([coreBytes(before), customSection("public-notice", PUBLIC_NOTE)]),
    "Only the producer's name section may disappear; all other framing and bytes must stay exact");
  assert.equal(fixture.privateNames.filter(name => publicBytes.includes(Buffer.from(name))).length, 0);
  assert.equal((await lstat(privateFile)).mode & 0o777, 0o600);
  await copyFile(privateFile, join(directories["private-restored"], "module.wasm"));
  const sides = {};
  let firstBehavior;
  for (const [side, directory, bytes, expectedNames] of [
    ["baseline", directories.baseline, before, fixture.privateNames.length],
    ["public", directories.public, publicBytes, 0],
    ["private_restored", directories["private-restored"], privateBytes, fixture.privateNames.length],
  ]) {
    const behavior = executeOwnFixture(fixture, bytes, { names: expectedNames > 0 });
    if (!firstBehavior) firstBehavior = behavior;
    else assert.deepEqual(behavior, firstBehavior, "Behavior differs between original, public and restored module");
    const gate = cli(args.python, ["scan-release", "--root", directory, "--policy", policy], expectedNames ? 3 : 0);
    assert.equal(gate.ok, expectedNames === 0);
    assert.equal(gate.checks.native_metadata_scan_completed, true);
    if (expectedNames) assert(gate.findings.some(f => f.code === "native_debug_metadata" && f.format === "wasm"));
    else assert.deepEqual(gate.findings, []);
    sides[side] = { sha256: sha(bytes), bytes: bytes.length, core_sections_sha256: sha(coreBytes(bytes)),
      gate_ok: gate.ok, findings: gate.findings, behavior,
      rea: await examine(fixture, join(directory, "module.wasm"), bytes, expectedNames,
        expectedNames ? "complete" : "not-present", join(directories.evidence, side + ".json")) };
  }
  return { id: fixture.id, features: fixture.features, source_sha256: sha(fixture.wat),
    expected_private_identifiers: fixture.privateNames.length, expected_typed_interface: fixture.interface,
    exact_private_backup: true, executable_sections_unchanged: true, retained_public_custom_section: "public-notice", sides };
}

async function measureLinkerRegression(policy) {
  const fixture = linkerFixture, root = join(work, fixture.id);
  const directories = await createDirectories(root, ["original", "old-public", "old-private", "new-public", "new-private", "evidence"]);
  const wat = join(root, "fixture.wat"), original = join(directories.original, "module.wasm");
  await writeFile(wat, fixture.wat, { flag: "wx" });
  run(join(wabtBin, "wat2wasm"), ["--relocatable", "--debug-names", wat, "-o", original]);
  const before = await readFile(original);
  const module = new WebAssembly.Module(before);
  assert.equal(WebAssembly.Module.customSections(module, "linking").length, 1);
  assert.equal(WebAssembly.Module.customSections(module, "reloc.Code").length, 1);
  const originalBehavior = executeOwnFixture(fixture, before, { names: true, notice: false });
  const oldPublic = join(directories["old-public"], "module.wasm"), oldPrivate = join(directories["old-private"], "original.wasm");
  const oldSplit = cli(args["baseline-python"], ["split-wasm-debug", "--input", original, "--public", oldPublic, "--private", oldPrivate]);
  assert.equal(oldSplit.ok, true);
  const oldBytes = await readFile(oldPublic);
  assert.deepEqual(await readFile(oldPrivate), before);
  assert.deepEqual(coreBytes(oldBytes), coreBytes(before));
  const oldBehavior = executeOwnFixture(fixture, oldBytes, { names: false, notice: false });
  assert.deepEqual(oldBehavior, originalBehavior);
  const oldGate = cli(args["baseline-python"], ["scan-release", "--root", directories["old-public"], "--policy", policy]);
  assert.equal(oldGate.ok, true);
  assert.deepEqual(oldGate.findings, []);
  const recovery = await examine(fixture, oldPublic, oldBytes, 1, "not-present", join(directories.evidence, "old-public.json"));
  const newGate = cli(args.python, ["scan-release", "--root", directories["old-public"], "--policy", policy], 3);
  assert.equal(newGate.ok, false);
  assert.equal(newGate.checks.native_metadata_scan_completed, false);
  assert(newGate.findings.some(f => f.code === "native_metadata_unverifiable" && f.format === "wasm" &&
    f.reason === "linker_metadata_requires_final_link"));
  const newPublic = join(directories["new-public"], "module.wasm"), newPrivate = join(directories["new-private"], "original.wasm");
  const rejected = command(args.python, ["-I", "-m", "releaseguard", "split-wasm-debug", "--input", original,
    "--public", newPublic, "--private", newPrivate], { exit: 2, allowStderr: true });
  assert.equal(rejected.stdout, "");
  const rejection = JSON.parse(rejected.stderr);
  assert.equal(rejection.ok, false);
  assert.match(rejection.error, /linker metadata.*final linked module/);
  for (const file of [newPublic, newPrivate]) await assert.rejects(lstat(file), { code: "ENOENT" });
  assert.deepEqual(await readFile(original), before);
  assert.deepEqual(await readFile(oldPublic), oldBytes);
  return { id: fixture.id, source_sha256: sha(fixture.wat), producer_flags: ["--relocatable", "--debug-names"],
    expected_private_identifiers: 1, original_sha256: sha(before), original_bytes: before.length,
    legacy_1_1: { actual_installed_release_executed: true, split_ok: true, gate_ok: true,
      original_private_backup_exact: true, public_sha256: sha(oldBytes), public_bytes: oldBytes.length,
      debug_name_section_removed: true, behavior: oldBehavior, rea: recovery },
    current: { gate_ok: false, findings: newGate.findings, native_metadata_scan_completed: false,
      split_exit_code: 2, split_error: rejection.error, no_output_files_created: true,
      recovery_measurement: "not-applicable-no-public-artifact", outcome: "blocked-before-publication" },
    limitation: "Recognizes linker section envelopes and requires final linking; it does not parse linker symbol/relocation tables or prove a linked program unrecoverable." };
}

try {
  await verifyWabt();
  const baseline = await verifyBaseline();
  const candidateVersion = run(args.python, ["-I", "-m", "releaseguard", "--version"]).trim();
  const policy = join(work, "policy.json");
  await writeFile(policy, '{"version":1}\n', { flag: "wx" });
  const results = [];
  for (const fixture of fixtures) results.push(await measureFixture(fixture, policy));
  const linker = await measureLinkerRegression(policy);
  await verifyWabt();
  assert.deepEqual(await verifyBaseline(), baseline, "Baseline installation changed during the probe");
  await reaRuntime.verifyUnchanged();
  const recoveryCounts = side => results.reduce((total, item) => total + item.sides[side].rea.private_identifiers_recovered.wat, 0);
  const behaviorCount = key => results.reduce((total, item) => total + item.sides.baseline.behavior[key], 0);
  const report = { schema: "releaseguard/wasm-corpus-recovery/v1", ok: true,
    recorded_at: new Date().toISOString(), node: process.version, host: process.platform + "/" + process.arch,
    candidate_releaseguard_version: candidateVersion, rea_cli_executed: true,
    mode: args["rea-source"] ? "rea-source-cli-and-wabt" : "rea-npm-cli-and-wabt",
    dependency_lock_sha256: sha(dependencyLock),
    tools: { "rea-agents": reaRuntime.record,
      wabt: { version: WABT_VERSION, source_commit: WABT_SOURCE, release_asset: WABT_ASSET,
        release_asset_sha256: WABT_ASSET_SHA, executable_sha256: WABT_TOOLS },
      baseline_releaseguard: { ...baseline, official_wheel_sha256: BASELINE_WHEEL_SHA } },
    fixture_oracle_source_sha256: sha(await readFile(new URL("./wasm_corpus_fixtures.mjs", import.meta.url))),
    summary: { different_programs: results.length, measured_sides_per_program: 3,
      known_private_identifiers: results.reduce((total, fixture) => total + fixture.expected_private_identifiers, 0),
      recovered_private_identifiers: { baseline: recoveryCounts("baseline"), public: recoveryCounts("public"), private_restored: recoveryCounts("private_restored") },
      numerical_cases: behaviorCount("numerical_cases"), runtime_trap_cases: behaviorCount("trap_cases"),
      host_rejection_cases: behaviorCount("host_rejection_cases"),
      rea_inspections_completed: results.length * 3 + 1, provider_errors_or_partial_results_counted_as_success: 0,
      linker_regression_outcome: linker.current.outcome },
    fixtures: results, linker_regression: linker,
    scope: "Five project-authored core Wasm programs with separate name-recovery and behavior oracles, plus one actual v1.1 linker-disclosure regression control.",
    limitations: ["WAT instructions, data and public interfaces remain decoded. This does not hide algorithms, runtime secrets or prevent independent reimplementation.",
      "Numerical/trap/host-rejection cases are counted once per fixture, not multiplied by three artifact sides or by two REA distributions. Stateful sequences use independent JS oracles but their steps are not statistically independent samples.",
      "These authored programs and 26 named identifiers are not an ecosystem-wide success rate, independent attack campaigns or an unrestricted agent evaluation.",
      "The separate linker control is a producer-valid relocatable module. The current policy refuses it until final linking; no nonexistent new public artifact is scored as zero recovery.",
      "Complete private originals remain recoverable and must stay outside public distribution.",
      args["rea-source"] ? "This runs the exact tracked-clean source commit and compiled runtime recorded in tools; it is separate from the npm distribution."
        : "This runs the published npm package identified by integrity; it does not assert the package is identical to a later repository snapshot."] };
  const serialized = JSON.stringify(report, null, 2) + "\n";
  if (args.out) await writeFile(resolve(args.out), serialized, { flag: "wx" });
  process.stdout.write(serialized);
} finally {
  if (!args.work) await rm(work, { recursive: true, force: true });
}
