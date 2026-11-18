/**
 * Real REA/WABT private-name recovery control on one project-authored module.
 * npm ci --prefix benchmarks/recovery-tools --omit=optional --ignore-scripts
 * Download the pinned official Linux x64 WABT asset, verify its SHA-256, unpack,
 * then run with --wabt-bin DIR --python /trusted/python --out report.json.
 * --work DIR retains the fixture and complete REA JSON in a NEW directory.
 * A missing tool, provider error, partial interface or changed input is a failure.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { selectReaRuntime } from "./rea_runtime.mjs";

const REA_SOURCE_REVIEW = {
  repository: "https://github.com/morluto/rea",
  commit: "c338e54c33213ca8dd157d30fbc922b65a04c49b",
  method: "read-only source review",
  executed_by_this_probe: false,
};
const WABT_VERSION = "1.0.42";
const WABT_SOURCE = "ff0ef7e0009402740c805a9744c09b05be063e48";
const WABT_ASSET = "https://github.com/WebAssembly/wabt/releases/download/1.0.42/wabt-1.0.42-linux-x64.tar.gz";
const WABT_ASSET_SHA = "84895407a6bbb80e918f33b16b2fb2206021c150b6bc9ff6f761263a745ab131";
// Exact executable bytes from the verified official release asset above.
// Other platforms/builds require a separate recorded experiment.
const WABT_TOOLS = {
  "wasm-validate": "6b722ed0df68204cfc7a8effdf1fc2ddeac2d184bd211cdf7fdfa5f9d49d3eb5",
  "wasm-objdump": "dad264def1a3b7755859c5bf48227f01259a95fa82b7c38358b12b9e70b27a41",
  "wasm2wat": "4322d652f650c1ee117b549c9722f42fc93eb4676ff046d60ba033b5639697a5",
  "wat2wasm": "9e9ec8f737c890553951defcb1ee7f82de99fcafa32bef54990de27413794e7f",
};
const PRIVATE_NAMES = [
  "rg_private_pricing_module_67c98e", "rg_private_quote_function_83b42d",
  "rg_private_quantity_argument_90a351",
];
const PUBLIC_NOTE = "Anti-REA Forge authored recovery fixture; this public notice is retained.";
const SOURCE = `(module $${PRIVATE_NAMES[0]}
  (func $${PRIVATE_NAMES[1]} (export "quote") (param $${PRIVATE_NAMES[2]} i32) (result i32)
    local.get $${PRIVATE_NAMES[2]}
    i32.const 7
    i32.mul
    i32.const 3
    i32.add))
`;
const INPUTS = [-2147483648, -1000000, -2, -1, 0, 1, 11, 1000000, 2147483647];
const EXPECTED_OUTPUTS = INPUTS.map(value => (value * 7 + 3) | 0);
const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const { values: args } = parseArgs({ options: {
  tools: { type: "string" }, "wabt-bin": { type: "string" },
  python: { type: "string", default: "python" }, out: { type: "string" },
  work: { type: "string" }, "rea-source": { type: "string" }, "rea-source-commit": { type: "string" },
} });
assert.equal(process.platform, "linux", "This pinned executable profile is Linux x64");
assert.equal(process.arch, "x64", "This pinned executable profile is Linux x64");
assert(args["wabt-bin"], "--wabt-bin is required; no implicit download or unpinned fallback");
const wabtBin = resolve(args["wabt-bin"]);
const tools = resolve(args.tools ?? join(dirname(fileURLToPath(import.meta.url)), "recovery-tools"));
const lockBytes = await readFile(join(tools, "package-lock.json"));
const reaRuntime = await selectReaRuntime({ tools, source: args["rea-source"], sourceCommit: args["rea-source-commit"] });
const reaEntry = reaRuntime.entry;

function run(program, argv, cwd, expectedExit = 0) {
  const result = spawnSync(program, argv, { cwd, encoding: "utf8", shell: false,
    timeout: 120_000, maxBuffer: 16 * 1024 * 1024, killSignal: "SIGKILL",
    env: { ...process.env, REA_WABT_BIN_DIRECTORY: wabtBin } });
  if (result.error || result.signal || result.status !== expectedExit) {
    throw new Error(`Command failed: ${program} ${argv[0]} (exit ${result.status}, signal ${result.signal}): ` +
      `${result.error ?? ""} ${(result.stdout ?? "").slice(0, 1500)} ${(result.stderr ?? "").slice(0, 1500)}`);
  }
  assert.equal(result.stderr, "", "Unexpected tool stderr is not evidence of protection");
  return result.stdout;
}

async function verifyWabt(cwd) {
  for (const [tool, expected] of Object.entries(WABT_TOOLS)) {
    const path = join(wabtBin, tool);
    assert.equal(sha(await readFile(path)), expected, tool + " executable identity");
    assert.equal(run(path, ["--version"], cwd).trim(), WABT_VERSION, tool + " version");
  }
}

function leb(value) {
  const bytes = [];
  do {
    const part = value & 127;
    value >>>= 7;
    bytes.push(part | (value ? 128 : 0));
  } while (value);
  return Buffer.from(bytes);
}
function customSection(name, text) {
  const key = Buffer.from(name);
  const payload = Buffer.concat([leb(key.length), key, Buffer.from(text)]);
  return Buffer.concat([Buffer.from([0]), leb(payload.length), payload]);
}

// This independent fixture reader preserves exact framing bytes. It is not a
// general validator; the Node engine and actual WABT validate all three inputs.
function sections(bytes) {
  assert(bytes.subarray(0, 8).equals(Buffer.from([0, 97, 115, 109, 1, 0, 0, 0])));
  const rows = [];
  let offset = 8;
  while (offset < bytes.length) {
    const start = offset;
    const id = bytes[offset++];
    let size = 0, shift = 0, more;
    do {
      assert(offset < bytes.length && shift < 35);
      const value = bytes[offset++];
      size += (value & 127) * 2 ** shift;
      more = value & 128;
      shift += 7;
    } while (more);
    const payloadStart = offset;
    offset += size;
    assert(offset <= bytes.length);
    rows.push({ id, start, payload_start: payloadStart, end: offset, bytes: bytes.subarray(start, offset) });
  }
  return rows;
}
const coreBytes = bytes => Buffer.concat([bytes.subarray(0, 8), ...sections(bytes).filter(s => s.id !== 0).map(s => s.bytes)]);

function executeOwnModule(bytes) {
  assert.equal(WebAssembly.validate(bytes), true);
  const module = new WebAssembly.Module(bytes);
  assert.deepEqual(WebAssembly.Module.imports(module), []);
  assert.deepEqual(WebAssembly.Module.exports(module), [{ name: "quote", kind: "function" }]);
  const output = new WebAssembly.Instance(module).exports;
  const values = INPUTS.map(value => output.quote(value));
  assert.deepEqual(values, EXPECTED_OUTPUTS);
  const notices = WebAssembly.Module.customSections(module, "public-notice");
  assert.equal(notices.length, 1);
  assert.equal(Buffer.from(notices[0]).toString(), PUBLIC_NOTE);
  return { module, values };
}

async function examine(file, bytes, expectedNames, cwd, evidenceDirectory, side) {
  const raw = run(process.execPath, [reaEntry, "inspect-wasm-artifact", file, "--format", "json"], cwd);
  await writeFile(join(evidenceDirectory, side + ".json"), raw, { flag: "wx" });
  const evidence = JSON.parse(raw);
  assert.equal(evidence.operation, "inspect_wasm_artifact");
  assert.equal(evidence.provider?.id, "wabt-artifact");
  assert(!Object.hasOwn(evidence, "error"));
  if (args["rea-source"]) {
    // The pinned November source snapshot uses Evidence v2, while the actual
    // 6.9.0 npm package uses the older subject envelope. Check each explicitly.
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
  assert.equal(result.interface?.state, "complete", "Partial interface cannot establish preserved public behavior");
  assert.deepEqual(result.interface.issues, []);
  assert.deepEqual(result.interface.entries.map(({ direction, name, kind, index, signature, issue }) =>
    ({ direction, name, kind, index, signature, issue })), [{ direction: "export", name: "quote",
    kind: "func", index: 0, signature: { kind: "func", params: ["i32"], results: ["i32"] }, issue: null }]);
  assert.deepEqual(result.imports, []);
  assert.equal(result.exports.length, 1);
  assert.deepEqual(result.custom_section_warnings, []);
  assert.equal(result.debug_name_metadata, expectedNames ? "complete" : "not-present");
  assert.equal(result.wat.representation, "decoded-wat");
  assert.equal(result.wat.sha256, sha(result.wat.text));
  assert(result.wat.text.includes("i32.mul") && result.wat.text.includes("i32.add"), "Real code must remain decoded");
  assert.match(result.wat.text, /i32\.const 7\b/);
  assert.match(result.wat.text, /i32\.const 3\b/);
  const names = PRIVATE_NAMES.filter(name => result.wat.text.includes(name));
  assert.equal(names.length, expectedNames);
  // Cross-check every parsed section's physical range, including retained custom
  // data, so an omitted or empty input cannot look like successful protection.
  const originalSections = sections(bytes);
  assert.deepEqual(result.sections.map(s => ({ start: s.start, end: s.end, bytes: s.bytes })),
    originalSections.map(s => ({ start: s.payload_start, end: s.end, bytes: s.end - s.payload_start })));
  assert.equal(result.tool_profile.source, "https://github.com/WebAssembly/wabt");
  assert.equal(result.tool_profile.release, WABT_VERSION);
  assert.equal(result.tool_profile.source_commit, WABT_SOURCE);
  assert.equal(result.tool_profile.commands.length, 3);
  assert.deepEqual(result.tool_profile.commands.map(c => c.tool).sort(), ["wasm-objdump", "wasm-validate", "wasm2wat"]);
  for (const command of result.tool_profile.commands) {
    assert.equal(command.sha256, WABT_TOOLS[command.tool]);
    assert.equal(command.version_banner.trim(), WABT_VERSION);
  }
  assert.equal(result.network_fetch, "not-performed");
  assert.equal(result.runtime_execution, "not-performed");
  assert.deepEqual(await readFile(file), bytes, "Analyzed input changed");
  return { exit_code: 0, operation: evidence.operation, provider: evidence.provider.id,
    artifact_sha256: result.artifact.sha256, artifact_bytes: result.artifact.bytes,
    evidence_id: evidence.evidence_id, evidence_stdout_sha256: sha(raw),
    evidence_stdout_bytes: Buffer.byteLength(raw), validation: result.validation,
    interface_state: result.interface.state, decoded_sections: result.sections.length,
    debug_name_metadata: result.debug_name_metadata, private_identifiers_recovered: names.length,
    wat_sha256: result.wat.sha256, wat_bytes: Buffer.byteLength(result.wat.text),
    arithmetic_instructions_visible: true, custom_section_warnings: [] };
}

const work = args.work ? resolve(args.work) : await mkdtemp(join(tmpdir(), "releaseguard-wasm-"));
if (args.work) await mkdir(work);
try {
  await verifyWabt(work);
  const baseline = join(work, "baseline"), publicDir = join(work, "public");
  const privateDir = join(work, "private"), restored = join(work, "private-restored");
  const evidenceDir = join(work, "evidence");
  for (const directory of [baseline, publicDir, privateDir, restored, evidenceDir]) await mkdir(directory);
  const wat = join(work, "fixture.wat"), input = join(baseline, "module.wasm");
  await writeFile(wat, SOURCE, { flag: "wx" });
  run(join(wabtBin, "wat2wasm"), ["--debug-names", wat, "-o", input], work);
  const before = Buffer.concat([await readFile(input), customSection("public-notice", PUBLIC_NOTE)]);
  await writeFile(input, before);
  assert.equal(PRIVATE_NAMES.filter(name => before.includes(Buffer.from(name))).length, PRIVATE_NAMES.length);
  const publicFile = join(publicDir, "module.wasm"), privateFile = join(privateDir, "original.wasm");
  const split = JSON.parse(run(args.python, ["-I", "-m", "releaseguard", "split-wasm-debug",
    "--input", input, "--public", publicFile, "--private", privateFile], work));
  assert.equal(split.ok, true);
  const publicBytes = await readFile(publicFile), privateBytes = await readFile(privateFile);
  assert.deepEqual(await readFile(input), before, "Input was mutated");
  assert.deepEqual(privateBytes, before, "Private original must be byte-exact");
  assert.deepEqual(coreBytes(publicBytes), coreBytes(before), "Executable sections must be byte-exact");
  assert.equal(PRIVATE_NAMES.filter(name => publicBytes.includes(Buffer.from(name))).length, 0);
  await copyFile(privateFile, join(restored, "module.wasm"));
  const policy = join(work, "policy.json");
  await writeFile(policy, '{"version":1}\n', { flag: "wx" });
  const sides = {};
  for (const [side, directory, bytes, expectedNames] of [
    ["baseline", baseline, before, 3], ["public", publicDir, publicBytes, 0],
    ["private_restored", restored, privateBytes, 3],
  ]) {
    const file = join(directory, "module.wasm");
    const execution = executeOwnModule(bytes);
    assert.equal(WebAssembly.Module.customSections(execution.module, "name").length, expectedNames ? 1 : 0);
    const gate = JSON.parse(run(args.python, ["-I", "-m", "releaseguard", "scan-release",
      "--root", directory, "--policy", policy], work, expectedNames ? 3 : 0));
    assert.equal(gate.ok, expectedNames === 0);
    if (expectedNames) assert(gate.findings.some(f => f.code === "native_debug_metadata" && f.format === "wasm"));
    else assert.deepEqual(gate.findings, []);
    sides[side] = { sha256: sha(bytes), bytes: bytes.length,
      core_sections_sha256: sha(coreBytes(bytes)), fixture_outputs: execution.values,
      gate_ok: gate.ok, findings: gate.findings,
      rea: await examine(file, bytes, expectedNames, work, evidenceDir, side) };
  }
  await verifyWabt(work);
  await reaRuntime.verifyUnchanged();
  const report = { schema: "releaseguard/wasm-recovery/v1", ok: true,
    recorded_at: new Date().toISOString(), node: process.version, host: process.platform + "/" + process.arch,
    rea_cli_executed: true, mode: args["rea-source"] ? "rea-source-cli-and-wabt" : "rea-npm-cli-and-wabt",
    dependency_lock_sha256: sha(lockBytes),
    tools: { "rea-agents": args["rea-source"] ? reaRuntime.record
        : { ...reaRuntime.record, separate_source_review: REA_SOURCE_REVIEW },
      wabt: { version: WABT_VERSION, source_commit: WABT_SOURCE, release_asset: WABT_ASSET,
        release_asset_sha256: WABT_ASSET_SHA, executable_sha256: WABT_TOOLS } },
    fixture_source_sha256: sha(SOURCE), expected_private_identifiers: PRIVATE_NAMES.length,
    inputs: INPUTS, expected_outputs: EXPECTED_OUTPUTS,
    exact_private_backup: true, executable_sections_unchanged: true,
    retained_public_custom_section: "public-notice", sides,
    scope: "Recovery of three original debug identifiers in one authored core Wasm module, through the actual REA WABT provider.",
    limitations: ["WAT arithmetic remains decoded on every side; this does not hide or prevent reconstruction of the algorithm.",
      "The private original contains the entire recoverable module and must never be published. No runtime-secret or memory protection is claimed.",
      args["rea-source"] ? "This runs the compiled, tracked-clean source commit identified in tools; it is a separate experiment from the published npm package."
        : "This runs the npm REA 6.9.0 package identified by integrity; an independently reviewed repository commit is not asserted to be that package's exact source.",
      "One Linux x64 fixture and three names are not independent applications, attack success-rate estimates or an unrestricted AI agent evaluation."] };
  const serialized = JSON.stringify(report, null, 2) + "\n";
  if (args.out) await writeFile(resolve(args.out), serialized, { flag: "wx" });
  process.stdout.write(serialized);
} finally {
  if (!args.work) await rm(work, { recursive: true, force: true });
}
