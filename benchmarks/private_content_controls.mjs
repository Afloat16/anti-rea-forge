/** Exact private-content publication controls with real pinned REA recovery. */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { selectReaRuntime } from "./rea_runtime.mjs";

const { values: args } = parseArgs({ options: {
  python: { type: "string", default: "python" }, "baseline-python": { type: "string" },
  "baseline-wheel": { type: "string" }, tools: { type: "string" },
  work: { type: "string" }, out: { type: "string" },
  "rea-source": { type: "string" }, "rea-source-commit": { type: "string" },
} });
assert(args["baseline-python"] && args["baseline-wheel"],
  "The installed official --baseline-python and --baseline-wheel are required");
const here = dirname(fileURLToPath(import.meta.url));
const helper = join(here, "private_content_probe.py");
const sha = data => createHash("sha256").update(data).digest("hex");
const baselineWheel = resolve(args["baseline-wheel"]);
const baselineSha = "1bb79222ca7aa1224f3815b2cacf235985e9c9f08bf7330ce0a80099df7bc3a6";
assert.equal(sha(await readFile(baselineWheel)), baselineSha, "Official v1.3.0 baseline wheel identity");
const runtime = await selectReaRuntime({ tools: resolve(args.tools ?? join(here, "recovery-tools")),
  source: args["rea-source"], sourceCommit: args["rea-source-commit"] });
const work = args.work ? resolve(args.work) : await mkdtemp(join(tmpdir(), "releaseguard-private-content-"));
if (args.work) await mkdir(work);

function run(program, argv, expected = 0) {
  const result = spawnSync(program, argv, { cwd: work, encoding: "utf8", shell: false,
    timeout: 60_000, maxBuffer: 16 * 1024 * 1024, killSignal: "SIGKILL" });
  assert(!result.error && !result.signal && result.status === expected,
    "Owned control failed (exit " + result.status + ", signal " + result.signal + "): " +
    String(result.error ?? "") + " " + (result.stderr ?? "").slice(0, 1500));
  return result.stdout;
}

async function inventory(root) {
  const rows = [];
  async function visit(relative) {
    const entries = await readdir(join(root, relative), { withFileTypes: true });
    for (const entry of entries) {
      const path = relative ? relative + "/" + entry.name : entry.name;
      if (entry.isDirectory()) await visit(path);
      else {
        assert(entry.isFile(), "Owned fixture contains a link or special file");
        const bytes = await readFile(join(root, path));
        rows.push({ path, bytes: bytes.length, sha256: sha(bytes) });
      }
    }
  }
  await visit("");
  return rows.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

function sourceRange(text, range) {
  const lines = text.split("\n");
  assert(Number.isInteger(range?.start?.line) && Number.isInteger(range?.end?.line));
  assert(range.start.line >= 1 && range.end.line <= lines.length);
  const selected = lines.slice(range.start.line - 1, range.end.line);
  if (selected.length === 1) return selected[0].slice(range.start.column, range.end.column);
  selected[0] = selected[0].slice(range.start.column);
  selected[selected.length - 1] = selected[selected.length - 1].slice(0, range.end.column);
  return selected.join("\n");
}

try {
  const identity = (python, wheel) => JSON.parse(run(python,
    ["-I", helper, "identity", ...(wheel ? ["--wheel", wheel] : [])]));
  const candidateBefore = identity(args.python);
  const baselineBefore = identity(args["baseline-python"], baselineWheel);
  assert.equal(baselineBefore.version, "1.3.0");
  assert.equal(candidateBefore.python_version, baselineBefore.python_version, "Paired Python runtime");
  assert.equal(candidateBefore.cryptography_version, baselineBefore.cryptography_version, "Paired cryptography runtime");
  const fixture = JSON.parse(run(args.python, ["-I", helper, "fixtures", "--work", work]));
  const evidence = join(work, "evidence");
  await mkdir(evidence);
  const inputs = [-2, 0, 1, 11], outputs = [-55, 19, 56, 426];
  const originalModule = await import(pathToFileURL(fixture.private_file).href);
  assert.deepEqual(inputs.map(value => originalModule.quote(value)), outputs);

  async function gate(python, name, root, expectedOk, candidate, config) {
    const command = config ? ["check", "--config", config] : ["scan-release", "--root", root,
      "--policy", fixture.policy, "--private-input-file", fixture.private_file];
    const raw = run(python, ["-I", "-m", "releaseguard", ...command], expectedOk ? 0 : 3);
    const report = JSON.parse(raw);
    assert.equal(report.ok, expectedOk);
    assert.equal(report.checks.private_inputs_checked, 1);
    const findings = report.findings.filter(item => item.code === "private_input_exposure");
    assert.equal(findings.length > 0, !expectedOk);
    assert(report.findings.every(item => item.code === "private_input_exposure"));
    if (candidate) {
      assert.equal(report.checks.private_input_profile, "exact-content/v1");
      assert.equal(report.checks.private_input_scan_completed, true);
      assert(report.checks.private_input_payloads_checked >= 1);
    }
    await writeFile(join(evidence, name + "-" + (candidate ? "candidate" : "baseline") + ".json"), raw, { flag: "wx" });
    return { exit_code: expectedOk ? 0 : 3, ok: report.ok, findings,
      ...(candidate ? { private_input_profile: report.checks.private_input_profile,
        private_input_scan_completed: report.checks.private_input_scan_completed,
        private_input_payloads_checked: report.checks.private_input_payloads_checked,
        private_input_candidate_checks: report.checks.private_input_candidate_checks,
        private_input_verification_bytes: report.checks.private_input_verification_bytes } : {}),
      evidence_sha256: sha(raw), evidence_bytes: Buffer.byteLength(raw) };
  }

  const javascriptCases = [];
  for (const item of fixture.javascript_cases) {
    const before = await inventory(item.root);
    const baseline = await gate(args["baseline-python"], item.name, item.root, item.baseline_ok, false);
    const candidate = await gate(args.python, item.name, item.root, item.candidate_ok, true);
    const raw = run(process.execPath, [runtime.entry, "analyze-javascript-application", item.root, "--format", "json"]);
    const document = JSON.parse(raw), result = document.normalized_result;
    assert.equal(document.operation, "analyze_javascript_application");
    assert.equal(document.provider?.id, "rea-javascript-application");
    assert(!Object.hasOwn(document, "error"));
    assert.equal(result.format, "directory");
    assert.equal(result.source_selection?.unselected_files ?? 0, 0);
    assert.deepEqual(result.integrity_contradictions, []);
    assert.equal(result.statistics.relevant_files, before.length);
    assert.equal(result.statistics.parsed_javascript_files, 1);
    for (const field of ["skipped_javascript_files", "parse_failures", "invalid_utf8_files"]) {
      assert.equal(result.statistics[field], 0);
    }
    assert.equal(result.graph.coverage.status, "complete");
    assert.equal(result.graph.coverage.truncated, false);
    const asset = result.graph.nodes.find(node => node.kind === "javascript-asset" && node.identity.sha256 === item.source_sha256);
    assert(asset?.observations.some(observation => observation.properties.path === item.script &&
      observation.properties.text_status === "included" && observation.properties.parse_status === "complete"));
    const functions = result.semantic_graph.nodes.filter(node => node.kind === "function" &&
      node.properties.name === "quote" && node.identity.artifact_sha256 === item.source_sha256 &&
      node.identity.module_path === item.script);
    assert.equal(functions.length, item.expected_private_function_count);
    const literals = functions.length ? result.semantic_graph.nodes.filter(node => node.kind === "literal" &&
      node.function_node_id === functions[0].node_id).map(node => node.properties.value) : [];
    const text = await readFile(join(item.root, item.script), "utf8");
    assert.equal(sha(text), item.source_sha256);
    assert.equal(text.includes(await readFile(fixture.private_file, "utf8")), item.contains_complete_reference);
    let recovery = null;
    if (functions.length) {
      assert(literals.includes(37) && literals.includes(19));
      const fingerprint = result.semantic_graph.fingerprints.find(row => row.function_node_id === functions[0].node_id);
      assert.equal(fingerprint?.status, "complete");
      const recovered = sourceRange(text, functions[0].identity.source_range);
      // Only the known owned fixture may execute. The analyzer itself consumes
      // inert source; recovery uses its digest-bound function source range.
      assert.equal(recovered, "function quote(quantity) { return quantity * 37 + 19; }");
      const recoveredFile = join(evidence, item.name + "-recovered.mjs");
      await writeFile(recoveredFile, "export " + recovered + "\n", { flag: "wx" });
      const recoveredModule = await import(pathToFileURL(recoveredFile).href);
      const recoveredOutputs = inputs.map(value => recoveredModule.quote(value));
      assert.deepEqual(recoveredOutputs, outputs);
      const publicModule = await import(pathToFileURL(join(item.root, item.script)).href);
      assert.deepEqual(inputs.map(value => publicModule.quote(value)), outputs);
      recovery = { method: "REA digest-bound source range copied from the owned published JavaScript",
        function_sha256: sha(recovered), normalized_ast_sha256: fingerprint.components.normalized_ast_sha256,
        input_values: inputs, original_outputs: outputs, published_outputs: outputs, recovered_outputs: recoveredOutputs };
    }
    await writeFile(join(evidence, item.name + "-rea.json"), raw, { flag: "wx" });
    assert.deepEqual(await inventory(item.root), before, "Scanner or analyzer changed the public input");
    javascriptCases.push({ name: item.name, source_bytes: item.source_bytes, source_sha256: item.source_sha256,
      contains_complete_reference: item.contains_complete_reference, inventory: before, baseline, candidate,
      rea: { operation: document.operation, provider: document.provider.id, evidence_id: document.evidence_id,
        evidence_sha256: sha(raw), evidence_bytes: Buffer.byteLength(raw), complete: true, truncated: false,
        parsed_javascript_files: 1, private_function_nodes: functions.length, private_function_literals: literals }, recovery });
  }

  const containerVariants = [];
  for (const item of fixture.container_variants) {
    const before = await inventory(item.root);
    const baseline = await gate(args["baseline-python"], item.name, item.root, item.baseline_ok, false);
    const candidate = await gate(args.python, item.name, item.root, item.candidate_ok, true);
    assert.deepEqual(await inventory(item.root), before);
    containerVariants.push({ name: item.name, shared_contained_payload_sha256: item.shared_contained_payload_sha256,
      inventory: before, baseline, candidate });
  }
  const configurationControls = [];
  for (const name of ["concatenated_bundle", "public_only"]) {
    const item = fixture.javascript_cases.find(row => row.name === name);
    configurationControls.push({ name,
      baseline: await gate(args["baseline-python"], name + "-configured", item.root, item.baseline_ok, false, item.config),
      candidate: await gate(args.python, name + "-configured", item.root, item.candidate_ok, true, item.config) });
  }
  const resourceProbe = JSON.parse(run(args.python, ["-I", helper, "resources", "--work", work]));
  await runtime.verifyUnchanged();
  assert.deepEqual(identity(args.python), candidateBefore, "Candidate changed during experiment");
  assert.deepEqual(identity(args["baseline-python"], baselineWheel), baselineBefore, "Baseline changed during experiment");
  const report = {
    schema: "releaseguard-private-content-controls/v1", candidate: candidateBefore,
    recorded_at: new Date().toISOString(),
    benchmark_files_sha256: { driver: sha(await readFile(fileURLToPath(import.meta.url))),
      helper: sha(await readFile(helper)), runtime: sha(await readFile(join(here, "rea_runtime.mjs"))) },
    baseline: { ...baselineBefore, official_wheel_sha256: baselineSha }, rea: runtime.record,
    node_version: process.version, private_reference_bytes: fixture.private_reference_bytes,
    private_reference_sha256: fixture.private_reference_sha256,
    scope: "One exact-content profile. Prefix, suffix, concatenation and chunk crossings are input variants; the six container layouts are deployment checks, not independent vulnerabilities or extra REA recoveries.",
    boundary: "Edited, encoded, compiled or split contents are not covered. The changed-comment case remains REA-recoverable and passes this exact-content profile. Protection requires keeping private implementation outside the public release.",
    javascript_cases: javascriptCases, container_variants: containerVariants,
    saved_configuration_controls: configurationControls, resource_probe: resourceProbe,
    summary: {
      exact_reference_controls: 1, newly_blocked_wrapping_profiles: 3,
      chunk_boundary_controls: 1, rea_recovered_published_inputs_with_complete_reference: 5,
      deployment_variants: containerVariants.length,
      unchanged_public_controls: 1, recoverable_edited_reference_boundaries: 1,
      whole_scan_candidate_limit: 4096, whole_scan_verification_byte_limit: 512 * 1024 * 1024,
    },
  };
  const output = JSON.stringify(report, null, 2) + "\n";
  if (args.out) await writeFile(resolve(args.out), output, { flag: "wx" });
  process.stdout.write(output);
} finally {
  if (!args.work) await rm(work, { recursive: true, force: true });
}
