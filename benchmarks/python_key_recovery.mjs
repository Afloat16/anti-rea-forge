/**
 * Real REA recovery of owned CPython integer constants, paired official v1.2
 * and current release gates, plus executable PYC/zipapp compatibility controls.
 * No downloads or third-party targets; provider errors never count as protection.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { selectReaRuntime } from "./rea_runtime.mjs";

const BASELINE_WHEEL_SHA = "b16280c1f81cb6cec5a028102edeefdaf8b62e9300da3e87acb1878b3f0ab75b";
const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const here = dirname(fileURLToPath(import.meta.url));
const helper = join(here, "python_key_recovery.py");
const { values: args } = parseArgs({ options: {
  python: { type: "string", default: "python" }, "baseline-python": { type: "string" },
  "baseline-wheel": { type: "string" }, tools: { type: "string" }, out: { type: "string" },
  work: { type: "string" }, "rea-source": { type: "string" }, "rea-source-commit": { type: "string" },
} });
assert(args["baseline-python"] && args["baseline-wheel"],
  "--baseline-python and the official --baseline-wheel are required");
const baselineWheel = resolve(args["baseline-wheel"]);
assert.equal(sha(await readFile(baselineWheel)), BASELINE_WHEEL_SHA, "Official v1.2.0 wheel identity");
const tools = resolve(args.tools ?? join(here, "recovery-tools"));
const runtime = await selectReaRuntime({ tools, source: args["rea-source"], sourceCommit: args["rea-source-commit"] });
const work = args.work ? resolve(args.work) : await mkdtemp(join(tmpdir(), "releaseguard-pyc-recovery-"));
if (args.work) await mkdir(work);
const temporary = join(work, "runtime-tmp");
await mkdir(temporary);

function run(program, argv, { exit = 0, input } = {}) {
  const result = spawnSync(program, argv, { cwd: work, encoding: "utf8", shell: false, input,
    timeout: 60_000, maxBuffer: 16 * 1024 * 1024, killSignal: "SIGKILL",
    env: { ...process.env, TMPDIR: temporary, TMP: temporary, TEMP: temporary } });
  // Deliberately do not echo command output: REA's raw evidence contains public
  // synthetic key integers, while this benchmark report records no key values.
  if (result.error || result.signal || result.status !== exit || result.stderr !== "")
    throw new Error(`Command did not complete cleanly (exit ${result.status}, signal ${result.signal}, ` +
      `stderr bytes ${Buffer.byteLength(result.stderr ?? "")}, error ${result.error?.code ?? "none"})`);
  return result.stdout;
}
const helperRun = (python, action, extra = [], options) =>
  JSON.parse(run(python, ["-I", helper, action, ...extra], options));
const cli = (python, argv, exit = 0) =>
  JSON.parse(run(python, ["-I", "-m", "releaseguard", ...argv], { exit }));
const baselineBefore = helperRun(args["baseline-python"], "identity", ["--wheel", baselineWheel]);
const candidateBefore = helperRun(args.python, "identity");
const corpus = helperRun(args.python, "generate", ["--work", join(work, "corpus")]);
assert.equal(corpus.implementation, "CPython", "The fixture producer must be CPython");
const rows = [];

for (const fixture of corpus.fixtures) {
  const artifact = join(fixture.root, "disk", "pricing.pyc");
  const original = await readFile(artifact);
  assert.equal(sha(original), fixture.artifact_sha256);
  const raw = run(process.execPath, [runtime.entry, "inspect-python-pyc", artifact, "--format", "json"]);
  const evidence = JSON.parse(raw), result = evidence.normalized_result;
  if (runtime.record.distribution === "source-build") {
    assert.equal(evidence.evidence_format, 2);
    assert.equal(evidence.subject.identity.sha256, fixture.artifact_sha256);
  } else {
    // The pinned npm release predates the source build's evidence-format 2
    // envelope. Verify its real legacy digest field without fabricating one.
    assert.equal(evidence.evidence_format, undefined);
    assert.equal(evidence.subject.digest.sha256, fixture.artifact_sha256);
  }
  assert.equal(evidence.provider.id, "rea-python-pyc");
  assert.equal(evidence.operation, "inspect_python_pyc");
  assert.equal(result.artifact.sha256, fixture.artifact_sha256);
  assert.equal(result.artifact.bytes, original.length);
  assert.equal(result.coverage.status, "complete", "Incomplete REA output cannot count as protection");
  const recovery = helperRun(args.python, "recover", ["--case", fixture.root], { input: raw });
  assert.equal(recovery.exact_key_recovered, fixture.expected_recovery);
  assert.equal(recovery.aes_plaintext_verified, fixture.expected_recovery);
  assert.equal(recovery.public_function_name_visible, true, "Ordinary program names must remain observable");
  assert(recovery.original_filename_occurrences > 0, "This profile does not remove Python source paths");
  const gates = {};
  for (const packaging of ["disk", "zipapp"]) {
    const argv = ["scan-release", "--root", join(fixture.root, packaging), "--policy", corpus.policy,
      "--asset-key-file", join(fixture.root, "configured.key")];
    const baseline = cli(args["baseline-python"], argv);
    assert.equal(baseline.ok, true, "Expected the official v1.2 configured-key regression");
    assert.deepEqual(baseline.findings, []);
    const expectedPass = fixture.expected_candidate_gate === "allow";
    const candidate = cli(args.python, argv, expectedPass ? 0 : 3);
    assert.equal(candidate.ok, expectedPass);
    assert.equal(candidate.checks.pyc_asset_keys_checked, true);
    assert.equal(candidate.checks.pyc_asset_key_files_checked, 1);
    assert.equal(candidate.checks.pyc_asset_key_scan_completed, fixture.expected_candidate_gate !== "incomplete");
    assert.equal(candidate.checks.structured_secret_scan_completed, true, "PYC completion is independent from JSON/DER");
    if (fixture.expected_candidate_gate === "reject") {
      assert(candidate.findings.some(f => f.code === "asset_key_exposure" && f.representation === "python-marshal-integer"));
      assert(!candidate.findings.some(f => f.code === "structured_secret_unverifiable"));
    } else if (fixture.expected_candidate_gate === "incomplete") {
      assert(candidate.findings.some(f => f.code === "structured_secret_unverifiable" && f.format === "cpython-pyc"));
      assert(!candidate.findings.some(f => f.code === "asset_key_exposure"));
    } else assert.deepEqual(candidate.findings, []);
    gates[packaging] = { baseline: { ok: baseline.ok, findings: baseline.findings },
      candidate: { ok: candidate.ok, findings: candidate.findings,
        pyc_files_checked: candidate.checks.pyc_asset_key_files_checked,
        pyc_scan_completed: candidate.checks.pyc_asset_key_scan_completed },
      archives_scanned: candidate.checks.archives_scanned };
  }
  const zipapp = join(fixture.root, "zipapp", "application.pyz");
  const behavior = JSON.parse(run(args.python, ["-I", zipapp]));
  assert.deepEqual(behavior, fixture.behavior, "Owned zipapp behavior changed");
  assert.deepEqual(await readFile(artifact), original, "Read-only analysis/gates changed the PYC");
  assert.equal(sha(await readFile(zipapp)), fixture.zipapp_sha256);
  const { root, ...publicFixture } = fixture;
  rows.push({ ...publicFixture, rea: { provider: evidence.provider.id, exit_code: 0,
    evidence_envelope: evidence.evidence_format ?? "legacy-unversioned",
    evidence_stdout_sha256: sha(raw), evidence_stdout_bytes: Buffer.byteLength(raw), ...recovery },
    gates, zipapp_behavior_verified: true, analyzed_artifact_unchanged: true });
}

assert.deepEqual(helperRun(args["baseline-python"], "identity", ["--wheel", baselineWheel]), baselineBefore,
  "The installed baseline changed during the experiment");
assert.deepEqual(helperRun(args.python, "identity"), candidateBefore, "The candidate package changed during the experiment");
await runtime.verifyUnchanged();
const disclosures = rows.filter(r => r.kind === "disclosure");
const publicControls = rows.filter(r => r.kind === "public-control");
const boundaries = rows.filter(r => r.kind.endsWith("-boundary"));
const report = {
  schema: "releaseguard/python-key-recovery/v1", generated_at: new Date().toISOString(),
  baseline: { ...baselineBefore, official_wheel_sha256: BASELINE_WHEEL_SHA, installed_bytes_verified: true },
  candidate: candidateBefore, rea_runtime: runtime.record,
  dependency_lock_sha256: sha(await readFile(join(tools, "package-lock.json"))),
  benchmark_files_sha256: { driver: sha(await readFile(fileURLToPath(import.meta.url))), helper: sha(await readFile(helper)) },
  environment: { node: process.version, platform: process.platform, architecture: process.arch,
    fixture_python: corpus.python, fixture_magic: corpus.magic },
  summary: { disclosure_fixtures: disclosures.length,
    real_rea_exact_key_and_plaintext_recoveries: disclosures.filter(r => r.rea.exact_key_recovered && r.rea.aes_plaintext_verified).length,
    baseline_allowed_disclosures: disclosures.filter(r => r.gates.disk.baseline.ok && r.gates.zipapp.baseline.ok).length,
    candidate_rejected_disclosures: disclosures.filter(r => !r.gates.disk.candidate.ok && !r.gates.zipapp.candidate.ok
      && r.gates.disk.candidate.pyc_scan_completed && r.gates.zipapp.candidate.pyc_scan_completed).length,
    packaging_profiles: ["standalone-pyc", "deflated-zipapp"],
    public_controls_passing_and_executable: publicControls.filter(r => r.gates.disk.candidate.ok
      && r.gates.zipapp.candidate.ok && r.zipapp_behavior_verified && !r.rea.exact_key_recovered).length,
    separately_reported_boundary_controls: boundaries.length,
    provider_errors_counted_as_protection: 0, algorithm_confidentiality_claimed: false },
  scope: [
    "Only project-owned synthetic keys/programs. REA runs as the real selected CLI provider; no simulated output.",
    "The release gate detects canonical representations of configured keys; it does not alter or encrypt executable bytecode.",
    "The 12 disclosure cases are paired representations, not independent attack samples or a security probability. Packaging variants and two REA distributions must not multiply this denominator.",
    "Ordinary PYC and zipapp behavior, names and original filenames remain visible. REA's PYC command reports constants/metadata, not reconstructed Python source.",
    "Unconfigured keys remain recoverable. Short signed/unsigned integer aliases are explicitly incomplete; this control is not counted as a detected disclosure.",
    "Computed, split and noncanonical integer encodings, other secret forms and general client-side algorithms remain outside this exact-pattern profile.",
    "Reports omit key bytes, integer values, key digests and raw recovered plaintext. Source/artifact/evidence hashes identify only synthetic experiment inputs and outputs.",
  ], fixtures: rows,
};
if (args.out) await writeFile(resolve(args.out), JSON.stringify(report, null, 2) + "\n", { flag: "wx" });
process.stdout.write(JSON.stringify(report, null, 2) + "\n");
