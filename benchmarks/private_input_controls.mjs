/** Paired owned-file publication controls with real, pinned REA observations. */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { selectReaRuntime } from "./rea_runtime.mjs";

const { values: args } = parseArgs({ options: {
  python: { type: "string", default: "python" }, "baseline-python": { type: "string" },
  "baseline-wheel": { type: "string" },
  tools: { type: "string" }, work: { type: "string" }, out: { type: "string" },
  "rea-source": { type: "string" }, "rea-source-commit": { type: "string" },
} });
const here = dirname(fileURLToPath(import.meta.url));
const tools = resolve(args.tools ?? join(here, "recovery-tools"));
const sha = (value) => createHash("sha256").update(value).digest("hex");
const BASELINE_WHEEL_SHA = "b16280c1f81cb6cec5a028102edeefdaf8b62e9300da3e87acb1878b3f0ab75b";
const identityHelper = join(here, "python_key_recovery.py");
assert.equal(Boolean(args["baseline-python"]), Boolean(args["baseline-wheel"]),
  "--baseline-python and the official --baseline-wheel must be supplied together");
const baselineWheel = args["baseline-wheel"] ? resolve(args["baseline-wheel"]) : null;
if (baselineWheel) assert.equal(sha(await readFile(baselineWheel)), BASELINE_WHEEL_SHA, "Official baseline wheel identity");
const PRIVATE_SOURCE = [
  "// Owned server-only example: rg_private_quote_37_19.",
  "export function quote(quantity) { return quantity * 37 + 19; }", "",
].join("\n");
const sourceDigest = sha(PRIVATE_SOURCE);
const runtime = await selectReaRuntime({ tools, source: args["rea-source"], sourceCommit: args["rea-source-commit"] });

function run(program, argv, cwd, expected = 0) {
  const result = spawnSync(program, argv, { cwd, encoding: "utf8", shell: false,
    timeout: 60_000, maxBuffer: 16 * 1024 * 1024, killSignal: "SIGKILL" });
  if (result.error || result.signal || result.status !== expected) {
    throw new Error("Control did not complete (exit " + result.status + ", signal " + result.signal + "): " +
      String(result.error ?? "") + " " + (result.stderr ?? "").slice(0, 1200));
  }
  return result.stdout;
}

async function inventory(root) {
  const rows = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    assert(entry.isFile(), "The owned fixture must remain flat and regular");
    const data = await readFile(join(root, entry.name));
    rows.push({ path: entry.name, size: data.length, sha256: sha(data) });
  }
  return rows.sort((a, b) => a.path.localeCompare(b.path, "en"));
}

async function inspectRea(root, evidence, name, privateCount) {
  const files = await inventory(root);
  const raw = run(process.execPath, [runtime.entry, "analyze-javascript-application", root,
    "--format", "json"], evidence);
  const document = JSON.parse(raw);
  assert.equal(document.operation, "analyze_javascript_application");
  assert.equal(document.provider?.id, "rea-javascript-application");
  assert(!Object.hasOwn(document, "error"));
  const result = document.normalized_result;
  assert.equal(result.format, "directory");
  assert.equal(result.source_selection?.unselected_files ?? 0, 0);
  assert.deepEqual(result.integrity_contradictions, []);
  assert.equal(result.statistics.relevant_files, files.length);
  assert.equal(result.statistics.parsed_javascript_files, files.filter((file) => file.path.endsWith(".mjs")).length);
  for (const field of ["skipped_javascript_files", "parse_failures", "invalid_utf8_files"]) {
    assert.equal(result.statistics[field], 0);
  }
  const graph = result.graph;
  assert.equal(graph.coverage.status, "complete");
  assert.equal(graph.coverage.truncated, false);
  const scripts = graph.nodes.filter((node) => node.kind === "javascript-asset");
  for (const file of files.filter((file) => file.path.endsWith(".mjs"))) {
    const node = scripts.find((item) => item.identity.sha256 === file.sha256);
    assert(node?.observations.some((item) => item.properties.path === file.path &&
      item.properties.text_status === "included" && item.properties.parse_status === "complete"));
  }
  const privateNodes = scripts.filter((node) => node.identity.sha256 === sourceDigest);
  assert.equal(privateNodes.length, privateCount);
  const exactCopies = [];
  for (const file of files) {
    if ((await readFile(join(root, file.path))).equals(Buffer.from(PRIVATE_SOURCE))) exactCopies.push(file.path);
  }
  assert.equal(exactCopies.length, privateCount);
  await writeFile(join(evidence, name + "-rea.json"), raw, { flag: "wx" });
  return { inventory: files, exact_private_file_copies: exactCopies.length,
    rea: { operation: document.operation, provider: document.provider.id, evidence_id: document.evidence_id,
      evidence_stdout_sha256: sha(raw), evidence_stdout_bytes: Buffer.byteLength(raw),
      graph_id: graph.graph_id, complete: true, truncated: false,
      parsed_javascript_files: result.statistics.parsed_javascript_files, private_source_nodes: privateNodes.length } };
}

async function project(work, name, root, privateFile, policy = { version: 1 }) {
  const directory = join(work, "configuration-" + name);
  await mkdir(directory);
  const policyPath = join(directory, "policy.json");
  await writeFile(policyPath, JSON.stringify(policy));
  const config = join(directory, "project.json");
  await writeFile(config, JSON.stringify({ version: 1, product: "owned-private-input-control",
    root, policy: "policy.json", private_input_files: [privateFile] }));
  return { config, policyPath };
}

function check(config, expected, work) {
  const report = JSON.parse(run(args.python, ["-I", "-m", "releaseguard", "check", "--config", config], work, expected));
  assert.equal(report.ok, expected === 0);
  assert.equal(report.checks.private_inputs_checked, 1);
  const findings = report.findings.filter((item) => item.code === "private_input_exposure");
  assert.equal(findings.length, expected === 3 ? 1 : 0);
  return { exit_code: expected, ok: report.ok, private_inputs_checked: 1,
    private_copy_findings: findings.length, findings };
}

const work = args.work ? resolve(args.work) : await mkdtemp(join(tmpdir(), "releaseguard-private-inputs-"));
if (args.work) await mkdir(work);
try {
  const identity = (python, wheel) => JSON.parse(run(python,
    ["-I", identityHelper, "identity", ...(wheel ? ["--wheel", wheel] : [])], work));
  const candidateBefore = identity(args.python);
  const baselineBefore = baselineWheel ? identity(args["baseline-python"], baselineWheel) : null;
  const coreVersion = candidateBefore.version;
  const privateDirectory = join(work, "private");
  const evidence = join(work, "evidence");
  await mkdir(privateDirectory);
  await mkdir(evidence);
  const privateFile = join(privateDirectory, "pricing.mjs");
  await writeFile(privateFile, PRIVATE_SOURCE);
  const reference = await import(pathToFileURL(privateFile).href);
  const inputs = [-2, 0, 1, 11];
  const outputs = inputs.map((value) => reference.quote(value));
  assert.deepEqual(outputs, [-55, 19, 56, 426]);
  const publicClient = await readFile(join(here, "../examples/private_service/public/client.mjs"));
  const sides = {};
  let publicConfig;
  for (const [name, count] of [["accidental_copy", 1], ["public_only", 0], ["private_restored", 1]]) {
    const root = join(work, name);
    await mkdir(root);
    await writeFile(join(root, "client.mjs"), publicClient);
    await writeFile(join(root, "package.json"), JSON.stringify({ name: "owned-public-client", version: "1.0.0",
      type: "module", main: "client.mjs" }));
    if (count) await cp(privateFile, join(root, "renamed-pricing.mjs"), { errorOnExist: true, force: false });
    const before = await inventory(root);
    const { config, policyPath } = await project(work, name, root, privateFile);
    sides[name] = await inspectRea(root, evidence, name, count);
    sides[name].configured_check = check(config, count ? 3 : 0, work);
    if (args["baseline-python"]) {
      const baseline = JSON.parse(run(args["baseline-python"], ["-I", "-m", "releaseguard", "scan-release",
        "--root", root, "--policy", policyPath], work));
      assert.equal(baseline.ok, true);
      sides[name].baseline_without_private_reference = { exit_code: 0, ok: true };
    }
    assert.deepEqual(await inventory(root), before, "The scanner or analyzer changed the public input");
    if (!count) publicConfig = config;
  }
  // A stale manual digest does not track changes in private implementation.
  const updatedDirectory = join(work, "updated_public");
  await mkdir(updatedDirectory);
  const updatedSource = PRIVATE_SOURCE.replace("* 37", "* 41");
  const updatedPrivate = join(privateDirectory, "updated-pricing.mjs");
  await writeFile(updatedPrivate, updatedSource);
  await writeFile(join(updatedDirectory, "renamed.data"), updatedSource);
  const updated = await project(work, "updated", updatedDirectory, updatedPrivate,
    { version: 1, forbid_file_sha256: [sourceDigest] });
  const stale = JSON.parse(run(args.python, ["-I", "-m", "releaseguard", "scan-release", "--root", updatedDirectory,
    "--policy", updated.policyPath], work));
  assert.equal(stale.ok, true);
  const updatedCheck = check(updated.config, 3, work);
  // Exercise the actual sign-and-final-recheck path, using an ephemeral fixture issuer.
  const publication = JSON.parse(run(args.python, ["-I", "-c", [
    "import json,sys",
    "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey",
    "from releaseguard.project import prepare_release",
    "r=prepare_release(sys.argv[1],Ed25519PrivateKey.generate(),'owned-1',sys.argv[2])",
    "print(json.dumps({'prepared':r['prepared'],'private_inputs_checked':r['scan']['checks']['private_inputs_checked']}))",
  ].join(";"), publicConfig, join(work, "publication")], work));
  assert.deepEqual(publication, { prepared: true, private_inputs_checked: 1 });
  assert.equal(sha(await readFile(privateFile)), sourceDigest);
  assert.deepEqual(identity(args.python), candidateBefore, "Candidate package changed during the control");
  if (baselineWheel) {
    assert.equal(sha(await readFile(baselineWheel)), BASELINE_WHEEL_SHA, "Baseline wheel changed during the control");
    assert.deepEqual(identity(args["baseline-python"], baselineWheel), baselineBefore,
      "Installed baseline changed during the control");
  }
  await runtime.verifyUnchanged();
  const report = { schema: "releaseguard/private-input-controls/v1", ok: true, core_version: coreVersion,
    recorded_at: new Date().toISOString(), node: process.version, host: process.platform + "/" + process.arch,
    rea_cli_executed: true, rea_runtime: runtime.record,
    baseline_version: baselineBefore?.version ?? null,
    baseline: baselineBefore ? { ...baselineBefore, official_wheel_sha256: BASELINE_WHEEL_SHA,
      installed_bytes_verified: true } : null,
    candidate: candidateBefore,
    benchmark_files_sha256: { driver: sha(await readFile(fileURLToPath(import.meta.url))),
      identity_helper: sha(await readFile(identityHelper)) },
    owned_private_fixture_sha256: sourceDigest, fixture_inputs: inputs, fixture_outputs: outputs,
    public_client_sha256: sha(publicClient), sides, publication,
    updated_private_input: { stale_manual_digest_passed: stale.ok, configured_check: updatedCheck },
    scope: "Exact declared private files remain outside the public client, with the production configured publication gate.",
    limitations: [
      "REA successfully analyzes the public JavaScript. Missing private source nodes mean those exact bytes were not supplied, not that equivalent behavior is impossible to infer.",
      "The existing manual forbid_file_sha256 rule can already block a known exact copy; live references additionally track changed private inputs and publication-time identity.",
      "This control exercises exact whole-file copies. The separate private-content control covers unchanged full contents inside larger payloads; transformed, compiled, encoded and partial copies remain outside that profile.",
      "This benchmark does not execute authentication, patch or replay controls. The reusable service example uses run_authorized_operation; the existing native patch control separately tests a real client patch against a separate service.",
    ] };
  const serialized = JSON.stringify(report, null, 2) + "\n";
  if (args.out) await writeFile(resolve(args.out), serialized, { flag: "wx" });
  process.stdout.write(serialized);
} finally {
  if (!args.work) await rm(work, { recursive: true, force: true });
}
