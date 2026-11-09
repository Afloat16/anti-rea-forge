/**
 * Real, paired source-map exposure control. Runs on project-authored inputs only.
 * First: npm ci --prefix benchmarks/recovery-tools --omit=optional --ignore-scripts
 * Then:  node benchmarks/source_map_recovery.mjs --python /trusted/python --out report.json
 * --work DIR retains fixtures and full REA evidence in a new directory.
 * --consumer-only deliberately omits REA; it never substitutes for an errored REA run.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const SOURCE_NAME = "pricing-original.js";
const MARKER = "releaseguard_source_only_canary_4bd216a5531e";
const ORIGINAL = [
  "/* source-only marker: " + MARKER + " */",
  "export function quote(quantity) {",
  "  const internalUnitPrice = 7;",
  "  return quantity * internalUnitPrice + 3;",
  "}", "",
].join("\n");
const EXPECTED_SOURCE = "950aba3d70fb67f10427f86534c8dac4b17fb1d8450522f3bffdb02849664cb5";
const EXPECTED_JS = "79a5c99baec4a8a063db6d51dc9f521f7776ace46d4f8bb1cc68c4702ca7a1e8";
const PINNED = { "rea-agents": "6.8.0", "terser": "5.44.1", "@jridgewell/trace-mapping": "0.3.31" };
const sha = (data) => createHash("sha256").update(data).digest("hex");
const json = async (file) => JSON.parse(await readFile(file, "utf8"));
const { values: args } = parseArgs({ options: {
  tools: { type: "string" }, python: { type: "string", default: "python" },
  out: { type: "string" }, work: { type: "string" }, "consumer-only": { type: "boolean" },
} });
const defaultTools = join(dirname(fileURLToPath(import.meta.url)), "recovery-tools");
const tools = resolve(args.tools ?? defaultTools);
const localRequire = createRequire(join(tools, "package.json"));
const lock = await json(join(tools, "package-lock.json"));
const toolsUsed = {};
for (const [name, expected] of Object.entries(PINNED)) {
  const pkg = await json(join(tools, "node_modules", name, "package.json"));
  const locked = lock.packages["node_modules/" + name];
  assert.equal(pkg.version, expected, name + " version");
  assert.equal(locked?.version, expected, name + " lock");
  assert.match(locked.integrity, /^sha512-/);
  toolsUsed[name] = { version: pkg.version, npm_integrity: locked.integrity };
}
const { minify } = localRequire("terser");
const mapping = localRequire("@jridgewell/trace-mapping");
const reaEntry = join(tools, "node_modules/rea-agents/scripts/rea.mjs");

function run(program, argv, cwd, expectedExit = 0) {
  const p = spawnSync(program, argv, { cwd, encoding: "utf8", timeout: 120_000,
    maxBuffer: 16 * 1024 * 1024, killSignal: "SIGKILL", shell: false });
  if (p.error || p.signal || p.status !== expectedExit) {
    // A host/provider failure, timeout or bad output must never count as a protected result.
    throw new Error("Command did not complete: " + program + " " + argv[0] + " (exit " +
      p.status + ", signal " + p.signal + "): " +
      String(p.error ?? "") + " " + (p.stdout ?? "").slice(0, 1000) + " " +
      (p.stderr ?? "").slice(0, 1000));
  }
  return p.stdout;
}

// A separate build accidentally republishes the map as a minified ESM data export.
// Check the real minifier output: ordinary JSON-key matching misses the bare key.
async function rejectRepackedMap(work, baseline, mapText) {
  const source = join(work, "repacked-build"), publicDir = join(work, "repacked-public");
  const privateDir = join(work, "repacked-private");
  const { code } = await minify("export const debugMap=" + mapText + ";", { module: true });
  assert.match(code, /[,{]sourcesContent:\[/);
  assert(code.includes(MARKER));
  await cp(baseline, source, { recursive: true, force: false, errorOnExist: true });
  await writeFile(join(source, "repacked.mjs"), code, { flag: "wx" });
  const denied = JSON.parse(run(args.python, ["-I", "-m", "releaseguard", "split-source-maps",
    "--root", source, "--public", publicDir, "--private", privateDir], work, 3));
  assert.equal(denied.ok, false);
  assert(denied.findings.some(f => f.code === "sources_content_literal" && f.path === "repacked.mjs"));
  for (const dir of [publicDir, privateDir]) await assert.rejects(lstat(dir), { code: "ENOENT" });
  return { input: "repacked.mjs", sha256: sha(code), original_marker_present: true,
    bare_sources_content_key: true, exit_code: 3, finding: "sources_content_literal",
    public_output_absent: true, private_output_absent: true };
}

// Enumerate all supplied artifacts. This fixture is deliberately flat and uncompressed.
// Reject a changed fixture shape instead of silently skipping directories or files.
async function inventory(directory) {
  const rows = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    assert(entry.isFile(), "Unexpected link, directory or special file: " + entry.name);
    const bytes = await readFile(join(directory, entry.name));
    rows.push({ path: entry.name, size: bytes.length, sha256: sha(bytes) });
  }
  return rows.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

async function recover(directory, files) {
  const recovered = [];
  for (const { path } of files.filter(f => f.path.endsWith(".map"))) {
    const decoded = new mapping.TraceMap(await json(join(directory, path)));
    for (const source of decoded.sources) {
      const content = mapping.sourceContentFor(decoded, source);
      assert.equal(typeof content, "string", "Fixture map lost embedded source");
      const position = mapping.originalPositionFor(decoded, { line: 1, column: 16 });
      recovered.push({ map: path, source, content_sha256: sha(content),
        exact_text: content === ORIGINAL, marker_present: content.includes(MARKER), position });
    }
  }
  return recovered;
}

async function examineWithRea(directory, files, expectedOriginals, evidenceDir, side) {
  const raw = run(process.execPath, [reaEntry, "analyze-javascript-application", directory,
    "--format", "json"], evidenceDir);
  const doc = JSON.parse(raw);
  assert.equal(doc.operation, "analyze_javascript_application");
  assert.equal(doc.provider?.id, "rea-javascript-application");
  assert(!Object.hasOwn(doc, "error"));
  const result = doc.normalized_result;
  assert.equal(result.format, "directory");
  assert.equal(result.source_selection?.unselected_files ?? 0, 0);
  assert.deepEqual(result.integrity_contradictions, []);
  const stats = result.statistics;
  assert.equal(stats.relevant_files, files.length);
  assert.equal(stats.parsed_javascript_files, 1);
  assert.equal(stats.skipped_javascript_files, 0);
  assert.equal(stats.parse_failures, 0);
  assert.equal(stats.invalid_utf8_files, 0);
  const graph = result.graph;
  assert.equal(graph.coverage.status, "complete", "Partial graph cannot establish absence");
  assert.equal(graph.coverage.truncated, false);
  // An empty graph (or a graph of the wrong input) cannot be a protected result.
  const js = graph.nodes.find(n => n.kind === "javascript-asset" && n.identity.sha256 === EXPECTED_JS);
  assert(js?.observations.some(o => o.properties.path === "app.js" &&
    o.properties.text_status === "included" && o.properties.parse_status === "complete"));
  const originals = graph.nodes.filter(n => n.identity.strategy === "source-map-original");
  assert.equal(originals.length, expectedOriginals);
  const mapNodes = graph.nodes.filter(n => n.kind === "source-map");
  assert.equal(mapNodes.length, expectedOriginals);
  if (expectedOriginals) {
    const row = originals[0];
    assert.equal(row.identity.original_source, SOURCE_NAME);
    assert.equal(row.identity.source_sha256, EXPECTED_SOURCE);
    assert.equal(row.identity.source_map_sha256, files.find(f => f.path === "app.js.map").sha256);
    assert(row.observations.some(o => o.evidence.extractor.operation === "parse-local-source-map" &&
      o.properties.content_available === true && o.properties.content_sha256 === EXPECTED_SOURCE));
  }
  await writeFile(join(evidenceDir, side + ".json"), raw, { flag: "wx" });
  return { exit_code: 0, operation: doc.operation, provider: doc.provider.id,
    evidence_id: doc.evidence_id, evidence_stdout_sha256: sha(raw),
    evidence_stdout_bytes: Buffer.byteLength(raw), graph_id: graph.graph_id,
    graph_nodes: graph.nodes.length, complete: true, truncated: false,
    inventoried_relevant_files: stats.relevant_files, parsed_javascript_files: 1,
    skipped_javascript_files: 0, parse_failures: 0, parsed_bundle_sha256: js.identity.sha256,
    map_nodes: mapNodes.length, embedded_original_content_sha256: originals.map(n => n.identity.source_sha256) };
}

const work = args.work ? resolve(args.work) : await mkdtemp(join(tmpdir(), "releaseguard-map-"));
if (args.work) await mkdir(work); // must not merge with or overwrite an existing fixture
try {
  assert.equal(sha(ORIGINAL), EXPECTED_SOURCE);
  const baseline = join(work, "baseline"), publicDir = join(work, "public"), privateDir = join(work, "private");
  const evidenceDir = join(work, "evidence");
  await mkdir(baseline);
  await mkdir(evidenceDir);
  const built = await minify({ [SOURCE_NAME]: ORIGINAL }, { module: true, mangle: true,
    compress: true, format: { comments: false }, sourceMap: { filename: "app.js", includeSources: true } });
  assert.equal(sha(built.code), EXPECTED_JS);
  assert(!built.code.includes(MARKER) && !built.code.includes("sourceMappingURL"));
  await writeFile(join(baseline, "app.js"), built.code);
  await writeFile(join(baseline, "app.js.map"), built.map);
  await writeFile(join(baseline, "package.json"), JSON.stringify({
    name: "source-map-fixture", version: "1.0.0", type: "module", main: "app.js" }) + "\n");
  const before = await inventory(baseline);
  const split = JSON.parse(run(args.python, ["-I", "-m", "releaseguard", "split-source-maps",
    "--root", baseline, "--public", publicDir, "--private", privateDir], work));
  assert.equal(split.ok, true);
  assert.deepEqual(await inventory(baseline), before, "Input changed");
  const published = await inventory(publicDir), archived = await inventory(privateDir);
  assert.deepEqual(published, before.filter(f => f.path !== "app.js.map"));
  assert.deepEqual(archived, before.filter(f => f.path === "app.js.map"));
  for (const { path } of published) {
    const bytes = await readFile(join(publicDir, path));
    assert(!bytes.includes(Buffer.from(MARKER)) && !bytes.includes(Buffer.from(ORIGINAL)));
  }
  const results = {};
  for (const [name, dir, files] of [["baseline", baseline, before], ["public", publicDir, published],
    ["private", privateDir, archived]]) {
    const trace = await recover(dir, files);
    if (name === "public") assert.deepEqual(trace, []);
    else {
      assert.equal(trace.length, 1);
      assert(trace[0].exact_text && trace[0].marker_present);
      assert.deepEqual(trace[0].position, { source: SOURCE_NAME, line: 2, column: 16, name: "quote" });
    }
    results[name] = { inventory: files, trace_mapping: trace };
    if (name !== "private") {
      // The only executed code is our own fixed, hash-checked, synthetic Terser output.
      const sample = await import(pathToFileURL(join(dir, "app.js")).href);
      const values = [-2, 0, 1, 11].map(x => sample.quote(x));
      assert.deepEqual(values, [-11, 3, 10, 80]);
      results[name].fixture_outputs = values;
      if (!args["consumer-only"]) results[name].rea = await examineWithRea(
        dir, files, name === "baseline" ? 1 : 0, evidenceDir, name);
    }
  }
  const report = { schema: "releaseguard/source-map-recovery/v1", ok: true,
    mode: args["consumer-only"] ? "trace-mapping-only" : "rea-cli-and-trace-mapping",
    rea_cli_executed: !args["consumer-only"],
    recorded_at: new Date().toISOString(), node: process.version, host: process.platform + "/" + process.arch,
    dependency_lock_sha256: sha(await readFile(join(tools, "package-lock.json"))), tools: toolsUsed,
    original_sha256: EXPECTED_SOURCE, sides: results,
    repacked_js_control: await rejectRepackedMap(work, baseline, built.map),
    scope: "Exact embedded original source recovery through a shipped external v3 map, on this fixture only.",
    limitations: ["REA's CLI reports the embedded original's digest, which this probe compares to the known source; trace-mapping returns the actual text.",
      "Generated JavaScript remains analyzable. No claim about recovering equivalent logic, an AI session, remote CDN/header exposure, or unrelated formats."] };
  const serialized = JSON.stringify(report, null, 2) + "\n";
  if (args.out) await writeFile(resolve(args.out), serialized, { flag: "wx" });
  process.stdout.write(serialized);
} finally {
  if (!args.work) await rm(work, { recursive: true, force: true });
}
