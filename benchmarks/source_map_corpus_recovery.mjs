/**
 * A real REA/trace-mapping corpus of owned builds, with explicit rejection controls.
 * npm ci --prefix benchmarks/recovery-tools --omit=optional --ignore-scripts
 * node benchmarks/source_map_corpus_recovery.mjs --python /trusted/python --out report.json
 * --work DIR retains fixtures and raw evidence in a new directory.
 * --baseline-python /trusted/v1.1/python additionally checks the prior disclosure gap.
 * Source-built REA: --rea-source DIR --rea-source-commit FULL_SHA
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
import { selectReaRuntime } from "./rea_runtime.mjs";

const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const json = async path => JSON.parse(await readFile(path, "utf8"));
const { values: args } = parseArgs({ options: {
  tools: { type: "string" }, python: { type: "string", default: "python" },
  out: { type: "string" }, work: { type: "string" }, "baseline-python": { type: "string" },
  "rea-source": { type: "string" }, "rea-source-commit": { type: "string" },
} });
const tools = resolve(args.tools ?? join(dirname(fileURLToPath(import.meta.url)), "recovery-tools"));
const localRequire = createRequire(join(tools, "package.json"));
const lock = await json(join(tools, "package-lock.json"));
const toolsUsed = {};
for (const [name, version] of Object.entries({ terser: "5.44.1", "@jridgewell/trace-mapping": "0.3.31" })) {
  assert.equal((await json(join(tools, "node_modules", name, "package.json"))).version, version);
  const locked = lock.packages["node_modules/" + name];
  assert.equal(locked?.version, version);
  assert.match(locked.integrity, /^sha512-/);
  toolsUsed[name] = { version, npm_integrity: locked.integrity };
}
const { minify } = localRequire("terser");
const mapping = localRequire("@jridgewell/trace-mapping");
const reaRuntime = await selectReaRuntime({ tools, source: args["rea-source"], sourceCommit: args["rea-source-commit"] });
toolsUsed["rea-agents"] = reaRuntime.record;
const work = args.work ? resolve(args.work) : await mkdtemp(join(tmpdir(), "releaseguard-map-corpus-"));
if (args.work) await mkdir(work);
const childTmp = join(work, "tmp");
await mkdir(childTmp);
const env = { ...process.env, TMPDIR: childTmp, TMP: childTmp, TEMP: childTmp };
const python = args.python.includes("/") || args.python.includes("\\") ? resolve(args.python) : args.python;
const inputs = [-2, 0, 1, 11];
let reaInvocations = 0;

function run(program, argv, expectedExit = 0) {
  const p = spawnSync(program, argv, { cwd: work, env, encoding: "utf8", timeout: 120_000,
    maxBuffer: 32 * 1024 * 1024, killSignal: "SIGKILL", shell: false });
  if (p.error || p.signal || p.status !== expectedExit) {
    throw new Error("Command failed (never a protection result): " + program + " " + argv[0] +
      "; exit=" + p.status + "; signal=" + p.signal + "; " + String(p.error ?? "") +
      " " + (p.stdout ?? "").slice(0, 1200) + " " + (p.stderr ?? "").slice(0, 1200));
  }
  return p;
}

async function put(root, path, bytes) {
  await mkdir(dirname(join(root, path)), { recursive: true });
  await writeFile(join(root, path), bytes, { flag: "wx" });
}

async function inventory(root) {
  const rows = [];
  async function visit(relative) {
    for (const entry of await readdir(join(root, relative), { withFileTypes: true })) {
      const path = relative ? relative + "/" + entry.name : entry.name;
      if (entry.isDirectory()) await visit(path);
      else {
        assert(entry.isFile(), "Unexpected link or special file: " + path);
        const bytes = await readFile(join(root, path));
        rows.push({ path, size: bytes.length, sha256: sha(bytes) });
      }
    }
  }
  await visit("");
  return rows.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

function source(name, body) {
  return "/* owned source-only canary: rg_corpus_" + name + " */\n" + body + "\n";
}

const corpus = [
  { id: "multiple-sources", entry: "app.js", exportName: "bundleQuote", expected: [-10, 4, 11, 79],
    features: ["three original modules", "one minified ESM bundle"], bundles: [
      { path: "app.js", sources: {
        "units.js": source("units", "export function subtotal(quantity) { return quantity * 7; }"),
        "fees.js": source("fees", "export function fee(quantity) { return quantity > 10 ? 2 : 4; }"),
        "entry.js": source("entry", "export function bundleQuote(quantity) { return subtotal(quantity) + fee(quantity); }"),
      } },
    ] },
  { id: "multiple-bundles", entry: "assets/main.js", exportName: "quote", expected: [-16, 2, 11, 101],
    features: ["two bundles with local import", "nested output directories", "three original modules"], bundles: [
      { path: "assets/main.js", sources: {
        "src/main.js": source("main", "import { base, surcharge } from './chunk.js';\nexport function quote(quantity) { return base(quantity) + surcharge(); }"),
      } },
      { path: "assets/chunk.js", sources: {
        "src/base.js": source("base", "export function base(quantity) { return quantity * 9; }"),
        "src/surcharge.js": source("surcharge", "export function surcharge() { return 2; }"),
      } },
    ] },
  { id: "unicode-escaped", entry: "assets/应用.js", exportName: "describe",
    expected: ["数量 -2，金额 -10 欧元", "数量 0，金额 0 欧元", "数量 1，金额 5 欧元", "数量 11，金额 55 欧元"],
    features: ["Unicode paths, identifiers and source text", "JSON Unicode-escaped keys and strings"], bundles: [
      { path: "assets/应用.js", escapeMap: true, sources: {
        "源/费率.js": source("unicode_rate", "export const 币种 = '欧元';\nexport function 金额(数量) { return 数量 * 5; }"),
        "源/报价-🧮.js": source("unicode_quote", "export function describe(数量) { return `数量 ${数量}，金额 ${金额(数量)} ${币种}`; }"),
      } },
    ] },
  { id: "partial-originals", entry: "partial.js", exportName: "quote", expected: [6, 6, 10, 50],
    features: ["two mapped modules", "one sourcesContent entry deliberately null"], bundles: [
      { path: "partial.js", omitted: ["helper-original.js"], sources: {
        "helper-original.js": source("omitted_helper", "export function clamp(quantity) { return Math.max(0, quantity); }"),
        "quote-original.js": source("partial_quote", "export function quote(quantity) { return clamp(quantity) * 4 + 6; }"),
      } },
    ] },
];

async function compile(bundle) {
  const built = await minify(bundle.sources, { module: true, mangle: true, compress: true,
    format: { comments: false, ascii_only: true }, sourceMap: { filename: bundle.path, includeSources: true } });
  assert(!built.code.includes("rg_corpus_") && !built.code.includes("sourceMappingURL"));
  const document = JSON.parse(built.map);
  assert.deepEqual([...document.sources].sort(), Object.keys(bundle.sources).sort());
  for (const [i, name] of document.sources.entries()) {
    assert.equal(document.sourcesContent[i], bundle.sources[name]);
    if (bundle.omitted?.includes(name)) document.sourcesContent[i] = null;
  }
  let mapText = JSON.stringify(document);
  if (bundle.escapeMap) mapText = mapText.replace('"sourcesContent"', '"sourcesCont\\u0065nt"')
    .replace('"sources"', '"sourc\\u0065s"')
    .replace(/[^\x20-\x7e]/g, character => "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"));
  return { code: built.code, mapText, document,
    originals: document.sources.map((name, i) => ({ name, text: bundle.sources[name],
      content_available: document.sourcesContent[i] !== null })) };
}

async function traceRecover(directory, mapRecords) {
  const recovered = [];
  for (const record of mapRecords) {
    const decoded = new mapping.AnyMap(await json(join(directory, record.path)));
    assert.deepEqual([...decoded.sources].sort(), record.originals.map(o => o.name).sort());
    for (const original of record.originals) {
      const content = mapping.sourceContentFor(decoded, original.name);
      assert.equal(content, original.content_available ? original.text : null);
      let sample;
      mapping.eachMapping(decoded, row => { if (!sample && row.source === original.name) sample = row; });
      assert(sample, "Original lacks a real mapping: " + original.name);
      const traced = mapping.originalPositionFor(decoded, { line: sample.generatedLine, column: sample.generatedColumn });
      assert.deepEqual(traced, { source: sample.source, line: sample.originalLine,
        column: sample.originalColumn, name: sample.name });
      recovered.push({ map: record.path, source: original.name, content_available: content !== null,
        exact_text: content === null ? null : content === original.text,
        content_sha256: content === null ? null : sha(content),
        generated_position: { line: sample.generatedLine, column: sample.generatedColumn }, original_position: traced });
    }
  }
  return recovered;
}

async function examineWithRea(directory, files, maps, evidenceDir, name, coverage = "complete") {
  const raw = run(process.execPath, [reaRuntime.entry, "analyze-javascript-application", directory, "--format", "json"]).stdout;
  ++reaInvocations;
  const document = JSON.parse(raw);
  assert.equal(document.operation, "analyze_javascript_application");
  assert.equal(document.provider?.id, "rea-javascript-application");
  assert(!Object.hasOwn(document, "error"));
  const result = document.normalized_result;
  assert.equal(result.format, "directory");
  assert.equal(result.source_selection?.unselected_files ?? 0, 0);
  assert.deepEqual(result.integrity_contradictions, []);
  const stats = result.statistics;
  const jsFiles = files.filter(f => /\.m?js$/.test(f.path));
  assert.equal(stats.relevant_files, files.length);
  assert.equal(stats.parsed_javascript_files, jsFiles.length);
  assert.equal(stats.skipped_javascript_files, 0);
  assert.equal(stats.parse_failures, 0);
  assert.equal(stats.invalid_utf8_files, 0);
  const graph = result.graph;
  assert.equal(graph.coverage.status, coverage, "Incomplete analysis cannot establish absence");
  assert.equal(graph.coverage.truncated, false);
  for (const file of jsFiles) {
    const node = graph.nodes.find(n => n.kind === "javascript-asset" && n.identity.sha256 === file.sha256);
    assert(node?.observations.some(o => o.properties.path === file.path &&
      o.properties.text_status === "included" && o.properties.parse_status === "complete"), file.path);
  }
  const originals = graph.nodes.filter(n => n.identity.strategy === "source-map-original");
  assert.equal(originals.length, maps.reduce((sum, m) => sum + m.originals.length, 0));
  assert.equal(graph.nodes.filter(n => n.kind === "source-map").length, maps.length);
  const rows = [];
  for (const record of maps) {
    const mapHash = files.find(f => f.path === record.path).sha256;
    for (const original of record.originals) {
      const expectedHash = original.content_available ? sha(original.text) : null;
      const node = originals.find(n => n.identity.source_map_sha256 === mapHash && n.identity.original_source === original.name);
      assert(node, "REA must observe the expected original: " + original.name);
      assert.equal(node.identity.source_sha256, expectedHash);
      assert(node.observations.some(o => o.evidence.extractor.operation === "parse-local-source-map" &&
        o.properties.content_available === original.content_available && o.properties.content_sha256 === expectedHash));
      rows.push({ map: record.path, source: original.name,
        content_available: original.content_available, content_sha256: expectedHash });
    }
  }
  await put(evidenceDir, name + ".json", raw);
  return { exit_code: 0, provider: document.provider.id, operation: document.operation,
    evidence_id: document.evidence_id, evidence_stdout_sha256: sha(raw),
    evidence_stdout_bytes: Buffer.byteLength(raw), graph_id: graph.graph_id,
    coverage: graph.coverage, graph_nodes: graph.nodes.length,
    inventoried_relevant_files: stats.relevant_files, parsed_javascript_files: stats.parsed_javascript_files,
    skipped_javascript_files: 0, parse_failures: 0, invalid_utf8_files: 0,
    parsed_bundle_sha256: jsFiles.map(f => f.sha256), map_nodes: maps.length,
    original_declarations: rows.length, exact_embedded_originals: rows.filter(r => r.content_available).length,
    originals: rows };
}

async function supportedBuild(spec) {
  const root = join(work, spec.id), baseline = join(root, "baseline"), publicDir = join(root, "public");
  const privateDir = join(root, "private"), restored = join(root, "private-restored"), evidence = join(root, "evidence");
  await mkdir(root);
  const records = [];
  for (const bundle of spec.bundles) {
    const built = await compile(bundle);
    await put(baseline, bundle.path, built.code);
    await put(baseline, bundle.path + ".map", built.mapText);
    records.push({ path: bundle.path + ".map", originals: built.originals });
  }
  await put(baseline, "package.json", JSON.stringify({ name: "owned-" + spec.id, version: "1.0.0", type: "module", main: spec.entry }) + "\n");
  const before = await inventory(baseline);
  const splitRaw = run(python, ["-I", "-m", "releaseguard", "split-source-maps", "--root", baseline,
    "--public", publicDir, "--private", privateDir]).stdout;
  assert.equal(JSON.parse(splitRaw).ok, true);
  await put(evidence, "split.json", splitRaw);
  const published = await inventory(publicDir), privateFiles = await inventory(privateDir);
  assert.deepEqual(published, before.filter(f => !f.path.endsWith(".map")));
  assert.deepEqual(privateFiles, before.filter(f => f.path.endsWith(".map")));
  await cp(publicDir, restored, { recursive: true, force: false, errorOnExist: true });
  for (const file of privateFiles) await put(restored, file.path, await readFile(join(privateDir, file.path)));
  assert.deepEqual(await inventory(restored), before);
  const sides = {};
  for (const [name, directory, files] of [["baseline", baseline, before], ["public", publicDir, published],
    ["private_restored", restored, before]]) {
    const selected = name === "public" ? [] : records;
    const trace = await traceRecover(directory, selected);
    const module = await import(pathToFileURL(join(directory, spec.entry)).href);
    const values = inputs.map(value => module[spec.exportName](value));
    assert.deepEqual(values, spec.expected);
    for (const file of files.filter(f => !f.path.endsWith(".map"))) {
      const bytes = await readFile(join(directory, file.path));
      assert(!bytes.includes(Buffer.from("rg_corpus_")));
      for (const record of records) for (const original of record.originals)
        assert(!bytes.includes(Buffer.from(original.text)), "Original copied into public artifacts");
    }
    sides[name] = { inventory: files, trace_mapping: trace, fixture_inputs: inputs, fixture_outputs: values,
      rea: await examineWithRea(directory, files, selected, evidence, name) };
    assert.deepEqual(await inventory(directory), files, "Analyzed artifacts changed: " + name);
  }
  const privateTrace = await traceRecover(privateDir, records);
  assert.deepEqual(await inventory(privateDir), privateFiles, "Private map bytes changed during recovery");
  assert.deepEqual(await inventory(baseline), before, "Original release must remain unchanged");
  return { id: spec.id, features: spec.features, bundle_count: spec.bundles.length,
    declared_originals: records.flatMap(m => m.originals.map(o => ({ map: m.path, source: o.name,
      original_sha256: sha(o.text), content_shipped_in_baseline_map: o.content_available }))),
    input_unchanged: true, public_asset_bytes_unchanged: true, private_map_bytes_unchanged: true,
    private_restoration_recreates_inventory: true, sides,
    private: { inventory: privateFiles, trace_mapping: privateTrace } };
}

async function indexedControl() {
  const root = join(work, "unsupported-indexed"), baseline = join(root, "baseline");
  const publicDir = join(root, "public"), privateDir = join(root, "private"), evidence = join(root, "evidence");
  await mkdir(root);
  const first = await compile({ path: "part1.js", sources: {
    "indexed-unit.js": source("indexed_unit", "export function unit(quantity) { return quantity * 2; }"),
  } });
  const second = await compile({ path: "part2.js", sources: {
    "indexed-main.js": source("indexed_main", "export function indexedTotal(quantity) { return unit(quantity) + 3; }"),
  } });
  assert(!first.code.includes("\n") && !second.code.includes("\n"));
  const document = { version: 3, file: "indexed.js", sections: [
    { offset: { line: 0, column: 0 }, map: { version: 3, sections: [
      { offset: { line: 0, column: 0 }, map: first.document },
    ] } },
    { offset: { line: 1, column: 0 }, map: second.document },
  ] };
  await put(baseline, "indexed.js", first.code + "\n" + second.code);
  await put(baseline, "indexed.js.map", JSON.stringify(document));
  await put(baseline, "package.json", '{"name":"owned-indexed","type":"module","main":"indexed.js"}\n');
  const before = await inventory(baseline);
  const records = [{ path: "indexed.js.map", originals: [...first.originals, ...second.originals] }];
  const trace = await traceRecover(baseline, records);
  const rea = await examineWithRea(baseline, before, records, evidence, "baseline");
  const module = await import(pathToFileURL(join(baseline, "indexed.js")).href);
  assert.deepEqual(inputs.map(q => module.indexedTotal(q)), [-1, 3, 5, 25]);
  const failure = run(python, ["-I", "-m", "releaseguard", "split-source-maps", "--root", baseline,
    "--public", publicDir, "--private", privateDir], 2);
  const denied = JSON.parse(failure.stderr);
  assert.equal(denied.ok, false);
  assert.match(denied.error, /flat v3 external source map/);
  for (const directory of [publicDir, privateDir]) await assert.rejects(lstat(directory), { code: "ENOENT" });
  assert.deepEqual(await inventory(baseline), before);
  await put(evidence, "split-rejection.json", failure.stderr);
  return { id: "nested-indexed-map", disposition: "unsupported-rejected", counted_as_protected_build: false,
    baseline: { inventory: before, trace_mapping: trace, rea }, split_exit_code: 2, split_error: denied.error,
    public_output_absent: true, private_output_absent: true, input_unchanged: true };
}

async function disclosureControl(id, mappings) {
  const root = join(work, id), release = join(root, "renamed-release"), selected = join(root, "format-selected-copy");
  const evidence = join(root, "evidence"), policy = join(root, "policy.json");
  await mkdir(root);
  await writeFile(policy, '{"version":1}\n', { flag: "wx" });
  const original = source("incomplete_map", "export const unpublishedRate = 79;");
  const document = { version: 3, sources: ["owned-original.js"], sourcesContent: [original] };
  if (mappings !== undefined) document.mappings = mappings;
  const payload = JSON.stringify(document).replace('"sourcesContent"', '"sourcesCont\\u0065nt"');
  assert.equal(JSON.parse(payload).sourcesContent[0], original);
  assert(!payload.includes("sourcesContent"));
  await put(release, "original-data.json", payload);
  // Explicit format selection changes only the filename, never the payload.
  await put(selected, "app.js.map", payload);
  await put(selected, "app.js", "export const rate=79;");
  await put(selected, "package.json", '{"name":"owned-incomplete-map","type":"module","main":"app.js"}\n');
  const before = await inventory(release), selectedFiles = await inventory(selected);
  assert.equal(before[0].sha256, selectedFiles.find(f => f.path === "app.js.map").sha256);
  const records = [{ path: "app.js.map", originals: [{ name: "owned-original.js", text: original, content_available: true }] }];
  // Partial mapping is permitted only for this positive content-recovery control.
  const rea = await examineWithRea(selected, selectedFiles, records, evidence, "recovery", "partial");
  const gate = run(python, ["-I", "-m", "releaseguard", "scan-release", "--root", release, "--policy", policy], 3);
  const denied = JSON.parse(gate.stdout);
  assert.equal(denied.ok, false);
  assert.equal(denied.checks.source_map_scan_completed, true);
  assert(denied.findings.some(f => f.code === "source_map_marker" && f.representation === "json-decoded-key"));
  await put(evidence, "current-gate.json", gate.stdout);
  let prior = null;
  if (args["baseline-python"]) {
    const baselinePython = resolve(args["baseline-python"]);
    const version = run(baselinePython, ["-I", "-c", 'import importlib.metadata; print(importlib.metadata.version("open-release-guard"))']).stdout.trim();
    assert.equal(version, "1.1.0", "Prior-version control must use the published v1.1.0 package");
    const allowed = run(baselinePython, ["-I", "-m", "releaseguard", "scan-release", "--root", release, "--policy", policy]);
    const old = JSON.parse(allowed.stdout);
    assert.equal(old.ok, true);
    assert.deepEqual(old.findings, []);
    await put(evidence, "v1.1.0-gate.json", allowed.stdout);
    prior = { version, exit_code: 0, allowed_disclosure: true, findings: [] };
  }
  assert.deepEqual(await inventory(release), before);
  assert.deepEqual(await inventory(selected), selectedFiles);
  return { id, disposition: "recoverable-disclosure-blocked", counted_as_protected_build: false,
    payload_sha256: sha(payload), payload_bytes: Buffer.byteLength(payload), original_sha256: sha(original),
    explicit_format_selection: "Byte-identical copy of original-data.json named app.js.map; analyst knows the format.",
    ordinary_json_recovers_exact_text: true, rea,
    prior_version_control: prior, current_gate: { exit_code: 3, findings: denied.findings,
      source_map_scan_completed: true }, input_unchanged: true };
}

try {
  const candidateVersion = run(python, ["-I", "-m", "releaseguard", "--version"]).stdout.trim();
  const builds = [];
  for (const spec of corpus) builds.push(await supportedBuild(spec));
  const controls = [await indexedControl(), await disclosureControl("missing-mappings", undefined),
    await disclosureControl("numeric-mappings", 17)];
  await reaRuntime.verifyUnchanged();
  const sum = (side, field) => builds.reduce((total, build) => total + build.sides[side].rea[field], 0);
  const report = { schema: "releaseguard/source-map-corpus-recovery/v1", ok: true,
    recorded_at: new Date().toISOString(), node: process.version, host: process.platform + "/" + process.arch,
    candidate_releaseguard_version: candidateVersion,
    mode: args["rea-source"] ? "rea-source-cli-and-trace-mapping" : "rea-cli-and-trace-mapping",
    tools: toolsUsed, dependency_lock_sha256: sha(await readFile(join(tools, "package-lock.json"))),
    summary: { supported_builds: builds.length, bundles: builds.reduce((total, b) => total + b.bundle_count, 0),
      baseline_original_declarations: sum("baseline", "original_declarations"),
      baseline_unavailable_originals: sum("baseline", "original_declarations") - sum("baseline", "exact_embedded_originals"),
      exact_embedded_originals: Object.fromEntries(["baseline", "public", "private_restored"].map(side => [side, sum(side, "exact_embedded_originals")])),
      functional_samples_per_side: builds.length * inputs.length,
      functional_samples_total: builds.length * inputs.length * 3,
      rea_invocations: reaInvocations, unsupported_indexed_rejected: 1, invalid_mapping_disclosures_blocked: 2,
      prior_v1_1_0_disclosures_allowed: args["baseline-python"] ? 2 : null },
    builds, controls,
    scope: "Exact source text exposed by local hidden external maps in four owned Terser builds; independent format and disclosure rejection controls.",
    limitations: [
      "REA reports original-content digests; trace-mapping returns exact text. All known originals are authored here, so this is not a blind recovery test.",
      "Supported three-sided comparisons require complete, nontruncated REA graphs and unchanged JavaScript bytes. The invalid-mappings controls establish positive recovery only, even though their graphs are partial.",
      "The null source-content entry was unavailable before protection and is excluded from recovered-content totals. Indexed maps are rejected, not claimed as successfully transformed.",
      "The same Terser version builds every corpus member. This is not cross-bundler coverage, equivalent-logic resistance, remote/CDN verification, or an AI-session experiment.",
      "The optional v1.1.0 baseline control checks installed distribution version only. In CI, the preceding Wasm corpus verifies the official wheel bytes and the installed package files of the same interpreter; this script does not independently repeat that byte-identity verification.",
    ] };
  const serialized = JSON.stringify(report, null, 2) + "\n";
  if (args.out) await writeFile(resolve(args.out), serialized, { flag: "wx" });
  process.stdout.write(serialized);
} finally {
  if (!args.work) await rm(work, { recursive: true, force: true });
}
