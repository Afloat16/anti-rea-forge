import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { createReleaseGuard, ReleaseGuardError } from "../src/index.js";

const execute = promisify(execFile);
const python = process.env.RELEASEGUARD_PYTHON || "python";
const client = createReleaseGuard({ python });
const fixtures = fileURLToPath(new URL("./fixtures/", import.meta.url));
const cliError = (error) => error instanceof ReleaseGuardError && error.code === "CLI_ERROR" && error.exitCode === 2;

async function release(t) {
  const base = await mkdtemp(join(tmpdir(), "releaseguard-js-integration-"));
  t.after(() => rm(base, { recursive: true, force: true }));
  const root = join(base, "dist");
  const policy = join(base, "rules.json");
  await mkdir(root);
  await writeFile(join(root, "app.js"), 'export const publicMessage = "hello";\n');
  await writeFile(policy, JSON.stringify({ version: 1, forbid_literals: ["synthetic-integration-secret"] }));
  return { base, root, policy };
}

test("installed Python core passes clean files and rejects a configured literal", async (t) => {
  const { root, policy } = await release(t);
  const passed = await client.scanRelease({ root, policy });
  assert.equal(passed.ok, true);
  assert.equal(passed.exitCode, 0);
  assert.equal(passed.files.length, 1);
  await writeFile(join(root, "app.js"), 'const value = "synthetic-integration-secret";\n');
  const rejected = await client.scanRelease({ root, policy });
  assert.equal(rejected.ok, false);
  assert.equal(rejected.exitCode, 3);
  assert.ok(rejected.findings.some((finding) => finding.code === "forbidden_literal"));
  assert.equal(JSON.stringify(rejected).includes("synthetic-integration-secret"), false);
});

test("invalid policy and missing files remain errors, never policy passes", async (t) => {
  const { root, policy } = await release(t);
  await writeFile(policy, '{"version":1,"typo_option":true}');
  await assert.rejects(client.scanRelease({ root, policy }), cliError);
  await assert.rejects(client.audit(join(root, "missing.exe")), cliError);
});

test("manifest verification transports trusted product/version and detects mutation", async (t) => {
  const { base, root } = await release(t);
  await execute(python, ["-I", join(fixtures, "materials.py"), base], { timeout: 10_000, maxBuffer: 4096 });
  const options = { manifest: join(base, "manifest.json"), root, publicKey: join(base, "public.pem"),
    product: "--Demo 产品", release: "2.0" };
  assert.equal((await client.verifyManifest(options)).files_verified, 1);
  await assert.rejects(client.verifyManifest({ ...options, release: "wrong" }), cliError);
  await writeFile(join(root, "app.js"), "modified\n");
  await assert.rejects(client.verifyManifest(options), cliError);
});

test("license verification transports the subject and feature requirements", async (t) => {
  const { base } = await release(t);
  await execute(python, ["-I", join(fixtures, "materials.py"), base], { timeout: 10_000, maxBuffer: 4096 });
  const options = { license: join(base, "license.json"), publicKey: join(base, "public.pem"),
    product: "--Demo 产品", subject: "-customer", requiredFeatures: ["export"] };
  assert.equal((await client.verifyLicense(options)).claims.subject, "-customer");
  await assert.rejects(client.verifyLicense({ ...options, subject: "other" }), cliError);
  await assert.rejects(client.verifyLicense({ ...options, requiredFeatures: ["admin"] }), cliError);
});

test("isolated Python ignores a cwd module and a module on PYTHONPATH", async (t) => {
  const { base } = await release(t);
  const pythonPath = join(base, "python-path");
  await mkdir(pythonPath);
  const shadow = "from pathlib import Path\nPath('shadow-was-executed').write_text('bad')\nraise RuntimeError('shadow imported')\n";
  await writeFile(join(base, "releaseguard.py"), shadow);
  await writeFile(join(pythonPath, "releaseguard.py"), shadow);
  const result = await execute(process.execPath, [join(fixtures, "scan.mjs"), python, "dist", "rules.json"], {
    cwd: base,
    env: { ...process.env, PYTHONPATH: pythonPath },
    timeout: 10_000,
    maxBuffer: 1024 * 1024,
  });
  assert.equal(JSON.parse(result.stdout).ok, true);
  await assert.rejects(access(join(base, "shadow-was-executed")));
});
