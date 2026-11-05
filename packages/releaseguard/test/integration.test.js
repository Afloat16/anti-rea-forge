import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

test("one project configuration runs the same release gate through JavaScript", async (t) => {
  const { base, root } = await release(t);
  const configDir = join(base, ".releaseguard");
  await execute(python, ["-I", "-m", "releaseguard", "project-init", "--root=" + root,
    "--product=--Demo 产品", "--out=" + configDir], { timeout: 10_000, maxBuffer: 4096 });
  const config = join(configDir, "project.json");
  const clean = await client.checkProject({ config });
  assert.equal(clean.ok, true);
  assert.equal(clean.files[0].path, "app.js");
  await writeFile(join(root, "app.js.map"), "{}");
  const rejected = await client.checkProject({ config });
  assert.equal(rejected.ok, false);
  assert.equal(rejected.exitCode, 3);
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

test("real signed analysis grants admit one callback and all denied conditions admit none", async (t) => {
  const { base, root } = await release(t);
  await execute(python, ["-I", join(fixtures, "materials.py"), base], { timeout: 10_000, maxBuffer: 4096 });
  const options = { manifest: join(base, "manifest.json"), root, publicKey: join(base, "public.pem"),
    product: "--Demo 产品", release: "2.0", subject: "-customer", audience: "analysis-service",
    operation: "inspect", grant: join(base, "analysis-grant.json") };
  let invoked = 0;
  const handler = () => { invoked += 1; return "owned analysis ran"; };
  const allowed = await client.checkAnalysis(options);
  assert.equal(allowed.authorized, true);
  assert.equal(typeof allowed.validity.expires_at, "string");
  assert.equal(await client.withAnalysisAuthorization(options, handler), "owned analysis ran");
  assert.equal(invoked, 1);
  const { grant, ...withoutGrant } = options;
  const cases = [
    [withoutGrant, "grant_required"],
    [{ ...options, operation: "decompile" }, "operation_not_granted"],
    [{ ...options, subject: "another-reviewer" }, "context_mismatch"],
    [{ ...options, audience: "another-service" }, "context_mismatch"],
    [{ ...options, grant: join(base, "expired-grant.json") }, "grant_expired"],
  ];
  for (const [rejected, reason] of cases) {
    const decision = await client.checkAnalysis(rejected);
    assert.equal(decision.reason, reason);
    assert.equal(decision.authorized, false);
    assert.equal(decision.validity === null, reason === "grant_required");
    await assert.rejects(client.withAnalysisAuthorization(rejected, handler),
      (error) => error instanceof ReleaseGuardError && error.code === "AUTHORIZATION_DENIED");
  }
  await writeFile(join(root, "app.js"), "changed after grant\n");
  assert.equal((await client.checkAnalysis(options)).reason, "release_mismatch");
  await assert.rejects(client.withAnalysisAuthorization(options, handler),
    (error) => error.code === "AUTHORIZATION_DENIED");
  assert.equal(invoked, 1);
});

test("a forged grant and an unreadable grant cannot reach the handler", async (t) => {
  const { base, root } = await release(t);
  await execute(python, ["-I", join(fixtures, "materials.py"), base], { timeout: 10_000, maxBuffer: 4096 });
  const grant = join(base, "analysis-grant.json");
  const document = JSON.parse(await readFile(grant, "utf8"));
  document.signature = Buffer.alloc(64).toString("base64");
  await writeFile(grant, JSON.stringify(document));
  const options = { manifest: join(base, "manifest.json"), root, publicKey: join(base, "public.pem"),
    product: "--Demo 产品", release: "2.0", subject: "-customer", audience: "analysis-service",
    operation: "inspect", grant };
  let invoked = 0;
  const handler = () => { invoked += 1; };
  const denied = await client.checkAnalysis(options);
  assert.equal(denied.reason, "grant_invalid");
  assert.equal(denied.validity, null);
  await assert.rejects(client.withAnalysisAuthorization(options, handler),
    (error) => error.code === "AUTHORIZATION_DENIED");
  await assert.rejects(client.withAnalysisAuthorization({ ...options, grant: join(base, "missing.json") }, handler), cliError);
  assert.equal(invoked, 0);
});

test("the runnable gateway example lists only an authorized release and otherwise exits before tool output", async (t) => {
  const { base, root } = await release(t);
  await execute(python, ["-I", join(fixtures, "materials.py"), base], { timeout: 10_000, maxBuffer: 4096 });
  const example = fileURLToPath(new URL("../../../examples/javascript/authorized-analysis.mjs", import.meta.url));
  const args = [example, "--python=" + python, "--manifest=" + join(base, "manifest.json"),
    "--root=" + root, "--public=" + join(base, "public.pem"), "--product=--Demo 产品", "--release=2.0",
    "--subject=-customer", "--audience=analysis-service"];
  const allowed = await execute(process.execPath, [...args, "--grant=" + join(base, "analysis-grant.json")], {
    timeout: 10_000, maxBuffer: 4096,
  });
  assert.deepEqual(JSON.parse(allowed.stdout), {
    ok: true, tool: "list_release_entries", operation: "inspect", entries: ["app.js"],
  });
  await assert.rejects(execute(process.execPath, args, { timeout: 10_000, maxBuffer: 4096 }), (error) => {
    assert.equal(error.code, 3);
    assert.equal(error.stdout, "");
    assert.equal(JSON.parse(error.stderr).code, "AUTHORIZATION_DENIED");
    return true;
  });
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
