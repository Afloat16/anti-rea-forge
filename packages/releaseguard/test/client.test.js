import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { createClient } from "../src/client.js";
import { createReleaseGuard, ReleaseGuardError } from "../src/index.js";

function scan(ok = true) {
  return { ok, root: resolve("dist"), findings: ok ? [] : [{ code: "forbidden_literal" }],
    files: [{ path: "app.js", size: 32, sha256: "b".repeat(64) }],
    checks: { scan_completed: true, files_scanned: 1 }, notes: [] };
}

function fake(document = scan(), options = {}) {
  const calls = [];
  const client = createClient({ python: "trusted Python", timeoutMs: 10_000, ...options }, async (...args) => {
    calls.push(args);
    return { exitCode: document.ok ? 0 : 3, stdout: JSON.stringify(document), stderr: "" };
  });
  return { client, calls };
}

const hasCode = (code) => (error) => error instanceof ReleaseGuardError && error.code === code;

test("public API is a frozen read-only check surface", () => {
  const client = createReleaseGuard();
  assert.deepEqual(Object.keys(client).sort(), ["audit", "gate", "scanRelease", "verifyLicense", "verifyManifest"]);
  assert.ok(Object.isFrozen(client));
});

test("scan uses isolated Python and exact absolute argv for spaces, Unicode and shell characters", async () => {
  const { client, calls } = fake();
  const root = "output with spaces/路径;$(ignored)`echo ignored`";
  const policy = "policy name.json";
  const result = await client.scanRelease({ root, policy });
  assert.equal(result.exitCode, 0);
  assert.deepEqual(calls[0][1], ["-I", "-m", "releaseguard", "scan-release",
    `--root=${resolve(root)}`, `--policy=${resolve(policy)}`]);
  assert.equal(calls[0][0], "trusted Python");
  assert.equal(calls[0][2].timeoutMs, 10_000);
  assert.ok(Object.isFrozen(result));
});

test("policy failures return exitCode 3 without throwing", async () => {
  const { client } = fake(scan(false));
  const result = await client.scanRelease({ root: "dist", policy: "rules.json" });
  assert.equal(result.ok, false);
  assert.equal(result.exitCode, 3);
  assert.equal(result.findings[0].code, "forbidden_literal");
});

test("a relative interpreter path is fixed at client creation", async () => {
  const { client, calls } = fake(scan(), { python: "./venv/bin/python" });
  await client.scanRelease({ root: "dist", policy: "rules.json" });
  assert.equal(calls[0][0], resolve("./venv/bin/python"));
});

test("gate forwards native arguments and preserves its detailed report", async () => {
  const report = { ...scan(), artifact: { path: resolve("app.exe"), size: 123, sha256: "a".repeat(64), format: "pe" } };
  const { client, calls } = fake(report);
  const result = await client.gate({ artifact: "-app.exe", policy: "rules.json", root: "dist" });
  assert.equal(result.artifact.sha256, "a".repeat(64));
  assert.deepEqual(calls[0][1].slice(3), ["gate", resolve("-app.exe"),
    `--policy=${resolve("rules.json")}`, `--root=${resolve("dist")}`]);
});

test("audit distinguishes informational warnings from strict policy failure", async () => {
  const report = { ok: true, policy_passed: false,
    audit: { format: "PE32+", kind: "exe", warnings: ["Example warning"], notes: [] } };
  const normal = fake(report);
  assert.equal((await normal.client.audit("app.exe")).ok, true);
  assert.equal(normal.calls[0][1].includes("--strict"), false);
  const strict = fake({ ...report, ok: false });
  assert.equal((await strict.client.audit("app.exe", { strict: true })).exitCode, 3);
  assert.equal(strict.calls[0][1].at(-1), "--strict");
  await assert.rejects(normal.client.audit("app.exe", { strict: true }), hasCode("PROTOCOL_ERROR"));
});

test("manifest options preserve a product beginning with a dash as data", async () => {
  const { client, calls } = fake({ ok: true, product: "--产品", release: "2.0", files_verified: 2 });
  assert.equal((await client.verifyManifest({ manifest: "manifest.json", root: "dist", publicKey: "public.pem",
    product: "--产品", release: "2.0" })).files_verified, 2);
  assert.ok(calls[0][1].includes("--product=--产品"));
  assert.ok(calls[0][1].includes("--release=2.0"));
  await assert.rejects(client.verifyManifest({ manifest: "manifest.json", root: "dist", publicKey: "public.pem",
    product: "wrong", release: "2.0" }), hasCode("PROTOCOL_ERROR"));
});

test("license results must match the requested identity and required features", async () => {
  const claims = { version: 1, product: "MyApp", subject: "customer", license_id: "sample-id",
    issued_at: "2026-01-01T00:00:00Z", not_before: "2026-01-01T00:00:00Z",
    expires_at: "2027-01-01T00:00:00Z", features: ["export", "read"] };
  const { client, calls } = fake({ ok: true, claims });
  const options = { license: "license.json", publicKey: "public.pem", product: "MyApp",
    subject: "customer", requiredFeatures: ["export"] };
  assert.deepEqual((await client.verifyLicense(options)).claims, claims);
  assert.equal(calls[0][1].at(-1), "--require-feature=export");
  await assert.rejects(client.verifyLicense({ ...options, subject: "wrong" }), hasCode("PROTOCOL_ERROR"));
  await assert.rejects(client.verifyLicense({ ...options, requiredFeatures: ["write"] }), hasCode("PROTOCOL_ERROR"));
});

test("feature expectations cannot be changed while the child is running", async () => {
  let finish;
  const client = createClient({}, () => new Promise((resolve) => { finish = resolve; }));
  const features = ["export"];
  const check = client.verifyLicense({ license: "license.json", publicKey: "public.pem", product: "MyApp",
    requiredFeatures: features });
  features.pop();
  finish({ exitCode: 0, stderr: "", stdout: JSON.stringify({ ok: true,
    claims: { version: 1, product: "MyApp", subject: "customer", license_id: "id", issued_at: "t",
      not_before: "t", expires_at: "t", features: [] } }) });
  await assert.rejects(check, hasCode("PROTOCOL_ERROR"));
});

test("invalid, ambiguous or incomplete output never becomes a pass", async (t) => {
  const cases = [
    { stdout: "" },
    { stdout: '{"ok":true' },
    { stdout: '{"ok":true}\n{"ok":true}' },
    { stdout: '{"ok":true}' },
    { stdout: JSON.stringify({ ...scan(), error: "failed" }) },
    { stdout: JSON.stringify({ ...scan(), ok: "true" }) },
    { stdout: JSON.stringify({ ...scan(), findings: [{ code: "leak" }] }) },
    { stdout: JSON.stringify({ ...scan(), checks: { scan_completed: false } }) },
    { stdout: JSON.stringify({ ...scan(), files: [] }) },
    { stdout: JSON.stringify({ ...scan(), files: [{ path: "app.js", size: 32, sha256: "bad" }] }) },
    { stdout: JSON.stringify({ ...scan(), checks: { scan_completed: true, files_scanned: 2 } }) },
    { stdout: JSON.stringify({ ...scan(), files: [...scan().files, ...scan().files], checks: { scan_completed: true, files_scanned: 2 } }) },
    { stdout: JSON.stringify(scan()), exitCode: 3 },
    { stdout: JSON.stringify(scan(false)), exitCode: 0 },
    { stdout: JSON.stringify(scan()), stderr: "unexpected warning" },
    { stdout: JSON.stringify(scan()).replace('"ok":true', '"ok":false,"ok":true') },
    { stdout: JSON.stringify(scan()).replace('"ok":true', '"ok":false,"\\u006fk":true') },
    { stdout: JSON.stringify(scan()).replace('"size":32', '"size":1e400') },
    { stdout: JSON.stringify({ ...scan(), nested: JSON.parse('['.repeat(70) + '0' + ']'.repeat(70)) }) },
  ];
  for (const [index, result] of cases.entries()) {
    await t.test(`case ${index}`, async () => {
      const client = createClient({}, async () => ({ exitCode: 0, stdout: "", stderr: "", ...result }));
      await assert.rejects(client.scanRelease({ root: "dist", policy: "rules.json" }), hasCode("PROTOCOL_ERROR"));
    });
  }
});

test("transport preserves additional nested report information and escaped keys", async () => {
  const document = { ...scan(), extra: { 'quote"key': { empty: {}, array: [false, null, "value"] } } };
  const { client } = fake(document);
  assert.deepEqual((await client.scanRelease({ root: "dist", policy: "rules.json" })).extra, document.extra);
});

test("tool errors expose bounded diagnostics only through deliberate access", async () => {
  const diagnostic = '{"ok":false,"error":"sensitive/path/example"}';
  const client = createClient({}, async () => ({ exitCode: 2, stdout: "", stderr: diagnostic }));
  await assert.rejects(client.scanRelease({ root: "dist", policy: "rules.json" }), (error) => {
    assert.equal(error.code, "CLI_ERROR");
    assert.equal(error.exitCode, 2);
    assert.equal(error.diagnostic, diagnostic);
    assert.equal(error.message.includes("sensitive"), false);
    assert.equal(Object.keys(error).includes("diagnostic"), false);
    return true;
  });
});

test("client settings and unknown options fail early", () => {
  for (const options of [null, [], { python: "" }, { python: "python\u0000" }, { python: 3 },
    { timeoutMs: 0 }, { timeoutMs: 600_001 }, { timeoutMs: 1.5 }, { maxOutputBytes: 1023 },
    { maxOutputBytes: 16 * 1024 * 1024 + 1 }, { shell: true }]) {
    assert.throws(() => createReleaseGuard(options), hasCode("INVALID_ARGUMENT"));
  }
});

test("call arguments reject typoed, empty, control and invalid feature inputs", async () => {
  const { client, calls } = fake();
  const check = (promise) => assert.rejects(promise, hasCode("INVALID_ARGUMENT"));
  await check(client.scanRelease({ root: "dist", policy: "rules.json", rooot: "ignored" }));
  await check(client.scanRelease({ root: "", policy: "rules.json" }));
  await check(client.scanRelease({ root: "bad\npath", policy: "rules.json" }));
  await check(client.scanRelease({ root: "bad\ud800path", policy: "rules.json" }));
  await check(client.scanRelease({ root: "x".repeat(32_769), policy: "rules.json" }));
  await check(client.scanRelease({ root: "dist", policy: "rules.json" }, { signal: {} }));
  await check(client.audit("app.exe", { strict: "yes" }));
  await check(client.verifyLicense({ license: "x", publicKey: "x", product: "x", requiredFeatures: ["x", "x"] }));
  await check(client.verifyLicense({ license: "x", publicKey: "x", product: "x", requiredFeatures: "export" }));
  assert.equal(calls.length, 0);
});
