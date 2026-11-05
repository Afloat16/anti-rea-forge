import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { createClient } from "../src/client.js";
import { ReleaseGuardError } from "../src/index.js";

const options = Object.freeze({ manifest: "signed manifest.json", root: "dist/产品", publicKey: "trusted/public.pem",
  product: "--Demo 产品", release: "2.0", subject: "-customer", audience: "analysis-service",
  operation: "inspect", grant: "private grant.json" });
const checks = { grant_signature: true, grant_scope: true, grant_time: true, release_integrity: true };
const deniedReasons = ["grant_required", "grant_invalid", "grant_expired", "grant_not_yet_valid",
  "context_mismatch", "operation_not_granted", "manifest_invalid", "release_mismatch"];
const hasCode = (code) => (error) => error instanceof ReleaseGuardError && error.code === code;

function timestamp(milliseconds) {
  return new Date(Math.floor(milliseconds / 1000) * 1000).toISOString().replace(".000Z", "Z");
}

function validity(start = Date.now() - 60_000, end = Date.now() + 3_600_000) {
  return { not_before: timestamp(start), expires_at: timestamp(end) };
}

function report(reason = "authorized") {
  const allowed = reason === "authorized";
  const signature = !["grant_required", "grant_invalid", "manifest_invalid"].includes(reason);
  const scope = signature && !["context_mismatch", "operation_not_granted"].includes(reason);
  const time = scope && !["grant_expired", "grant_not_yet_valid"].includes(reason);
  return { ok: allowed, authorized: allowed, decision: allowed ? "allow" : "deny", reason,
    ...Object.fromEntries(["product", "release", "subject", "audience", "operation"].map((key) => [key, options[key]])),
    manifest_sha256: "a".repeat(64), issuer_key_sha256: "b".repeat(64),
    checks: { grant_signature: signature, grant_scope: scope, grant_time: time, release_integrity: allowed },
    validity: signature ? validity() : null,
    limitations: ["Cooperating gateway only."] };
}

function output(document) {
  return { exitCode: document.ok ? 0 : 3, stdout: JSON.stringify(document), stderr: "" };
}

test("analysis calls use isolated Python and keep exact trusted context in separate arguments", async () => {
  const calls = [];
  const client = createClient({}, async (...args) => { calls.push(args); return output(report()); });
  const result = await client.checkAnalysis(options);
  assert.equal(result.authorized, true);
  assert.deepEqual(calls[0][1], ["-I", "-m", "releaseguard", "analysis-check",
    "--manifest=" + resolve(options.manifest), "--root=" + resolve(options.root),
    "--public=" + resolve(options.publicKey), "--product=--Demo 产品", "--release=2.0",
    "--subject=-customer", "--audience=analysis-service", "--operation=inspect",
    "--grant=" + resolve(options.grant)]);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.checks));
  assert.ok(Object.isFrozen(result.validity));
  assert.ok(Object.isFrozen(result.limitations));
});

test("missing grants remain a normal denied check without inventing a grant path", async () => {
  const calls = [];
  const client = createClient({}, async (...args) => { calls.push(args); return output(report("grant_required")); });
  const { grant, ...withoutGrant } = options;
  const result = await client.checkAnalysis(withoutGrant);
  assert.equal(result.authorized, false);
  assert.equal(result.exitCode, 3);
  assert.equal(result.reason, "grant_required");
  assert.equal(result.validity, null);
  assert.equal(calls[0][1].some((arg) => arg.startsWith("--grant=")), false);
});

test("every explicit denial stops the protected callback", async () => {
  let invoked = 0;
  for (const reason of deniedReasons) {
    const client = createClient({}, async () => output(report(reason)));
    await assert.rejects(client.withAnalysisAuthorization(options, () => { invoked += 1; }), (error) => {
      assert.ok(hasCode("AUTHORIZATION_DENIED")(error));
      assert.equal(error.exitCode, 3);
      assert.equal(error.diagnostic, undefined);
      assert.equal(error.message, "Analysis authorization denied: " + reason + ".");
      return true;
    });
  }
  assert.equal(invoked, 0);
});

test("allowed callbacks receive a frozen report exactly once and preserve their asynchronous result", async () => {
  const client = createClient({}, async () => output(report()));
  let invoked = 0;
  const value = { result: "tool completed" };
  const result = await client.withAnalysisAuthorization(options, async (verified) => {
    invoked += 1;
    assert.equal(verified.decision, "allow");
    assert.equal(verified.checks.release_integrity, true);
    assert.throws(() => { verified.checks.release_integrity = false; }, TypeError);
    assert.throws(() => { verified.validity.expires_at = "later"; }, TypeError);
    return value;
  });
  assert.equal(invoked, 1);
  assert.equal(result, value);
});

test("each admission rechecks authorization rather than caching an earlier allow", async () => {
  let checksRun = 0;
  let invoked = 0;
  const client = createClient({}, async () => output(report(checksRun++ === 0 ? "authorized" : "grant_expired")));
  const handler = () => { invoked += 1; };
  await client.withAnalysisAuthorization(options, handler);
  await assert.rejects(client.withAnalysisAuthorization(options, handler), hasCode("AUTHORIZATION_DENIED"));
  assert.equal(checksRun, 2);
  assert.equal(invoked, 1);
});

test("callback failures are propagated without another check or callback retry", async () => {
  let checksRun = 0;
  let invoked = 0;
  const client = createClient({}, async () => { checksRun += 1; return output(report()); });
  const failure = new Error("owned handler failed");
  await assert.rejects(client.withAnalysisAuthorization(options, () => {
    invoked += 1;
    throw failure;
  }), (error) => error === failure);
  assert.equal(checksRun, 1);
  assert.equal(invoked, 1);
});

test("CLI and runner errors cannot admit a protected callback", async () => {
  let invoked = 0;
  const cli = createClient({}, async () => ({ exitCode: 2, stdout: "", stderr: '{"ok":false,"error":"bad input"}' }));
  await assert.rejects(cli.withAnalysisAuthorization(options, () => { invoked += 1; }), hasCode("CLI_ERROR"));
  for (const code of ["SPAWN_FAILED", "PROCESS_ERROR", "TIMEOUT", "OUTPUT_LIMIT", "ABORTED"]) {
    const client = createClient({}, async () => { throw new ReleaseGuardError(code, "Worker failed"); });
    await assert.rejects(client.withAnalysisAuthorization(options, () => { invoked += 1; }), hasCode(code));
  }
  assert.equal(invoked, 0);
});

test("contradictory, forged-context and malformed reports never invoke the callback", async () => {
  let invoked = 0;
  const cases = [
    { ...report(), authorized: false },
    { ...report(), decision: "deny" },
    { ...report(), reason: "grant_required" },
    { ...report(), manifest_sha256: null },
    { ...report(), manifest_sha256: "bad" },
    { ...report(), issuer_key_sha256: "bad" },
    { ...report(), limitations: "not a list" },
    { ...report(), extra_untrusted_field: "ignored approval" },
    { ...report(), checks: { ...checks, grant_signature: "true" } },
    { ...report(), checks: { ...checks, extra_check: true } },
    { ...report("grant_invalid"), checks: { ...checks } },
    { ...report("grant_invalid"), reason: "untrusted diagnostic text" },
    { ...report("grant_invalid"), authorized: true },
    { ...report("grant_invalid"), decision: "allow" },
    { ...report("grant_invalid"), validity: validity() },
    ...Object.keys(checks).map((key) => ({ ...report(), checks: { ...checks, [key]: false } })),
    ...["product", "release", "subject", "audience", "operation"].map((key) => ({ ...report(), [key]: "changed" })),
  ];
  for (const document of cases) {
    const client = createClient({}, async () => output(document));
    await assert.rejects(client.withAnalysisAuthorization(options, () => { invoked += 1; }), hasCode("PROTOCOL_ERROR"));
  }
  for (const value of [
    { ...output(report()), exitCode: 3 },
    { ...output(report()), stderr: "unexpected diagnostic" },
    { ...output(report()), stdout: JSON.stringify(report()).replace('"authorized":true', '"authorized":false,"authorized":true') },
  ]) {
    const client = createClient({}, async () => value);
    await assert.rejects(client.withAnalysisAuthorization(options, () => { invoked += 1; }), hasCode("PROTOCOL_ERROR"));
  }
  assert.equal(invoked, 0);
});

test("validity metadata must be exact UTC, calendar-valid and bounded before callback admission", async () => {
  let invoked = 0;
  const malformed = [
    null, undefined, {}, "later",
    { ...validity(), extra: true },
    { not_before: "2026-02-30T00:00:00Z", expires_at: "2026-03-02T01:00:00Z" },
    { not_before: "0000-01-01T00:00:00Z", expires_at: "0000-01-01T01:00:00Z" },
    { not_before: "2026-11-05T00:00:00+00:00", expires_at: "2026-11-05T01:00:00Z" },
    { not_before: "2026-11-05T00:00:00.000Z", expires_at: "2026-11-05T01:00:00Z" },
    { not_before: "2026-11-05T00:00:60Z", expires_at: "2026-11-05T01:00:00Z" },
    { not_before: "2026-11-05T01:00:00Z", expires_at: "2026-11-05T01:00:00Z" },
    { not_before: "2026-11-05T01:00:00Z", expires_at: "2026-11-05T00:00:00Z" },
    { not_before: "2026-11-05T00:00:00Z", expires_at: "2026-11-06T00:00:01Z" },
  ];
  for (const window of malformed) {
    const client = createClient({}, async () => output({ ...report(), validity: window }));
    await assert.rejects(client.withAnalysisAuthorization(options, () => { invoked += 1; }), hasCode("PROTOCOL_ERROR"));
  }
  assert.equal(invoked, 0);
});

test("a delayed verifier allow cannot start a callback once its grant expires", async (t) => {
  let clock = Date.parse("2026-11-05T00:00:00Z");
  t.mock.method(Date, "now", () => clock);
  const acceptedByPython = report();
  let finish;
  let invoked = 0;
  const client = createClient({}, () => new Promise((resolve) => { finish = resolve; }));
  const pending = client.withAnalysisAuthorization(options, () => { invoked += 1; });
  finish(output(acceptedByPython));
  // Simulate the gateway scheduling the callback only after the exclusive expiry.
  // No sleep and no altered process or Python clock are needed.
  clock = Date.parse(acceptedByPython.validity.expires_at);
  await assert.rejects(pending, (error) => hasCode("AUTHORIZATION_DENIED")(error)
    && error.message === "Analysis authorization denied: grant_expired.");
  assert.equal(invoked, 0);
});

test("the gateway clock admits the start boundary and refuses before start or at expiry", async (t) => {
  let clock = Date.parse("2026-11-05T00:00:00Z");
  t.mock.method(Date, "now", () => clock);
  const acceptedByPython = { ...report(), validity: {
    not_before: "2026-11-05T00:00:00Z", expires_at: "2026-11-06T00:00:00Z",
  } };
  const client = createClient({}, async () => output(acceptedByPython));
  let invoked = 0;
  const handler = () => { invoked += 1; };
  await client.withAnalysisAuthorization(options, handler);
  assert.equal(invoked, 1);
  clock -= 1;
  await assert.rejects(client.withAnalysisAuthorization(options, handler), (error) => hasCode("AUTHORIZATION_DENIED")(error)
    && error.message === "Analysis authorization denied: grant_not_yet_valid.");
  clock = Date.parse(acceptedByPython.validity.expires_at);
  await assert.rejects(client.withAnalysisAuthorization(options, handler), hasCode("AUTHORIZATION_DENIED"));
  clock += 1;
  await assert.rejects(client.withAnalysisAuthorization(options, handler), hasCode("AUTHORIZATION_DENIED"));
  assert.equal(invoked, 1);
});

test("a denied malformed manifest may report a null digest without becoming an allow", async () => {
  const document = { ...report("manifest_invalid"), manifest_sha256: null };
  const client = createClient({}, async () => output(document));
  assert.equal((await client.checkAnalysis(options)).manifest_sha256, null);
});

test("mutating input options while Python runs cannot replace the expected context", async () => {
  let finish;
  let invoked = 0;
  const client = createClient({}, () => new Promise((resolve) => { finish = resolve; }));
  const mutable = { ...options };
  const pending = client.withAnalysisAuthorization(mutable, () => { invoked += 1; });
  mutable.subject = "another-subject";
  mutable.operation = "instrument";
  finish(output({ ...report(), subject: mutable.subject, operation: mutable.operation }));
  await assert.rejects(pending, hasCode("PROTOCOL_ERROR"));
  assert.equal(invoked, 0);
});

test("an already-cancelled admission starts neither Python nor the callback", async () => {
  const controller = new AbortController();
  controller.abort();
  let checksRun = 0;
  let invoked = 0;
  const client = createClient({}, async () => { checksRun += 1; return output(report()); });
  await assert.rejects(client.withAnalysisAuthorization(options, () => { invoked += 1; }, {
    signal: controller.signal,
  }), hasCode("ABORTED"));
  assert.equal(checksRun, 0);
  assert.equal(invoked, 0);
});

test("cancellation after the worker resolves still prevents callback admission", async () => {
  const controller = new AbortController();
  let finish;
  let invoked = 0;
  const client = createClient({}, () => new Promise((resolve) => { finish = resolve; }));
  const pending = client.withAnalysisAuthorization(options, () => { invoked += 1; }, { signal: controller.signal });
  finish(output(report()));
  queueMicrotask(() => controller.abort());
  await assert.rejects(pending, hasCode("ABORTED"));
  assert.equal(invoked, 0);
});

test("changing the controls object cannot replace a captured cancellation signal", async () => {
  const controller = new AbortController();
  const controls = { signal: controller.signal };
  let finish;
  let invoked = 0;
  const client = createClient({}, () => new Promise((resolve) => { finish = resolve; }));
  const pending = client.withAnalysisAuthorization(options, () => { invoked += 1; }, controls);
  controls.signal = new AbortController().signal;
  controller.abort();
  finish(output(report()));
  await assert.rejects(pending, hasCode("ABORTED"));
  assert.equal(invoked, 0);
});

test("bad handler, unknown scopes and missing context fail before Python", async () => {
  let checksRun = 0;
  const client = createClient({}, async () => { checksRun += 1; return output(report()); });
  for (const invalid of [
    { ...options, operation: "patch" }, { ...options, operation: "inspect,decompile" },
    { ...options, operation: undefined }, { ...options, release: undefined },
    { ...options, subject: "" }, { ...options, audience: "bad\ncontext" },
    { ...options, grant: null }, { ...options, allowWithoutGrant: true },
  ]) {
    await assert.rejects(client.checkAnalysis(invalid), hasCode("INVALID_ARGUMENT"));
  }
  await assert.rejects(client.withAnalysisAuthorization(options, null), hasCode("INVALID_ARGUMENT"));
  await assert.rejects(client.withAnalysisAuthorization(options, () => {}, { signal: {} }), hasCode("INVALID_ARGUMENT"));
  assert.equal(checksRun, 0);
});
