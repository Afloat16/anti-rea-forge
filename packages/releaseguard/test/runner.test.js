import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createClient } from "../src/client.js";
import { mkdtemp, rm, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { runCommand } from "../src/runner.js";
import { ReleaseGuardError } from "../src/index.js";

const fixture = fileURLToPath(new URL("./fixtures/worker.mjs", import.meta.url));
const controls = { timeoutMs: 5000, maxOutputBytes: 4096 };
const run = (mode, args = [], options = {}) => runCommand(process.execPath, [fixture, mode, ...args], { ...controls, ...options });
const hasCode = (code) => (error) => error instanceof ReleaseGuardError && error.code === code;

test("a real child receives metacharacters verbatim without a shell", async (t) => {
  const temporary = await mkdtemp(join(tmpdir(), "releaseguard-js-argv-"));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const marker = join(temporary, "must-not-exist");
  const values = ["space value", "路径🔒", `; touch '${marker}'`, `$(touch '${marker}')`, "& echo injected", "`echo injected`"];
  const result = await run("argv", values);
  assert.equal(result.exitCode, 0);
  assert.deepEqual(JSON.parse(result.stdout), values);
  await assert.rejects(access(marker));
});

test("UTF-8 survives a split code point across child writes", async () => {
  const result = await run("unicode");
  assert.equal(JSON.parse(result.stdout).message, "路径🔒");
});

test("invalid UTF-8 is rejected without replacement characters", async () => {
  await assert.rejects(run("invalid-utf8"), hasCode("PROTOCOL_ERROR"));
});

test("normal process exit and stderr are kept separate for protocol validation", async () => {
  const result = await run("exit", ["2"]);
  assert.deepEqual(result, { exitCode: 2, stdout: '{"ok":false}', stderr: "diagnostic" });
});

test("stdout budget overflow terminates the child", async () => {
  await assert.rejects(run("overflow-stdout", [], { maxOutputBytes: 1024 }), hasCode("OUTPUT_LIMIT"));
});

test("the byte budget includes stderr and stdout together", async () => {
  await assert.rejects(run("overflow-combined", [], { maxOutputBytes: 1024 }), hasCode("OUTPUT_LIMIT"));
});

test("a hanging child is terminated on timeout", async () => {
  await assert.rejects(run("hang", [], { timeoutMs: 100 }), hasCode("TIMEOUT"));
});

test("cancellation before spawn does not require an executable", async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(runCommand("nonexistent-python-releaseguard-test", [], {
    ...controls, signal: controller.signal,
  }), hasCode("ABORTED"));
});

test("cancellation while running terminates the child", async () => {
  const controller = new AbortController();
  const pending = run("hang", [], { signal: controller.signal });
  const timer = setTimeout(() => controller.abort(), 50);
  try {
    await assert.rejects(pending, hasCode("ABORTED"));
  } finally {
    clearTimeout(timer);
  }
});

test("spawn failures are actionable errors", async () => {
  await assert.rejects(runCommand("nonexistent-python-releaseguard-test", [], controls), hasCode("SPAWN_FAILED"));
});

test("abnormal termination cannot masquerade as a report", { skip: process.platform === "win32" }, async () => {
  await assert.rejects(run("signal"), (error) => error.code === "PROCESS_ERROR" && error.signal === "SIGTERM");
});

test("spawn failures with absent stdio reject clearly and cannot admit an authorization callback", async () => {
  // Reliable cross-platform model of Node's EMFILE/ENFILE spawn failure shape.
  // The real async error is emitted after spawn returns a child without pipes.
  for (const errno of ["EMFILE", "ENFILE"]) {
    let invoked = 0;
    let killed = 0;
    let drained = false;
    const spawnWithoutPipes = () => {
      const child = new EventEmitter();
      child.stdout = errno === "EMFILE" ? undefined : null;
      child.stderr = null;
      child.kill = () => { killed += 1; return false; };
      child.unref = () => {};
      queueMicrotask(() => {
        child.emit("error", Object.assign(new Error("spawn fd exhaustion"), { code: errno }));
        drained = true;
        child.emit("close", -1, null);
      });
      return child;
    };
    const client = createClient({}, (...args) => runCommand(...args, spawnWithoutPipes));
    await assert.rejects(client.withAnalysisAuthorization({
      manifest: "manifest.json", root: "dist", publicKey: "public.pem",
      product: "Demo", release: "1.0", subject: "reviewer", audience: "analysis-service", operation: "inspect",
    }, () => { invoked += 1; }), hasCode("SPAWN_FAILED"));
    assert.equal(invoked, 0);
    assert.equal(killed, 1);
    assert.equal(drained, true);
  }
});
