/** Exact runtime identity for the paired REA recovery experiments. */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, readdir, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";

export const REA_VERSION = "6.9.0";
export const REA_INTEGRITY = "sha512-KqDn1UR5BMqHoQ3MGAnPuWiSKwgdFaz1L/uUNgrKt+1W8kPtgYP8AWEOXIF1lDIOBVyPuYIIst2iamo1Wf3r8g==";
// Official registry claims recorded on 2026-11-18; not an independent Sigstore
// signature-chain verification and not the identity of a later source build.
const REA_PROVENANCE = {
  url: "https://registry.npmjs.org/-/npm/v1/attestations/rea-agents@6.9.0",
  recorded_date: "2026-11-18",
  declared_source_commit: "d74549e495c58eb4a560279fd9f05508401ea0a0",
  subject_sha512: "2aa0e7d5447904ca87a10dcc1809cfb968922b081d15acf52ffb94360acab7ed56f243ed8183fc01610e5c817594320e055c8fb98208b2dda26a6a3559fdebf2",
  signature_chain_independently_verified: false,
};
const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const json = async path => JSON.parse(await readFile(path, "utf8"));

function git(directory, args) {
  const result = spawnSync("git", ["-C", directory, ...args], { shell: false,
    encoding: "utf8", timeout: 15_000, maxBuffer: 1024 * 1024 });
  assert(!result.error && !result.signal && result.status === 0,
    "Source identity command failed: " + (result.error ?? result.stderr));
  return result.stdout.trim();
}

// The digest covers names, lengths and contents of every emitted runtime file.
// A completed command still fails if the compiled runtime changed during it.
async function runtimeInventory(directory) {
  const digest = createHash("sha256");
  let files = 0, bytes = 0;
  async function visit(relative) {
    const entries = await readdir(join(directory, relative), { withFileTypes: true });
    entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    for (const entry of entries) {
      const path = relative + "/" + entry.name;
      if (entry.isDirectory()) await visit(path);
      else {
        assert(entry.isFile(), "Source-built runtime contains a link or special file: " + path);
        const data = await readFile(join(directory, path));
        digest.update(JSON.stringify([path, data.length, sha(data)]) + "\n");
        ++files;
        bytes += data.length;
      }
    }
  }
  await visit("dist");
  assert(files > 0, "No source-built runtime files");
  return { files, bytes, inventory_sha256: digest.digest("hex") };
}

export async function selectReaRuntime({ tools, source, sourceCommit }) {
  assert.equal(Boolean(source), Boolean(sourceCommit),
    "--rea-source and --rea-source-commit must be supplied together");
  if (!source) {
    const root = join(tools, "node_modules/rea-agents");
    const metadata = await json(join(root, "package.json"));
    const lock = await json(join(tools, "package-lock.json"));
    const locked = lock.packages["node_modules/rea-agents"];
    assert.equal(metadata.version, REA_VERSION);
    assert.equal(locked?.version, REA_VERSION);
    assert.equal(locked?.integrity, REA_INTEGRITY);
    assert.equal(Buffer.from(REA_INTEGRITY.slice(7), "base64").toString("hex"), REA_PROVENANCE.subject_sha512);
    return { entry: join(root, "scripts/rea.mjs"),
      record: { distribution: "npm", version: REA_VERSION, npm_integrity: REA_INTEGRITY,
        recorded_registry_provenance: REA_PROVENANCE },
      verifyUnchanged: async () => {} };
  }

  assert.match(sourceCommit, /^[0-9a-f]{40}$/, "Full lowercase source commit is required");
  const root = await realpath(resolve(source));
  assert.equal(await realpath(git(root, ["rev-parse", "--show-toplevel"])), root,
    "--rea-source must name the repository root");
  const checkTracked = () => {
    assert.equal(git(root, ["rev-parse", "HEAD"]), sourceCommit, "Unexpected source commit");
    assert.equal(git(root, ["status", "--porcelain", "--untracked-files=no"]), "",
      "Tracked source changes cannot represent the pinned commit");
  };
  checkTracked();
  const metadata = await json(join(root, "package.json"));
  assert.equal(metadata.name, "rea-agents");
  const sourceLockBytes = await readFile(join(root, "package-lock.json"));
  const sourceLock = JSON.parse(sourceLockBytes);
  const buildTools = {};
  for (const name of ["tsrs", "typescript", "rolldown"]) {
    const installed = await json(join(root, "node_modules", name, "package.json"));
    const locked = sourceLock.packages["node_modules/" + name];
    assert.equal(installed.version, locked?.version, "Source build-tool version: " + name);
    buildTools[name] = { version: installed.version, npm_integrity: locked.integrity };
  }
  const runtime = await runtimeInventory(root);
  const launcher = await readFile(join(root, "scripts/rea.mjs"));
  const record = { distribution: "source-build", version_field: metadata.version,
    source_repository: "https://github.com/morluto/rea", source_commit: sourceCommit,
    source_tree: git(root, ["rev-parse", "HEAD^{tree}"]), tracked_source_clean: true,
    source_package_lock_sha256: sha(sourceLockBytes),
    installed_lock_sha256: sha(await readFile(join(root, "node_modules/.package-lock.json"))),
    build_script: metadata.scripts.compile, installed_build_tools: buildTools,
    launcher_sha256: sha(launcher), compiled_runtime: runtime };
  return { entry: join(root, "scripts/rea.mjs"), record,
    verifyUnchanged: async () => {
      checkTracked();
      assert.equal(sha(await readFile(join(root, "scripts/rea.mjs"))), record.launcher_sha256);
      assert.equal(sha(await readFile(join(root, "node_modules/.package-lock.json"))), record.installed_lock_sha256);
      assert.deepEqual(await runtimeInventory(root), runtime, "Source-built runtime changed during the probe");
    } };
}
