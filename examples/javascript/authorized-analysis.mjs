/**
 * Operator-run example of an authorization boundary around one fixed tool.
 * These flags are trusted service configuration, never model/target input.
 * A real service obtains subject from authentication and fixes this mapping
 * before exposing the tool. It must keep the release immutable during use.
 */
import { readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { createReleaseGuard, ReleaseGuardError } from "../../packages/releaseguard/src/index.js";

try {
  const { values } = parseArgs({
    options: {
      manifest: { type: "string" },
      root: { type: "string" },
      public: { type: "string" },
      product: { type: "string" },
      release: { type: "string" },
      subject: { type: "string" },
      audience: { type: "string" },
      grant: { type: "string" },
      python: { type: "string" },
      help: { type: "boolean", short: "h" },
    },
    allowPositionals: false,
  });
  if (values.help) {
    console.log("Usage: node examples/javascript/authorized-analysis.mjs --manifest evidence/manifest.json --root dist"
      + " --public trusted-issuer.pem --product Demo --release 1.0 --subject reviewer --audience analysis-service"
      + " [--grant grant.json] [--python /trusted/python]");
    console.log("Fixed tool: list_release_entries; fixed scope: inspect. Missing grant denies without calling the tool.");
  } else {
    const guard = createReleaseGuard({ python: values.python });
    const options = Object.freeze({
      manifest: values.manifest,
      root: typeof values.root === "string" ? resolve(values.root) : values.root,
      publicKey: values.public, product: values.product, release: values.release,
      subject: values.subject, audience: values.audience,
      grant: values.grant, operation: "inspect",
    });
    const result = await guard.withAnalysisAuthorization(options, async () => {
      // This tool uses the same captured, immutable absolute root. Its read
      // starts after authorization; no target code or arbitrary command runs.
      const entries = await readdir(options.root);
      return { ok: true, tool: "list_release_entries", operation: "inspect", entries: entries.sort() };
    });
    console.log(JSON.stringify(result, null, 2));
  }
} catch (error) {
  console.error(JSON.stringify({
    ok: false,
    code: error instanceof ReleaseGuardError ? error.code : "EXAMPLE_ERROR",
    error: error instanceof ReleaseGuardError ? error.message : "The configured example could not complete.",
  }));
  process.exitCode = error instanceof ReleaseGuardError && error.code === "AUTHORIZATION_DENIED" ? 3 : 2;
}
