/** Run from the repository root after installing the core into a trusted Python. */
import { parseArgs } from "node:util";
import { createReleaseGuard, ReleaseGuardError } from "../../packages/releaseguard/src/index.js";

try {
  const { values } = parseArgs({
    options: {
      root: { type: "string" },
      policy: { type: "string" },
      python: { type: "string" },
      help: { type: "boolean", short: "h" },
    },
    allowPositionals: false,
  });
  if (values.help) {
    console.log("Usage: node examples/javascript/scan-release.mjs --root dist --policy policy.json [--python /trusted/python]");
  } else {
    const guard = createReleaseGuard({ python: values.python });
    const report = await guard.scanRelease({ root: values.root, policy: values.policy });
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.exitCode;
  }
} catch (error) {
  console.error(JSON.stringify({
    ok: false,
    code: error instanceof ReleaseGuardError ? error.code : "INVALID_ARGUMENT",
    error: error instanceof Error ? error.message : "Command failed",
  }));
  process.exitCode = 2;
}
