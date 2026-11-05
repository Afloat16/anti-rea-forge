import { createReleaseGuard } from "../../src/index.js";

const [python, root, policy] = process.argv.slice(2);
const report = await createReleaseGuard({ python }).scanRelease({ root, policy });
process.stdout.write(JSON.stringify(report));
process.exitCode = report.exitCode;
