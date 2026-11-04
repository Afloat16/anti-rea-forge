import { createReleaseGuard, ReleaseGuardError, type ScanReleaseReport } from "@anti-rea-forge/releaseguard";

const guard = createReleaseGuard({ python: "/trusted/bin/python", timeoutMs: 10_000 });
const report: ScanReleaseReport = await guard.scanRelease({ root: "dist", policy: "rules.json" }, {
  signal: new AbortController().signal,
});
const bytes: number = report.files[0].size;
const passed: boolean = report.ok;
const license = await guard.verifyLicense({
  license: "customer.json", publicKey: "public.pem", product: "Demo", requiredFeatures: ["export"] as const,
});
const features: readonly string[] = license.claims.features;
const audit = await guard.audit("app.exe", { strict: true });
const warnings: readonly string[] = audit.audit.warnings;
const error = new ReleaseGuardError("CLI_ERROR", "Check failed", { exitCode: 2 });
const diagnostic: string | undefined = error.diagnostic;
void [bytes, passed, features, warnings, diagnostic];

// @ts-expect-error A directory is required, not a numeric identifier.
guard.scanRelease({ root: 42, policy: "rules.json" });
// @ts-expect-error Unknown transport controls must not silently disable checks.
guard.audit("app.exe", { strict: "yes" });
// @ts-expect-error The bridge has no issuer/private-key API.
guard.issueLicense({ privateKey: "issuer.pem" });
