import { createReleaseGuard, ReleaseGuardError, type ScanReleaseReport, type AnalysisOptions,
  type AuthorizedAnalysisReport, type AnalysisDenialReason } from "@anti-rea-forge/releaseguard";

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

const projectReport: ScanReleaseReport = await guard.checkProject({ config: ".releaseguard/project.json" });
const analysis: AnalysisOptions = {
  manifest: "release-manifest.json", root: "dist", publicKey: "trusted-issuer.pem", grant: "grant.json",
  product: "Demo", release: "1.0", subject: "authenticated-reviewer", audience: "analysis-service", operation: "inspect",
};
const decision = await guard.checkAnalysis(analysis);
if (decision.authorized) {
  const allowed: AuthorizedAnalysisReport = decision;
  const digest: string = decision.manifest_sha256;
  const expiry: string = decision.validity.expires_at;
  void [allowed, digest, expiry];
} else {
  const denial: AnalysisDenialReason = decision.reason;
  const expiry: string | undefined = decision.validity?.expires_at;
  void [denial, expiry];
}
const handlerValue: number = await guard.withAnalysisAuthorization(analysis, async (verified) => {
  const verifiedScope: true = verified.checks.grant_scope;
  const expiry: string = verified.validity.expires_at;
  void [verifiedScope, expiry];
  return 42;
});
const deniedError = new ReleaseGuardError("AUTHORIZATION_DENIED", "Analysis denied", { exitCode: 3 });
void [projectReport, handlerValue, deniedError];

// @ts-expect-error A directory is required, not a numeric identifier.
guard.scanRelease({ root: 42, policy: "rules.json" });
// @ts-expect-error Unknown transport controls must not silently disable checks.
guard.audit("app.exe", { strict: "yes" });
// @ts-expect-error The bridge has no issuer/private-key API.
guard.issueLicense({ privateKey: "issuer.pem" });
// @ts-expect-error An unknown operation must not be interpreted as a valid scope.
guard.checkAnalysis({ ...analysis, operation: "patch" });
// @ts-expect-error A callback is required; a precomputed tool result is not a handler.
guard.withAnalysisAuthorization(analysis, 42);
// @ts-expect-error Scope decisions cannot be modified by a handler.
guard.withAnalysisAuthorization(analysis, (verified) => { verified.checks.grant_scope = false; });
// @ts-expect-error Verified validity is immutable.
guard.withAnalysisAuthorization(analysis, (verified) => { verified.validity.expires_at = "later"; });
