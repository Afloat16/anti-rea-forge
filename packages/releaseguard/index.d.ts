export type JsonValue = null | boolean | number | string | readonly JsonValue[] | JsonObject;
export interface JsonObject {
  readonly [key: string]: JsonValue;
}

export type ReleaseGuardErrorCode =
  | "INVALID_ARGUMENT"
  | "AUTHORIZATION_DENIED"
  | "SPAWN_FAILED"
  | "PROCESS_ERROR"
  | "CLI_ERROR"
  | "PROTOCOL_ERROR"
  | "OUTPUT_LIMIT"
  | "TIMEOUT"
  | "ABORTED";

export class ReleaseGuardError extends Error {
  readonly code: ReleaseGuardErrorCode;
  readonly exitCode?: number;
  readonly signal?: string;
  /** Bounded child diagnostics. Non-enumerable; inspect deliberately. */
  readonly diagnostic?: string;
  constructor(
    code: ReleaseGuardErrorCode,
    message: string,
    details?: { exitCode?: number; signal?: string; diagnostic?: string },
  );
}

export interface ClientOptions {
  /** Interpreter executable, not a shell command. Defaults to RELEASEGUARD_PYTHON or python. */
  readonly python?: string;
  /** 1..600000 milliseconds; default 30000. */
  readonly timeoutMs?: number;
  /** Combined stdout/stderr bytes, 1024..16777216; default 4194304. */
  readonly maxOutputBytes?: number;
}

export interface RunOptions {
  readonly signal?: AbortSignal;
}

export interface Finding extends JsonObject {
  readonly code: string;
}

export interface ScanChecks extends JsonObject {
  readonly scan_completed: true;
}

export interface ScanReleaseReport extends JsonObject {
  readonly ok: boolean;
  readonly exitCode: 0 | 3;
  readonly root: string;
  readonly files: readonly (JsonObject & {
    readonly path: string;
    readonly size: number;
    readonly sha256: string;
  })[];
  readonly findings: readonly Finding[];
  readonly checks: ScanChecks & { readonly files_scanned: number };
  readonly notes: readonly string[];
}

export interface GateReport extends JsonObject {
  readonly ok: boolean;
  readonly exitCode: 0 | 3;
  readonly artifact: JsonObject & {
    readonly path: string;
    readonly size: number;
    readonly sha256: string;
    readonly format: "pe" | "elf";
  };
  readonly findings: readonly Finding[];
  readonly checks: ScanChecks;
  readonly notes: readonly string[];
}

export interface AuditReport extends JsonObject {
  readonly ok: boolean;
  readonly exitCode: 0 | 3;
  readonly policy_passed: boolean;
  readonly audit: JsonObject & {
    readonly format: "PE32" | "PE32+";
    readonly kind: "exe" | "dll";
    readonly warnings: readonly string[];
    readonly notes: readonly string[];
  };
}

export interface ManifestReport extends JsonObject {
  readonly ok: true;
  readonly exitCode: 0;
  readonly product: string;
  readonly release: string;
  readonly files_verified: number;
}

export interface LicenseClaims extends JsonObject {
  readonly version: 1;
  readonly product: string;
  readonly subject: string;
  readonly license_id: string;
  readonly issued_at: string;
  readonly not_before: string;
  readonly expires_at: string;
  readonly features: readonly string[];
}

export interface LicenseReport extends JsonObject {
  readonly ok: true;
  readonly exitCode: 0;
  readonly claims: LicenseClaims;
}

/** Independent scopes: none implicitly grants another. */
export type AnalysisOperation = "inspect" | "decompile" | "instrument";

export type AnalysisDenialReason =
  | "grant_required"
  | "grant_invalid"
  | "grant_expired"
  | "grant_not_yet_valid"
  | "context_mismatch"
  | "operation_not_granted"
  | "manifest_invalid"
  | "release_mismatch";

export interface AnalysisOptions {
  readonly manifest: string;
  /** Immutable release directory held under trusted service control. */
  readonly root: string;
  /** Previously trusted issuer key, never chosen by the analyzed target. */
  readonly publicKey: string;
  readonly product: string;
  readonly release: string;
  /** Identity from authenticated service context, not a model assertion. */
  readonly subject: string;
  readonly audience: string;
  /** Fixed by the trusted tool-to-scope mapping. */
  readonly operation: AnalysisOperation;
  /** Omission returns a denied check; it never grants implicit permission. */
  readonly grant?: string;
}

export interface AnalysisChecks extends JsonObject {
  readonly grant_signature: boolean;
  readonly grant_scope: boolean;
  readonly grant_time: boolean;
  readonly release_integrity: boolean;
}

export interface AnalysisValidity extends JsonObject {
  /** Whole-second UTC timestamp, YYYY-MM-DDTHH:MM:SSZ. */
  readonly not_before: string;
  /** Exclusive expiry, at most 86400 seconds after not_before. */
  readonly expires_at: string;
}

interface AnalysisReportBase extends JsonObject {
  readonly product: string;
  readonly release: string;
  readonly subject: string;
  readonly audience: string;
  readonly operation: AnalysisOperation;
  readonly issuer_key_sha256: string;
  readonly limitations: readonly string[];
}

export interface AuthorizedAnalysisReport extends AnalysisReportBase {
  readonly ok: true;
  readonly authorized: true;
  readonly exitCode: 0;
  readonly decision: "allow";
  readonly reason: "authorized";
  readonly manifest_sha256: string;
  readonly validity: AnalysisValidity;
  readonly checks: AnalysisChecks & {
    readonly grant_signature: true;
    readonly grant_scope: true;
    readonly grant_time: true;
    readonly release_integrity: true;
  };
}

export interface DeniedAnalysisReport extends AnalysisReportBase {
  readonly ok: false;
  readonly authorized: false;
  readonly exitCode: 3;
  readonly decision: "deny";
  readonly reason: AnalysisDenialReason;
  readonly manifest_sha256: string | null;
  /** Non-null only after the grant signature and schema were verified. */
  readonly validity: AnalysisValidity | null;
  readonly checks: AnalysisChecks;
}

export type AnalysisReport = AuthorizedAnalysisReport | DeniedAnalysisReport;

export interface ReleaseGuard {
  checkProject(
    options: { config: string },
    controls?: RunOptions,
  ): Promise<ScanReleaseReport>;

  /** Read-only verifier decision. A caller using this method must enforce its result. */
  checkAnalysis(options: AnalysisOptions, controls?: RunOptions): Promise<AnalysisReport>;

  /**
   * Verify afresh, recheck validity on the trusted gateway clock, then invoke
   * the trusted handler once only if allowed. Denial throws AUTHORIZATION_DENIED.
   * Other errors/cancellation do not call it. The handler must use the captured,
   * immutable configuration; this wrapper does not inspect or rewrite tool args.
   * Once admitted, cancellation and continuing authorization belong to the handler.
   */
  withAnalysisAuthorization<T>(
    options: AnalysisOptions,
    handler: (report: AuthorizedAnalysisReport) => T | PromiseLike<T>,
    controls?: RunOptions,
  ): Promise<T>;

  scanRelease(
    options: { root: string; policy: string },
    controls?: RunOptions,
  ): Promise<ScanReleaseReport>;

  audit(
    artifact: string,
    options?: RunOptions & { strict?: boolean },
  ): Promise<AuditReport>;

  gate(
    options: { artifact: string; policy: string; root?: string },
    controls?: RunOptions,
  ): Promise<GateReport>;

  verifyManifest(
    options: {
      manifest: string;
      root: string;
      publicKey: string;
      product: string;
      release?: string;
    },
    controls?: RunOptions,
  ): Promise<ManifestReport>;

  verifyLicense(
    options: {
      license: string;
      publicKey: string;
      product: string;
      subject?: string;
      requiredFeatures?: readonly string[];
    },
    controls?: RunOptions,
  ): Promise<LicenseReport>;
}

/** Runs the installed Python core in isolated mode; no cryptography is reimplemented here. */
export function createReleaseGuard(options?: ClientOptions): ReleaseGuard;
