export type JsonValue = null | boolean | number | string | readonly JsonValue[] | JsonObject;
export interface JsonObject {
  readonly [key: string]: JsonValue;
}

export type ReleaseGuardErrorCode =
  | "INVALID_ARGUMENT"
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

export interface ReleaseGuard {
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
