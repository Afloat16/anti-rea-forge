import { ReleaseGuardError } from "./error.js";

const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const strings = (value) => Array.isArray(value) && value.every((item) => typeof item === "string");
const nonempty = (value) => typeof value === "string" && value.length > 0;
const count = (value) => Number.isSafeInteger(value) && value >= 0;
const sha256 = (value) => typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
const authorizationChecks = ["grant_signature", "grant_scope", "grant_time", "release_integrity"];
const denialReasons = ["grant_required", "grant_invalid", "grant_expired", "grant_not_yet_valid",
  "context_mismatch", "operation_not_granted", "manifest_invalid", "release_mismatch"];

function fields(value, names) {
  return record(value) && Object.keys(value).length === names.length
    && names.every((name) => Object.hasOwn(value, name));
}

function utcMilliseconds(value) {
  if (typeof value !== "string" || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/u.test(value)
      || value.startsWith("0000")) return null;
  const milliseconds = Date.parse(value);
  // Date.parse can normalize invalid calendar dates. Require an exact roundtrip.
  if (!Number.isFinite(milliseconds)
      || new Date(milliseconds).toISOString() !== value.slice(0, -1) + ".000Z") return null;
  return milliseconds;
}

/** Internal protocol helper; not a second signature or grant implementation. */
export function analysisValidityWindow(value) {
  if (!fields(value, ["not_before", "expires_at"])) return null;
  const start = utcMilliseconds(value.not_before);
  const end = utcMilliseconds(value.expires_at);
  if (start === null || end === null || end - start < 1000 || end - start > 86_400_000) return null;
  return { start, end };
}
const invalid = () => new ReleaseGuardError("PROTOCOL_ERROR", "Release Guard returned an invalid or inconsistent report.");

/** Reject duplicate members and excessive nesting, as well as invalid JSON. */
function parseJson(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw invalid();
  }
  let position = 0;
  const whitespace = () => {
    while (/\s/u.test(text[position] ?? "x")) position += 1;
  };
  function string() {
    const start = position++;
    while (position < text.length) {
      const char = text[position++];
      if (char === "\\") position += 1;
      else if (char === '"') return JSON.parse(text.slice(start, position));
    }
    throw invalid();
  }
  function visit(depth) {
    if (depth > 64) throw invalid();
    whitespace();
    const char = text[position];
    if (char === '"') string();
    else if (char === "{" || char === "[") {
      position += 1;
      const end = char === "{" ? "}" : "]";
      const keys = new Set();
      whitespace();
      while (text[position] !== end) {
        if (char === "{") {
          const key = string();
          if (keys.has(key)) throw invalid();
          keys.add(key);
          whitespace();
          position += 1; // Colon: JSON.parse already verified the syntax.
        }
        visit(depth + 1);
        whitespace();
        if (text[position] === ",") position += 1;
        whitespace();
      }
      position += 1;
    } else {
      const start = position;
      while (position < text.length && !/[\s,}\]]/u.test(text[position])) position += 1;
      const primitive = text.slice(start, position);
      if (!['true', 'false', 'null'].includes(primitive) && !Number.isFinite(Number(primitive))) throw invalid();
    }
  }
  visit(0);
  return value;
}

function findingsReport(document) {
  return Array.isArray(document.findings)
    && document.findings.every((finding) => record(finding) && nonempty(finding.code))
    && document.ok === (document.findings.length === 0)
    && record(document.checks) && document.checks.scan_completed === true
    && strings(document.notes);
}

/** This checks the CLI transport contract; Python performs all cryptography. */
export function decodeReport(command, result, expected) {
  const { exitCode, stdout, stderr } = result;
  if (exitCode !== 0 && exitCode !== 3) {
    throw new ReleaseGuardError("CLI_ERROR", "Release Guard could not complete the requested check.", {
      exitCode,
      diagnostic: stderr || stdout,
    });
  }
  if (stderr.trim() !== "") throw invalid();
  const document = parseJson(stdout);
  if (!record(document) || typeof document.ok !== "boolean"
      || document.ok !== (exitCode === 0) || Object.hasOwn(document, "error")) throw invalid();

  let valid = false;
  switch (command) {
    case "check":
    case "scan-release":
      valid = findingsReport(document) && nonempty(document.root)
        && Array.isArray(document.files) && document.files.length > 0
        && document.files.every((file) => record(file) && nonempty(file.path)
          && count(file.size) && typeof file.sha256 === "string" && /^[0-9a-f]{64}$/u.test(file.sha256))
        && new Set(document.files.map((file) => file.path)).size === document.files.length
        && document.checks.files_scanned === document.files.length;
      break;
    case "analysis-check": {
      const window = analysisValidityWindow(document.validity);
      const shape = fields(document, ["ok", "authorized", "decision", "reason", "product", "release", "subject",
        "audience", "operation", "manifest_sha256", "issuer_key_sha256", "checks", "validity", "limitations"])
        && fields(document.checks, authorizationChecks)
        && authorizationChecks.every((name) => typeof document.checks[name] === "boolean")
        && ["product", "release", "subject", "audience", "operation"]
          .every((name) => document[name] === expected[name])
        && sha256(document.issuer_key_sha256)
        && (document.manifest_sha256 === null || sha256(document.manifest_sha256))
        && (document.validity === null || window !== null)
        && (document.checks.grant_signature ? window !== null : document.validity === null)
        && strings(document.limitations);
      const complete = shape && authorizationChecks.every((name) => document.checks[name]);
      valid = shape && document.authorized === document.ok
        && (document.ok
          ? document.decision === "allow" && document.reason === "authorized"
            && complete && sha256(document.manifest_sha256) && window !== null
          : document.decision === "deny" && denialReasons.includes(document.reason) && !complete);
      if (valid) {
        Object.freeze(document.checks);
        if (document.validity !== null) Object.freeze(document.validity);
        Object.freeze(document.limitations);
      }
      break;
    }
    case "gate":
      valid = findingsReport(document) && record(document.artifact)
        && nonempty(document.artifact.path) && count(document.artifact.size)
        && /^[0-9a-f]{64}$/u.test(document.artifact.sha256)
        && ["pe", "elf"].includes(document.artifact.format);
      break;
    case "audit": {
      const audit = document.audit;
      valid = record(audit) && strings(audit.warnings) && strings(audit.notes)
        && ["PE32", "PE32+"].includes(audit.format) && ["exe", "dll"].includes(audit.kind)
        && document.policy_passed === (audit.warnings.length === 0)
        && document.ok === (!expected.strict || document.policy_passed);
      break;
    }
    case "manifest-verify":
      valid = document.ok && document.product === expected.product
        && nonempty(document.release) && count(document.files_verified)
        && (expected.release === undefined || document.release === expected.release);
      break;
    case "license-verify": {
      const claims = document.claims;
      valid = document.ok && record(claims) && claims.version === 1
        && claims.product === expected.product
        && ["subject", "license_id", "issued_at", "not_before", "expires_at"]
          .every((name) => nonempty(claims[name]))
        && strings(claims.features) && new Set(claims.features).size === claims.features.length
        && (expected.subject === undefined || claims.subject === expected.subject)
        && expected.requiredFeatures.every((feature) => claims.features.includes(feature));
      break;
    }
  }
  if (!valid) throw invalid();
  return Object.freeze({ ...document, exitCode });
}
