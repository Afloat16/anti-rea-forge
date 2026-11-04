import { resolve } from "node:path";
import { ReleaseGuardError } from "./error.js";
import { decodeReport } from "./protocol.js";
import { runCommand } from "./runner.js";

function input(message) {
  throw new ReleaseGuardError("INVALID_ARGUMENT", message);
}

function object(value, allowed, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) input(`${label} must be an object.`);
  if (Object.keys(value).some((key) => !allowed.includes(key))) input(`${label} has an unsupported option.`);
  return value;
}

function text(value, label) {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > 32_768
      || /[\u0000-\u001f\u007f\ud800-\udfff]/u.test(value)) {
    input(`${label} must be a nonempty bounded Unicode string without controls.`);
  }
  return value;
}

function path(value, label) {
  return resolve(text(value, label));
}

function integer(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    input(`${label} must be an integer in ${minimum}..${maximum}.`);
  }
  return value;
}

function runOptions(options = {}) {
  object(options, ["signal"], "Run options");
  if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) {
    input("signal must be an AbortSignal.");
  }
  return { signal: options.signal };
}

/** Internal runner injection keeps process tests independent of a Python install. */
export function createClient(options = {}, runner = runCommand) {
  object(options, ["python", "timeoutMs", "maxOutputBytes"], "Client options");
  const executable = text(options.python ?? process.env.RELEASEGUARD_PYTHON ?? "python", "python");
  const config = Object.freeze({
    python: /[/\\]/u.test(executable) ? resolve(executable) : executable,
    timeoutMs: integer(options.timeoutMs ?? 30_000, 1, 600_000, "timeoutMs"),
    maxOutputBytes: integer(options.maxOutputBytes ?? 4 * 1024 * 1024, 1024, 16 * 1024 * 1024, "maxOutputBytes"),
  });

  async function call(command, args, expected, options) {
    const controls = runOptions(options);
    // Isolated mode excludes cwd and PYTHONPATH from Python module resolution.
    // The selected interpreter must have the core installed (editable is fine).
    const result = await runner(config.python, ["-I", "-m", "releaseguard", command, ...args], {
      timeoutMs: config.timeoutMs,
      maxOutputBytes: config.maxOutputBytes,
      ...controls,
    });
    return decodeReport(command, result, expected);
  }

  return Object.freeze({
    async scanRelease(options, controls) {
      object(options, ["root", "policy"], "scanRelease options");
      return call("scan-release", [
        `--root=${path(options.root, "root")}`,
        `--policy=${path(options.policy, "policy")}`,
      ], {}, controls);
    },

    async audit(artifact, options = {}) {
      object(options, ["strict", "signal"], "audit options");
      const strict = options.strict ?? false;
      if (typeof strict !== "boolean") input("strict must be a boolean.");
      return call("audit", [path(artifact, "artifact"), ...(strict ? ["--strict"] : [])],
        { strict }, { signal: options.signal });
    },

    async gate(options, controls) {
      object(options, ["artifact", "policy", "root"], "gate options");
      return call("gate", [
        path(options.artifact, "artifact"),
        `--policy=${path(options.policy, "policy")}`,
        ...(options.root === undefined ? [] : [`--root=${path(options.root, "root")}`]),
      ], {}, controls);
    },

    async verifyManifest(options, controls) {
      object(options, ["manifest", "root", "publicKey", "product", "release"], "verifyManifest options");
      const product = text(options.product, "product");
      const release = options.release === undefined ? undefined : text(options.release, "release");
      return call("manifest-verify", [
        path(options.manifest, "manifest"),
        `--root=${path(options.root, "root")}`,
        `--public=${path(options.publicKey, "publicKey")}`,
        `--product=${product}`,
        ...(release === undefined ? [] : [`--release=${release}`]),
      ], { product, release }, controls);
    },

    async verifyLicense(options, controls) {
      object(options, ["license", "publicKey", "product", "subject", "requiredFeatures"], "verifyLicense options");
      const product = text(options.product, "product");
      const subject = options.subject === undefined ? undefined : text(options.subject, "subject");
      const requiredFeatures = options.requiredFeatures ?? [];
      if (!Array.isArray(requiredFeatures) || requiredFeatures.length > 128
          || requiredFeatures.some((feature) => typeof feature !== "string"
            || !/^[A-Za-z0-9_.:-]{1,64}$/u.test(feature))
          || new Set(requiredFeatures).size !== requiredFeatures.length) {
        input("requiredFeatures must contain at most 128 unique feature identifiers.");
      }
      // Copy before awaiting the child: later caller mutations cannot change
      // which expected features this invocation validates.
      const features = [...requiredFeatures];
      return call("license-verify", [
        path(options.license, "license"),
        `--public=${path(options.publicKey, "publicKey")}`,
        `--product=${product}`,
        ...(subject === undefined ? [] : [`--subject=${subject}`]),
        ...features.map((feature) => `--require-feature=${feature}`),
      ], { product, subject, requiredFeatures: features }, controls);
    },
  });
}
