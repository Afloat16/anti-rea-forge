/** Errors never automatically include child output, which can contain file paths. */
export class ReleaseGuardError extends Error {
  constructor(code, message, { exitCode, signal, diagnostic } = {}) {
    super(message);
    this.name = "ReleaseGuardError";
    this.code = code;
    if (exitCode !== undefined) this.exitCode = exitCode;
    if (signal !== undefined) this.signal = signal;
    // Inspect deliberately; console.error(error) should not dump child output.
    Object.defineProperty(this, "diagnostic", { value: diagnostic });
  }
}
