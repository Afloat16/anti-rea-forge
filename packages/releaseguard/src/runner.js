import { spawn } from "node:child_process";
import { ReleaseGuardError } from "./error.js";

/** Internal process boundary. No shell, stdin, or caller-supplied command flags. */
export function runCommand(executable, args, { timeoutMs, maxOutputBytes, signal }) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new ReleaseGuardError("ABORTED", "Release Guard was cancelled before starting."));
      return;
    }

    let child;
    let settled = false;
    let timer;
    let size = 0;
    const stdout = [];
    const stderr = [];

    function cleanup() {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    }

    function fail(error, terminate = false) {
      if (settled) return;
      settled = true;
      cleanup();
      if (terminate && child) {
        child.kill("SIGKILL");
        child.stdout?.destroy();
        child.stderr?.destroy();
        child.unref();
      }
      reject(error);
    }

    function abort() {
      fail(new ReleaseGuardError("ABORTED", "Release Guard was cancelled."), true);
    }

    function collect(chunks, chunk) {
      if (settled) return;
      size += chunk.length;
      if (size > maxOutputBytes) {
        fail(new ReleaseGuardError("OUTPUT_LIMIT", "Release Guard exceeded its combined output limit."), true);
        return;
      }
      chunks.push(chunk);
    }

    try {
      child = spawn(executable, args, {
        shell: false,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch {
      fail(new ReleaseGuardError("SPAWN_FAILED", "The configured Python interpreter could not be started."));
      return;
    }

    child.once("error", () => {
      fail(new ReleaseGuardError("SPAWN_FAILED", "The configured Python interpreter could not be started."));
    });
    child.stdout.on("data", (chunk) => collect(stdout, chunk));
    child.stderr.on("data", (chunk) => collect(stderr, chunk));
    for (const stream of [child.stdout, child.stderr]) {
      stream.once("error", () => {
        fail(new ReleaseGuardError("PROCESS_ERROR", "Could not read Release Guard output."), true);
      });
    }

    child.once("close", (exitCode, exitSignal) => {
      if (settled) return;
      if (exitSignal !== null || exitCode === null) {
        fail(new ReleaseGuardError("PROCESS_ERROR", "Release Guard did not exit normally.", {
          signal: exitSignal ?? undefined,
        }));
        return;
      }
      try {
        const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
        const result = {
          exitCode,
          stdout: decoder.decode(Buffer.concat(stdout)),
          stderr: decoder.decode(Buffer.concat(stderr)),
        };
        settled = true;
        cleanup();
        resolve(result);
      } catch {
        fail(new ReleaseGuardError("PROTOCOL_ERROR", "Release Guard returned invalid UTF-8 output."));
      }
    });

    timer = setTimeout(() => {
      fail(new ReleaseGuardError("TIMEOUT", "Release Guard exceeded its time limit."), true);
    }, timeoutMs);
    signal?.addEventListener("abort", abort, { once: true });
    // An AbortSignal can change between the initial check and listener setup.
    if (signal?.aborted) abort();
  });
}
