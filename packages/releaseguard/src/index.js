import { createClient } from "./client.js";

export { ReleaseGuardError } from "./error.js";

export function createReleaseGuard(options) {
  return createClient(options);
}
