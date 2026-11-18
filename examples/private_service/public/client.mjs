/** The host supplies its existing authenticated transport; no private rules live here. */
export function requestQuote(quantity, capability, send) {
  if (!Number.isSafeInteger(quantity) || quantity < 0 || quantity > 100_000) {
    throw new TypeError("quantity must be an integer in 0..100000");
  }
  if (typeof send !== "function") throw new TypeError("an authenticated transport is required");
  const request = new TextEncoder().encode(JSON.stringify({ quantity }));
  return send({ request, capability });
}
