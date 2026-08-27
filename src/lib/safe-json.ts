/**
 * JSON parsing that cannot smuggle prototype keys.
 *
 * `JSON.parse` creates `__proto__` as a real own enumerable property, and Zod's
 * unknown-key check does not see it — so a `strictObject` schema accepts
 * `{"v":1,...,"__proto__":{...}}` even though it rejects `{"v":1,...,"extra":1}`. Nothing
 * downstream is currently exploitable, because Zod returns a fresh object and the storage
 * layer re-picks fields by name. But relying on that is relying on the *second* line of
 * defence, and any future refactor that spreads or merges the parsed input would turn it
 * into a live prototype-pollution bug.
 *
 * Stripping the keys at the single point where untrusted JSON enters the process closes
 * the class for every current and future schema.
 */

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function reviver(key: string, value: unknown): unknown {
  return FORBIDDEN_KEYS.has(key) ? undefined : value;
}

/** `JSON.parse` with prototype keys removed. Throws on malformed JSON, like the original. */
export function parseJsonSafely(text: string): unknown {
  return JSON.parse(text, reviver);
}
