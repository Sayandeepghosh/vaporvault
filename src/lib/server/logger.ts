import "server-only";

/**
 * Minimal structured logger with a hard redaction pass.
 *
 * Secret ids, ciphertext and key material must never reach logs: log aggregation is a
 * common exfiltration path, and a secret id is half of the capability needed to read a
 * secret. Anything whose key looks sensitive is replaced before serialisation.
 */

export type LogValue = string | number | boolean | null | undefined;
export type LogFields = Record<string, LogValue>;

const REDACTED = "[redacted]";

/**
 * Deny-list of field names whose values must never be serialised.
 *
 * A deny-list is the wrong shape for this job — it fails silently the moment someone
 * invents a new field name — so `emit` additionally drops any key that is not on the
 * explicit allow-list below. This pattern is kept as a second layer.
 */
const SENSITIVE_KEY_PATTERN =
  /(secret|passphrase|password|token|cipher|ciphertext|envelope|plaintext|\bct\b|key|\biv\b|salt|authorization|cookie|fragment|\bid\b|ident|\bip\b|addr|host|url|payload|body|data|value|content|hash|digest|referer|agent)/i;

/**
 * Field names this logger is permitted to emit verbatim.
 *
 * Anything else is redacted even if the deny-list above misses it, so adding a new log
 * field is a deliberate act rather than an accidental disclosure. Nothing here can carry
 * a secret id, ciphertext, key material or a client address.
 */
const ALLOWED_KEYS = new Set([
  "code",
  "detail",
  "durationMs",
  "errorMessage",
  "errorName",
  "event",
  "hits",
  "limit",
  "reason",
  "rule",
  "scope",
  "status",
  "trusted",
  "ttlSeconds",
]);

const MAX_VALUE_LENGTH = 256;

function sanitise(fields: LogFields): Record<string, LogValue> {
  const out: Record<string, LogValue> = {};
  for (const [key, value] of Object.entries(fields)) {
    if (value === undefined) continue;
    if (!ALLOWED_KEYS.has(key) || SENSITIVE_KEY_PATTERN.test(key)) {
      out[key] = REDACTED;
      continue;
    }
    out[key] =
      typeof value === "string" && value.length > MAX_VALUE_LENGTH
        ? `${value.slice(0, MAX_VALUE_LENGTH)}...`
        : value;
  }
  return out;
}

type Level = "debug" | "info" | "warn" | "error";

function emit(level: Level, event: string, fields: LogFields = {}): void {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    event,
    ...sanitise(fields),
  });

  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

export const logger = {
  debug: (event: string, fields?: LogFields) => emit("debug", event, fields),
  info: (event: string, fields?: LogFields) => emit("info", event, fields),
  warn: (event: string, fields?: LogFields) => emit("warn", event, fields),
  error: (event: string, fields?: LogFields) => emit("error", event, fields),
};

/**
 * Reduce an unknown thrown value to a loggable shape.
 * Keeps the error name and message; deliberately drops the stack.
 */
export function describeError(error: unknown): LogFields {
  if (error instanceof Error) {
    return { errorName: error.name, errorMessage: error.message.slice(0, MAX_VALUE_LENGTH) };
  }
  return { errorName: "UnknownError" };
}
