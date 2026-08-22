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

const SENSITIVE_KEY_PATTERN =
  /(secret|passphrase|password|token|cipher|ciphertext|envelope|plaintext|\bct\b|\bkey\b|\biv\b|salt|authorization|cookie|fragment|\bid\b)/i;

const MAX_VALUE_LENGTH = 256;

function sanitise(fields: LogFields): Record<string, LogValue> {
  const out: Record<string, LogValue> = {};
  for (const [key, value] of Object.entries(fields)) {
    if (value === undefined) continue;
    if (SENSITIVE_KEY_PATTERN.test(key)) {
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
