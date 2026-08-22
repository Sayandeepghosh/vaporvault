import "server-only";

import { utf8Decode } from "@/lib/crypto/encoding";

/**
 * Uniform JSON responses.
 *
 * Every error is one of a small set of codes with a fixed, non-revealing message. In
 * particular a missing, expired, already-read, malformed or corrupt secret all produce
 * the exact same 404 body, so the API cannot be used to enumerate or probe ids.
 */

export type ApiErrorCode =
  | "invalid_request"
  | "unsupported_media_type"
  | "payload_too_large"
  | "forbidden"
  | "not_found"
  | "method_not_allowed"
  | "rate_limited"
  | "service_unavailable"
  | "internal_error";

const ERROR_MESSAGES: Record<ApiErrorCode, string> = {
  invalid_request: "The request payload was rejected.",
  unsupported_media_type: "Unsupported content type.",
  payload_too_large: "The encrypted payload is too large.",
  forbidden: "Request blocked.",
  not_found: "Secret not found or already destroyed.",
  method_not_allowed: "Method not allowed.",
  rate_limited: "Too many requests. Please slow down and try again.",
  service_unavailable: "Service temporarily unavailable.",
  internal_error: "Something went wrong.",
};

function baseHeaders(): Headers {
  return new Headers({
    "content-type": "application/json; charset=utf-8",
    // Secrets and their metadata must never be cached by a browser, CDN or proxy.
    "cache-control": "no-store, no-cache, must-revalidate, private",
    pragma: "no-cache",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  });
}

export function jsonOk(data: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  const headers = baseHeaders();
  for (const [key, value] of Object.entries(extraHeaders ?? {})) headers.set(key, value);
  return new Response(JSON.stringify(data), { status, headers });
}

export interface JsonErrorOptions {
  retryAfterSeconds?: number;
}

export function jsonError(
  code: ApiErrorCode,
  status: number,
  options: JsonErrorOptions = {},
): Response {
  const headers = baseHeaders();
  if (options.retryAfterSeconds !== undefined) {
    headers.set("retry-after", String(Math.max(1, Math.ceil(options.retryAfterSeconds))));
  }
  if (status === 405) headers.set("allow", "POST");

  return new Response(JSON.stringify({ error: code, message: ERROR_MESSAGES[code] }), {
    status,
    headers,
  });
}

export class BodyTooLargeError extends Error {
  constructor() {
    super("request body exceeds the configured limit");
    this.name = "BodyTooLargeError";
  }
}

export class MalformedBodyError extends Error {
  constructor() {
    super("request body is not valid JSON");
    this.name = "MalformedBodyError";
  }
}

/**
 * Read and parse a JSON body with a hard byte ceiling.
 *
 * The stream is consumed incrementally and aborted the moment the limit is exceeded, so a
 * lying (or absent) `Content-Length` cannot be used to make the process buffer unbounded
 * data. The header is still checked first as a cheap early rejection.
 */
export async function readJsonBody(request: Request, maxBytes: number): Promise<unknown> {
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    const size = Number(declared);
    if (!Number.isFinite(size) || size < 0) throw new MalformedBodyError();
    if (size > maxBytes) throw new BodyTooLargeError();
  }

  const body = request.body;
  if (body === null) throw new MalformedBodyError();

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      received += value.byteLength;
      if (received > maxBytes) throw new BodyTooLargeError();
      chunks.push(value);
    }
  } catch (error) {
    // Stop reading immediately; do not keep draining a client that is still sending.
    await reader.cancel().catch(() => undefined);
    throw error;
  }

  if (received === 0) throw new MalformedBodyError();

  const merged = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return JSON.parse(utf8Decode(merged));
  } catch {
    throw new MalformedBodyError();
  }
}
