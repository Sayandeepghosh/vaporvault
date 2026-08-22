import { MAX_REQUEST_BODY_BYTES } from "@/lib/constants";
import { createSecretRequestSchema } from "@/lib/api-contract";
import { guardApiRequest } from "@/lib/server/api-guard";
import {
  BodyTooLargeError,
  MalformedBodyError,
  jsonError,
  jsonOk,
  readJsonBody,
} from "@/lib/server/http";
import { describeError, logger } from "@/lib/server/logger";
import { createSecret, SecretStoreError } from "@/lib/server/secret-store";

/**
 * POST /api/secrets — store an already-encrypted envelope.
 *
 * The server sees `{ v, salt, iv, ct }` and a TTL. It has no way to derive the content
 * key: that requires the link key, which only ever exists in the sender's browser and in
 * the URL fragment.
 */

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  try {
    const guard = await guardApiRequest(request, "create");
    if (guard instanceof Response) return guard;

    let raw: unknown;
    try {
      raw = await readJsonBody(request, MAX_REQUEST_BODY_BYTES);
    } catch (error) {
      if (error instanceof BodyTooLargeError) return jsonError("payload_too_large", 413);
      if (error instanceof MalformedBodyError) return jsonError("invalid_request", 400);
      throw error;
    }

    const parsed = createSecretRequestSchema.safeParse(raw);
    if (!parsed.success) {
      // Validation detail is intentionally withheld; the client already knows the schema.
      return jsonError("invalid_request", 400);
    }

    const { id, expiresAt } = await createSecret({
      envelope: parsed.data.envelope,
      ttlSeconds: parsed.data.ttlSeconds,
    });

    logger.info("secret.created", { ttlSeconds: parsed.data.ttlSeconds });
    return jsonOk({ id, expiresAt }, 201);
  } catch (error) {
    if (error instanceof SecretStoreError) {
      logger.error("secret.create_rejected", { code: error.code });
      return error.code === "id_collision"
        ? jsonError("service_unavailable", 503)
        : jsonError("invalid_request", 400);
    }
    // Never leak the failure reason or a stack trace.
    logger.error("secret.create_failed", describeError(error));
    return jsonError("service_unavailable", 503);
  }
}

/** Creation is a POST-only operation; make that explicit rather than 404-ing. */
export async function GET(): Promise<Response> {
  return jsonError("method_not_allowed", 405);
}
