import { guardApiRequest } from "@/lib/server/api-guard";
import { jsonError, jsonOk } from "@/lib/server/http";
import { describeError, logger } from "@/lib/server/logger";
import { consumeSecret } from "@/lib/server/secret-store";

/**
 * POST /api/secrets/:id/reveal — atomically read and destroy a secret.
 *
 * Why POST, and why a separate endpoint from the page URL:
 * link unfurlers, mail scanners, antivirus proxies and browser prefetchers all issue GET
 * requests against pasted URLs. If a GET could burn a secret, a secret would frequently
 * be destroyed before the recipient ever opened it. Destruction therefore requires an
 * explicit, non-idempotent POST that only our own UI issues after the user confirms.
 */

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface RouteContext {
  params: Promise<{ id: string }>;
}

export async function POST(request: Request, context: RouteContext): Promise<Response> {
  try {
    const guard = await guardApiRequest(request, "reveal");
    if (guard instanceof Response) return guard;

    const { id } = await context.params;

    // A malformed id returns the same 404 as a missing one: no shape oracle.
    const envelope = await consumeSecret({ id });
    if (!envelope) {
      logger.info("secret.reveal_miss");
      return jsonError("not_found", 404);
    }

    logger.info("secret.revealed");
    return jsonOk({ envelope }, 200);
  } catch (error) {
    logger.error("secret.reveal_failed", describeError(error));
    return jsonError("service_unavailable", 503);
  }
}

/**
 * Explicitly refuse GET. This is the control that stops a link preview, crawler or
 * prefetch from consuming a one-time secret.
 */
export async function GET(): Promise<Response> {
  return jsonError("method_not_allowed", 405);
}
