import { jsonError, jsonOk } from "@/lib/server/http";
import { describeError, logger } from "@/lib/server/logger";
import { getSecretsRedis } from "@/lib/server/redis";

/**
 * GET /api/health — liveness/readiness for container orchestration.
 *
 * Unauthenticated by design so a load balancer can call it, and therefore deliberately
 * uninformative: it returns up or down and nothing else. No version, no dependency names,
 * no error text. The only work it does is a Redis PING, which is too cheap to be a useful
 * amplification target.
 */

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(): Promise<Response> {
  try {
    await getSecretsRedis().ping();
    return jsonOk({ status: "ok" });
  } catch (error) {
    logger.error("health.degraded", describeError(error));
    return jsonError("service_unavailable", 503);
  }
}
