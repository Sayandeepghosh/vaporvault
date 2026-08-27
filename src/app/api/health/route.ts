import { REDIS_SECRET_PREFIX } from "@/lib/constants";
import { jsonError, jsonOk } from "@/lib/server/http";
import { describeError, logger } from "@/lib/server/logger";
import { getSecretsRedis } from "@/lib/server/redis";

const HEALTH_PROBE_KEY = `${REDIS_SECRET_PREFIX}health-probe`;

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
    const redis = getSecretsRedis();
    await redis.ping();
    /**
     * Assert a *write*, not just reachability.
     *
     * `PING` is not an OOM-denied command, so a Redis that has hit `maxmemory` under the
     * deliberate `noeviction` policy still answers it. That is the exact state in which the
     * app returns 503 for every request — the fail-closed rate limiter needs a write — so a
     * PING-only check reports healthy during a total outage and keeps traffic routed at it.
     */
    await redis.setIfAbsent(HEALTH_PROBE_KEY, "1", 30);
    return jsonOk({ status: "ok" });
  } catch (error) {
    logger.error("health.degraded", describeError(error));
    return jsonError("service_unavailable", 503);
  }
}
