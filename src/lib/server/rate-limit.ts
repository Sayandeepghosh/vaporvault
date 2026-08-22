import "server-only";

import { createHmac, randomBytes } from "node:crypto";

import { REDIS_RATELIMIT_PREFIX } from "@/lib/constants";
import { toBase64Url } from "@/lib/crypto/encoding";
import { getServerConfig, type RateRule } from "@/lib/server/config";
import { describeError, logger } from "@/lib/server/logger";
import { getSecretsRedis, type SecretsRedis } from "@/lib/server/redis";

export type RateLimitDecision =
  | { readonly allowed: true }
  | {
      readonly allowed: false;
      readonly reason: "limited" | "unavailable";
      readonly retryAfterSeconds: number;
    };

export interface EnforceRateLimitInput {
  /** Logical bucket, e.g. `create` or `reveal`. */
  scope: string;
  /** Caller identity (an IP, or a constant for global/unattributed buckets). */
  identity: string;
  rules: ReadonlyArray<RateRule>;
  redis?: SecretsRedis;
  nowMs?: number;
}

/**
 * Pseudonymise the identity before it becomes part of a Redis key.
 *
 * Rate limiting should not turn Redis into a log of who visited. A keyed hash keeps the
 * buckets useful while making the stored value non-reversible without `APP_SECRET`.
 */
function hashIdentity(identity: string): string {
  const digest = createHmac("sha256", getServerConfig().clientIdentityKey)
    .update(identity)
    .digest();
  return toBase64Url(new Uint8Array(digest)).slice(0, 22);
}

/**
 * Sliding-window limiter.
 *
 * Every call records a hit *before* the verdict is known, so rejected requests still
 * consume budget. That is intentional: it makes brute-force attempts self-limiting
 * instead of free.
 *
 * Fails closed. If Redis cannot answer we deny rather than silently disabling the only
 * brute-force control in the system.
 */
export async function enforceRateLimit({
  scope,
  identity,
  rules,
  redis = getSecretsRedis(),
  nowMs = Date.now(),
}: EnforceRateLimitInput): Promise<RateLimitDecision> {
  if (rules.length === 0) return { allowed: true };

  const identityHash = hashIdentity(identity);
  const member = `${nowMs}:${randomBytes(8).toString("hex")}`;

  try {
    for (const rule of rules) {
      const key = `${REDIS_RATELIMIT_PREFIX}${scope}:${rule.name}:${identityHash}`;
      const hits = await redis.slidingWindowHit({
        key,
        windowMs: rule.windowMs,
        nowMs,
        member,
      });

      if (hits > rule.limit) {
        logger.warn("ratelimit.blocked", { scope, rule: rule.name, hits, limit: rule.limit });
        return {
          allowed: false,
          reason: "limited",
          // Upper bound: the window can never take longer than its own length to drain.
          retryAfterSeconds: Math.ceil(rule.windowMs / 1000),
        };
      }
    }

    return { allowed: true };
  } catch (error) {
    logger.error("ratelimit.unavailable", { scope, ...describeError(error) });
    return { allowed: false, reason: "unavailable", retryAfterSeconds: 5 };
  }
}
