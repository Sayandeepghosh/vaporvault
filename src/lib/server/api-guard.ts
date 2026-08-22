import "server-only";

import { resolveClientIdentity, type ClientIdentity } from "@/lib/server/client-identity";
import { getServerConfig, type RateRule } from "@/lib/server/config";
import { jsonError } from "@/lib/server/http";
import { logger } from "@/lib/server/logger";
import { enforceRateLimit, type RateLimitDecision } from "@/lib/server/rate-limit";
import { guardStateChangingRequest } from "@/lib/server/request-guard";

/**
 * The single gate every mutating endpoint passes through: CSRF/content-type checks, then
 * two independent rate-limit tiers.
 *
 * Keeping it in one place means neither route can accidentally skip a control, and the
 * ordering (cheap header checks before any Redis round-trip) is enforced by construction.
 */

export type ApiScope = "create" | "reveal";

export interface ApiRequestContext {
  readonly identity: ClientIdentity;
}

let attributionWarningEmitted = false;

/**
 * Tell the operator, once, that per-client rate limiting is not actually in effect.
 *
 * Silently degrading to a shared bucket is the kind of thing nobody notices until it is
 * abused, so it gets exactly one loud line in the logs per process.
 */
function warnOnceAboutAttribution(trusted: boolean): void {
  if (trusted || attributionWarningEmitted) return;
  attributionWarningEmitted = true;
  logger.warn("ratelimit.no_client_attribution", {
    detail:
      "No trustworthy client address is available, so all callers share one rate-limit pool. " +
      "Put the app behind a reverse proxy and set TRUSTED_PROXY_HOPS (and CLIENT_IP_HEADER) to enable per-client limits.",
  });
}

function rateLimitResponse(decision: Extract<RateLimitDecision, { allowed: false }>): Response {
  if (decision.reason === "unavailable") {
    // Fail closed: without Redis there is no brute-force protection, so refuse service.
    return jsonError("service_unavailable", 503, {
      retryAfterSeconds: decision.retryAfterSeconds,
    });
  }
  return jsonError("rate_limited", 429, { retryAfterSeconds: decision.retryAfterSeconds });
}

export async function guardApiRequest(
  request: Request,
  scope: ApiScope,
): Promise<Response | ApiRequestContext> {
  const config = getServerConfig();

  const failure = guardStateChangingRequest(request, config);
  if (failure === "unsupported_media_type") return jsonError("unsupported_media_type", 415);
  if (failure === "forbidden") return jsonError("forbidden", 403);

  const identity = resolveClientIdentity(request.headers, config);
  warnOnceAboutAttribution(identity.trusted);

  // Per-client tier. Without a trustworthy client address, a per-client bucket would be
  // meaningless, so those requests share one clearly-labelled pool instead.
  const perClientRules: ReadonlyArray<RateRule> = identity.trusted
    ? scope === "create"
      ? config.rateLimits.create
      : config.rateLimits.reveal
    : [
        {
          name: "unattributed",
          limit: config.rateLimits.unattributedPerMinute,
          windowMs: 60_000,
        },
      ];

  const perClient = await enforceRateLimit({
    scope,
    identity: identity.value,
    rules: perClientRules,
  });
  if (!perClient.allowed) return rateLimitResponse(perClient);

  // Whole-instance tier: bounds cost even when traffic is spread across many addresses.
  const global = await enforceRateLimit({
    scope: `${scope}:all`,
    identity: "all",
    rules: scope === "create" ? config.rateLimits.globalCreate : config.rateLimits.globalReveal,
  });
  if (!global.allowed) return rateLimitResponse(global);

  return { identity };
}
