import "server-only";

import { getServerConfig, type ServerConfig } from "@/lib/server/config";

/**
 * CSRF and content-type policy for state-changing endpoints.
 *
 * VaporVault holds no cookies, sessions or ambient credentials, so classic CSRF has
 * little to steal. These checks still matter: without them, any origin can drive a
 * victim's browser into burning secrets (a destructive cross-site action) and into
 * consuming the victim's rate-limit budget.
 *
 * Layers, cheapest first:
 *  1. `Content-Type: application/json` — a value that cannot be produced by a plain HTML
 *     form, so simple form-based CSRF is structurally impossible and any cross-origin
 *     `fetch` is forced through a CORS preflight (which we never answer).
 *  2. `Sec-Fetch-Site` — set by the browser, unforgeable from script.
 *  3. `Origin` allow-list — the explicit check, for browsers and proxies alike.
 */

export type RequestGuardFailure = "unsupported_media_type" | "forbidden";

export function guardStateChangingRequest(
  request: Request,
  config: ServerConfig = getServerConfig(),
): RequestGuardFailure | null {
  const contentType = request.headers.get("content-type");
  if (!contentType || !contentType.toLowerCase().startsWith("application/json")) {
    return "unsupported_media_type";
  }

  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite !== null && fetchSite !== "same-origin") {
    return "forbidden";
  }

  const origin = request.headers.get("origin");
  if (origin !== null) {
    // `null` (as a literal string) is what sandboxed/opaque origins send. Never allow it.
    if (origin === "null") return "forbidden";
    let normalised: string;
    try {
      normalised = new URL(origin).origin;
    } catch {
      return "forbidden";
    }
    if (!config.allowedOrigins.has(normalised) && !isDevelopmentLoopback(normalised, config)) {
      return "forbidden";
    }
    return null;
  }

  // No Origin header. Browsers send one on every cross-origin request, and modern
  // browsers send it on same-origin POSTs too. Accept the request only when the browser
  // positively told us it is same-origin, or when we are running outside production
  // (so `curl` remains usable in development).
  if (fetchSite === "same-origin") return null;
  return config.isProduction ? "forbidden" : null;
}

function isDevelopmentLoopback(origin: string, config: ServerConfig): boolean {
  if (config.isProduction) return false;
  try {
    const { hostname } = new URL(origin);
    return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
  } catch {
    return false;
  }
}
