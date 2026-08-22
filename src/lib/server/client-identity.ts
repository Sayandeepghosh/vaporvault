import "server-only";

import { getServerConfig, type ServerConfig } from "@/lib/server/config";

/**
 * Establishing *who* is calling, without trusting attacker-controlled headers.
 *
 * `X-Forwarded-For` is appended to by every hop, so any client can prepend arbitrary
 * entries. Trusting the left-most entry (the common mistake) hands attackers an
 * unlimited supply of rate-limit identities. We therefore only accept a value we can
 * attribute to a proxy we actually operate, and we count hops from the right.
 *
 * With `TRUSTED_PROXY_HOPS = n`, the header we receive looks like
 *   `client, proxy1, ..., proxy(n-1)`
 * so the last entry we can trust is at index `length - n`. Anything to the left of that
 * was supplied by the client.
 *
 * When no trustworthy source is configured we fall back to a single shared bucket rather
 * than pretending to have per-client attribution.
 */

export const UNATTRIBUTED_IDENTITY = "unattributed";

export interface ClientIdentity {
  readonly value: string;
  /** False when the value is a shared fallback bucket rather than a real client address. */
  readonly trusted: boolean;
}

const IPV4 =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

function isIpAddress(value: string): boolean {
  if (IPV4.test(value)) return true;
  // Loose IPv6 check: hex groups separated by colons, optionally with an embedded IPv4
  // tail or a `::` compression marker. Precision is unnecessary here because the value is
  // only ever used as an opaque bucket key.
  return value.includes(":") && /^[0-9a-fA-F:.]{2,45}$/.test(value) && !value.includes("..");
}

/** Strip `:port` from IPv4 and `[..]:port` from IPv6 forms. */
function stripPort(value: string): string {
  if (value.startsWith("[")) {
    const closing = value.indexOf("]");
    return closing === -1 ? value : value.slice(1, closing);
  }
  const firstColon = value.indexOf(":");
  if (firstColon !== -1 && value.indexOf(":", firstColon + 1) === -1) {
    // Exactly one colon: IPv4:port.
    return value.slice(0, firstColon);
  }
  return value;
}

export function resolveClientIdentity(
  headers: Headers,
  config: ServerConfig = getServerConfig(),
): ClientIdentity {
  const hops = config.trustedProxyHops;
  if (hops === 0) {
    return { value: UNATTRIBUTED_IDENTITY, trusted: false };
  }

  const raw = headers.get(config.clientIpHeader);
  if (!raw) return { value: UNATTRIBUTED_IDENTITY, trusted: false };

  const entries = raw
    .split(",")
    .map((entry) => stripPort(entry.trim()))
    .filter((entry) => entry.length > 0);

  // Fewer entries than trusted hops means the chain is not what we were told to expect.
  if (entries.length < hops) return { value: UNATTRIBUTED_IDENTITY, trusted: false };

  const candidate = entries[entries.length - hops];
  if (!candidate || !isIpAddress(candidate)) {
    return { value: UNATTRIBUTED_IDENTITY, trusted: false };
  }

  return { value: candidate.toLowerCase(), trusted: true };
}
