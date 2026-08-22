import "server-only";

import { createHmac, randomBytes } from "node:crypto";
import { z } from "zod";

import { MAX_TTL_SECONDS } from "@/lib/constants";

/**
 * Runtime configuration.
 *
 * Validated lazily (on first request) rather than at module load so that
 * `next build` and CI type-checks do not require production secrets, while a
 * misconfigured deployment still fails loudly on its very first request.
 */

const positiveInt = (fallback: number) => z.coerce.number().int().positive().default(fallback);

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),

  REDIS_URL: z.string().min(1, "REDIS_URL is required"),

  /**
   * Single high-entropy secret. Sub-keys for distinct purposes are derived from it,
   * so operators manage one value instead of several.
   */
  APP_SECRET: z.string().min(32, "APP_SECRET must be at least 32 characters").optional(),

  /** Comma-separated list of origins allowed to call the API. Required in production. */
  ALLOWED_ORIGINS: z.string().optional(),

  /**
   * Number of reverse proxies you actually operate between the internet and this app.
   * 0 (the default) means `X-Forwarded-For` is attacker-controlled and must be ignored.
   */
  TRUSTED_PROXY_HOPS: z.coerce.number().int().min(0).max(8).default(0),
  CLIENT_IP_HEADER: z.string().min(1).default("x-forwarded-for"),

  RATE_LIMIT_CREATE_PER_MINUTE: positiveInt(10),
  RATE_LIMIT_CREATE_PER_HOUR: positiveInt(60),
  RATE_LIMIT_REVEAL_PER_MINUTE: positiveInt(30),
  RATE_LIMIT_REVEAL_PER_HOUR: positiveInt(200),
  /** Whole-instance ceilings; blunt DDoS / cost protection. */
  RATE_LIMIT_GLOBAL_CREATE_PER_MINUTE: positiveInt(300),
  RATE_LIMIT_GLOBAL_REVEAL_PER_MINUTE: positiveInt(900),
  /** Shared bucket used when no trustworthy client IP can be established. */
  RATE_LIMIT_UNATTRIBUTED_PER_MINUTE: positiveInt(120),

  REDIS_COMMAND_TIMEOUT_MS: positiveInt(2_000),
  REDIS_CONNECT_TIMEOUT_MS: positiveInt(5_000),
});

export interface RateRule {
  readonly name: string;
  readonly limit: number;
  readonly windowMs: number;
}

export interface ServerConfig {
  readonly isProduction: boolean;
  readonly redisUrl: string;
  readonly allowedOrigins: ReadonlySet<string>;
  readonly trustedProxyHops: number;
  readonly clientIpHeader: string;
  readonly maxTtlSeconds: number;
  readonly redis: {
    readonly commandTimeoutMs: number;
    readonly connectTimeoutMs: number;
  };
  readonly rateLimits: {
    readonly create: ReadonlyArray<RateRule>;
    readonly reveal: ReadonlyArray<RateRule>;
    readonly globalCreate: ReadonlyArray<RateRule>;
    readonly globalReveal: ReadonlyArray<RateRule>;
    readonly unattributedPerMinute: number;
  };
  /** HMAC key for mapping secret ids onto Redis keys. */
  readonly secretIdKey: Buffer;
  /** HMAC key for pseudonymising client IPs in rate-limit keys. */
  readonly clientIdentityKey: Buffer;
}

export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigurationError";
  }
}

function parseOrigins(raw: string | undefined): Set<string> {
  const origins = new Set<string>();
  for (const candidate of (raw ?? "").split(",")) {
    const trimmed = candidate.trim();
    if (trimmed.length === 0) continue;
    let url: URL;
    try {
      url = new URL(trimmed);
    } catch {
      throw new ConfigurationError(`ALLOWED_ORIGINS contains an invalid URL: ${trimmed}`);
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new ConfigurationError(`ALLOWED_ORIGINS must use http(s): ${trimmed}`);
    }
    origins.add(url.origin);
  }
  return origins;
}

/** Domain-separated sub-key derivation, so one leaked purpose does not leak the others. */
function deriveSubKey(appSecret: string, label: string): Buffer {
  return createHmac("sha256", appSecret).update(`vaporvault/v1/${label}`).digest();
}

let cached: ServerConfig | null = null;

export function getServerConfig(): ServerConfig {
  if (cached) return cached;

  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    // Surface which variables are wrong, never their values.
    const fields = [...new Set(parsed.error.issues.map((issue) => issue.path.join(".")))];
    throw new ConfigurationError(`Invalid environment configuration: ${fields.join(", ")}`);
  }

  const env = parsed.data;
  const isProduction = env.NODE_ENV === "production";
  const allowedOrigins = parseOrigins(env.ALLOWED_ORIGINS);

  if (isProduction && allowedOrigins.size === 0) {
    throw new ConfigurationError("ALLOWED_ORIGINS must be set in production");
  }

  let appSecret = env.APP_SECRET;
  if (!appSecret) {
    if (isProduction) {
      throw new ConfigurationError("APP_SECRET must be set in production");
    }
    // Development convenience only: ephemeral, regenerated on every boot.
    appSecret = randomBytes(32).toString("hex");
    console.warn(
      "[vaporvault] APP_SECRET is not set; generated an ephemeral development secret. " +
        "Existing links will stop resolving after a restart.",
    );
  }

  cached = {
    isProduction,
    redisUrl: env.REDIS_URL,
    allowedOrigins,
    trustedProxyHops: env.TRUSTED_PROXY_HOPS,
    clientIpHeader: env.CLIENT_IP_HEADER.toLowerCase(),
    maxTtlSeconds: MAX_TTL_SECONDS,
    redis: {
      commandTimeoutMs: env.REDIS_COMMAND_TIMEOUT_MS,
      connectTimeoutMs: env.REDIS_CONNECT_TIMEOUT_MS,
    },
    rateLimits: {
      create: [
        { name: "m", limit: env.RATE_LIMIT_CREATE_PER_MINUTE, windowMs: 60_000 },
        { name: "h", limit: env.RATE_LIMIT_CREATE_PER_HOUR, windowMs: 3_600_000 },
      ],
      reveal: [
        { name: "m", limit: env.RATE_LIMIT_REVEAL_PER_MINUTE, windowMs: 60_000 },
        { name: "h", limit: env.RATE_LIMIT_REVEAL_PER_HOUR, windowMs: 3_600_000 },
      ],
      globalCreate: [
        { name: "m", limit: env.RATE_LIMIT_GLOBAL_CREATE_PER_MINUTE, windowMs: 60_000 },
      ],
      globalReveal: [
        { name: "m", limit: env.RATE_LIMIT_GLOBAL_REVEAL_PER_MINUTE, windowMs: 60_000 },
      ],
      unattributedPerMinute: env.RATE_LIMIT_UNATTRIBUTED_PER_MINUTE,
    },
    secretIdKey: deriveSubKey(appSecret, "secret-id"),
    clientIdentityKey: deriveSubKey(appSecret, "client-identity"),
  };

  return cached;
}

/** Test-only escape hatch. */
export function resetServerConfigCache(): void {
  cached = null;
}
