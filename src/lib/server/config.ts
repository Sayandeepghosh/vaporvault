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

  /**
   * Comma-separated list of origins allowed to call the API.
   * Required in production unless the platform supplies one (see `platformOrigins`).
   */
  ALLOWED_ORIGINS: z.string().optional(),

  /*
   * Vercel system variables. Set by the platform at build and run time, never by the
   * client, so they are safe to fold into the origin allow-list. Without them every
   * preview deployment would reject its own API calls, because its `*.vercel.app`
   * hostname is not something you can know in advance.
   */
  VERCEL: z.string().optional(),
  VERCEL_URL: z.string().optional(),
  VERCEL_BRANCH_URL: z.string().optional(),
  VERCEL_PROJECT_PRODUCTION_URL: z.string().optional(),

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

type PlatformEnv = Pick<
  z.infer<typeof envSchema>,
  "VERCEL" | "VERCEL_URL" | "VERCEL_BRANCH_URL" | "VERCEL_PROJECT_PRODUCTION_URL"
>;

/**
 * Origins the hosting platform guarantees belong to this deployment.
 *
 * Vercel exposes these as bare hostnames with no scheme, and always over HTTPS. They are
 * injected into the function environment by the platform, so unlike a request header they
 * cannot be influenced by a caller — which is what makes it safe to trust them for CSRF
 * decisions. Anything not on this list still has to be declared in `ALLOWED_ORIGINS`.
 */
/**
 * A bare DNS hostname: labels of letters, digits and interior hyphens, at least two of
 * them. Deliberately strict, because `new URL()` is far too permissive for this job —
 * `https://myapp.vercel.app@evil.example` parses happily and yields `https://evil.example`,
 * which would *replace* the deployment's own origin in the allow-list with an attacker's.
 */
const PLATFORM_HOSTNAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i;

function platformOrigins(env: PlatformEnv): string[] {
  if (!env.VERCEL) return [];

  const hosts = [env.VERCEL_PROJECT_PRODUCTION_URL, env.VERCEL_URL, env.VERCEL_BRANCH_URL];
  const origins: string[] = [];

  for (const host of hosts) {
    if (!host) continue;
    // Reject anything carrying a scheme, userinfo, port, path, comma or whitespace, and
    // always compose the origin ourselves over https. The platform documents these as bare
    // hostnames served over TLS; anything else means our assumption is wrong, and the safe
    // response is to ignore the value rather than to guess at it.
    if (!PLATFORM_HOSTNAME.test(host)) {
      console.warn("[vaporvault] ignoring malformed platform hostname in origin allow-list");
      continue;
    }
    origins.push(`https://${host.toLowerCase()}`);
  }

  return origins;
}

/**
 * Values published in `.env.example`, plus the usual suspects.
 *
 * The template's `APP_SECRET` placeholder is 42 characters, so it satisfies the 32-character
 * minimum. Without this check the documented Quick Start — `cp .env.example .env` — yields a
 * production deployment whose HMAC key is a string printed in a public repository, which
 * would let anyone recompute every Redis key and de-pseudonymise every rate-limit identity.
 */
const PLACEHOLDER_SECRET =
  /^(replace[-_ ]?me|change[-_ ]?me|change[-_ ]?this|changeit|your[-_ ]|devpassword|password|hunter2|insecure|placeholder|todo|xxxx)/i;

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
  for (const origin of platformOrigins(env)) allowedOrigins.add(origin);

  if (isProduction && allowedOrigins.size === 0) {
    throw new ConfigurationError(
      "No allowed origin is configured. Set ALLOWED_ORIGINS (a custom domain always needs it).",
    );
  }

  let appSecret = env.APP_SECRET;

  if (appSecret && PLACEHOLDER_SECRET.test(appSecret)) {
    if (isProduction) {
      throw new ConfigurationError(
        "APP_SECRET is still the example placeholder. Generate one with: openssl rand -hex 32",
      );
    }
    console.warn(
      "[vaporvault] APP_SECRET looks like the example placeholder. This must not reach production.",
    );
  }

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
