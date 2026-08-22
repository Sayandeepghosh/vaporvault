import "server-only";

import Redis, { type RedisOptions } from "ioredis";

import { getServerConfig } from "@/lib/server/config";
import { describeError, logger } from "@/lib/server/logger";

/**
 * A deliberately tiny port in front of Redis.
 *
 * Only four operations are needed, each of which is atomic on the server side. Keeping
 * the surface this small means the burn-on-read and rate-limit logic can be exercised
 * against an in-memory double, and it makes the atomicity guarantees auditable in one
 * place instead of scattered across route handlers.
 */
export interface SecretsRedis {
  /** `SET key value EX ttl NX`. Resolves false when the key already existed. */
  setIfAbsent(key: string, value: string, ttlSeconds: number): Promise<boolean>;
  /** `GETDEL key`. Single atomic read-and-destroy; this is what makes reads one-time. */
  getAndDelete(key: string): Promise<string | null>;
  /** Sliding-window counter. Returns the number of hits inside the window, inclusive. */
  slidingWindowHit(input: SlidingWindowInput): Promise<number>;
  ping(): Promise<void>;
}

export interface SlidingWindowInput {
  readonly key: string;
  readonly windowMs: number;
  readonly nowMs: number;
  /** Unique per request, so simultaneous hits cannot collapse into one sorted-set member. */
  readonly member: string;
}

export class RedisUnavailableError extends Error {
  constructor(operation: string) {
    super(`redis operation timed out: ${operation}`);
    this.name = "RedisUnavailableError";
  }
}

/**
 * Bound every command with our own deadline.
 *
 * ioredis' `commandTimeout` only starts once a command is written to the socket, so a
 * command queued while the connection is down can hang far longer than expected. An
 * explicit race keeps request latency bounded during a Redis outage.
 */
async function withDeadline<T>(promise: Promise<T>, ms: number, operation: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new RedisUnavailableError(operation)), ms);
  });
  try {
    return await Promise.race([promise, deadline]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

class IoredisAdapter implements SecretsRedis {
  constructor(
    private readonly client: Redis,
    private readonly timeoutMs: number,
  ) {}

  async setIfAbsent(key: string, value: string, ttlSeconds: number): Promise<boolean> {
    const reply = await withDeadline(
      this.client.set(key, value, "EX", ttlSeconds, "NX"),
      this.timeoutMs,
      "setIfAbsent",
    );
    return reply === "OK";
  }

  async getAndDelete(key: string): Promise<string | null> {
    return withDeadline(this.client.getdel(key), this.timeoutMs, "getAndDelete");
  }

  async slidingWindowHit({ key, windowMs, nowMs, member }: SlidingWindowInput): Promise<number> {
    // MULTI/EXEC executes as a single isolated unit, so trim + record + count cannot
    // interleave with a concurrent request.
    const replies = await withDeadline(
      this.client
        .multi()
        .zremrangebyscore(key, 0, nowMs - windowMs)
        .zadd(key, nowMs, member)
        .zcard(key)
        .pexpire(key, windowMs)
        .exec(),
      this.timeoutMs,
      "slidingWindowHit",
    );

    if (!replies) throw new RedisUnavailableError("slidingWindowHit");
    for (const [error] of replies) {
      if (error) throw error;
    }

    const count = replies[2]?.[1];
    if (typeof count !== "number") throw new RedisUnavailableError("slidingWindowHit");
    return count;
  }

  async ping(): Promise<void> {
    await withDeadline(this.client.ping(), this.timeoutMs, "ping");
  }
}

function createClient(): Redis {
  const config = getServerConfig();
  const options: RedisOptions = {
    // Connect on first use; keeps `next build` from opening sockets.
    lazyConnect: true,
    connectTimeout: config.redis.connectTimeoutMs,
    commandTimeout: config.redis.commandTimeoutMs,
    maxRetriesPerRequest: 1,
    enableReadyCheck: true,
    keepAlive: 10_000,
    retryStrategy: (attempt) => Math.min(attempt * 200, 2_000),
    ...(config.redisUrl.startsWith("rediss://") ? { tls: {} } : {}),
  };

  const client = new Redis(config.redisUrl, options);
  // Without a listener, ioredis re-emits connection errors as uncaught exceptions.
  client.on("error", (error: unknown) => logger.error("redis.connection_error", describeError(error)));
  return client;
}

interface RedisCache {
  client: Redis;
  adapter: SecretsRedis;
}

const globalCache = globalThis as typeof globalThis & { __vaporvaultRedis?: RedisCache };

export function getSecretsRedis(): SecretsRedis {
  if (!globalCache.__vaporvaultRedis) {
    const client = createClient();
    globalCache.__vaporvaultRedis = {
      client,
      adapter: new IoredisAdapter(client, getServerConfig().redis.commandTimeoutMs),
    };
  }
  return globalCache.__vaporvaultRedis.adapter;
}
