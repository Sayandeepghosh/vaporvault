import Redis from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { REDIS_SECRET_PREFIX } from "@/lib/constants";
import { encryptSecret } from "@/lib/crypto/secret-crypto";
import { resetServerConfigCache } from "@/lib/server/config";
import type { SecretsRedis } from "@/lib/server/redis";

/**
 * Integration tests against a real Redis.
 *
 * The one-time guarantee rests entirely on Redis semantics (`SET NX EX`, `GETDEL`, and the
 * atomicity of `MULTI`), so a mock would verify nothing that matters. These are skipped
 * when no server is configured; `docker compose up redis` is enough to run them.
 */

const REDIS_URL = process.env.TEST_REDIS_URL;
const suite = REDIS_URL ? describe : describe.skip;

suite("secret store (real Redis)", () => {
  let raw: Redis;
  let createSecret: typeof import("@/lib/server/secret-store").createSecret;
  let consumeSecret: typeof import("@/lib/server/secret-store").consumeSecret;

  beforeAll(async () => {
    process.env.REDIS_URL = REDIS_URL;
    process.env.APP_SECRET = "test-app-secret-test-app-secret-0123456789";
    resetServerConfigCache();

    const store = await import("@/lib/server/secret-store");
    createSecret = store.createSecret;
    consumeSecret = store.consumeSecret;

    raw = new Redis(REDIS_URL!);
    await raw.flushdb();
  });

  afterAll(async () => {
    await raw?.flushdb();
    await raw?.quit();
    const { getSecretsRedis } = await import("@/lib/server/redis");
    // Release the pooled connection so Vitest can exit.
    await (getSecretsRedis() as unknown as { ping: () => Promise<void> }).ping().catch(() => {});
  });

  async function storeFresh(plaintext = "integration-secret") {
    const { envelope, fragment } = await encryptSecret({ plaintext });
    const { id, expiresAt } = await createSecret({ envelope, ttlSeconds: 300 });
    return { envelope, fragment, id, expiresAt };
  }

  it("stores the envelope and returns a 22-character id", async () => {
    const { id, expiresAt } = await storeFresh();
    expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(new Date(expiresAt).getTime()).toBeGreaterThan(Date.now());
  });

  it("never stores the raw id as the Redis key", async () => {
    const { id } = await storeFresh();
    const keys = await raw.keys(`${REDIS_SECRET_PREFIX}*`);
    expect(keys.length).toBeGreaterThan(0);
    expect(keys.some((key) => key.includes(id))).toBe(false);
  });

  it("applies the TTL to the stored key", async () => {
    await raw.flushdb();
    await storeFresh();
    const [key] = await raw.keys(`${REDIS_SECRET_PREFIX}*`);
    const ttl = await raw.ttl(key);
    expect(ttl).toBeGreaterThan(290);
    expect(ttl).toBeLessThanOrEqual(300);
  });

  it("returns the exact envelope that was stored", async () => {
    const { envelope, id } = await storeFresh();
    await expect(consumeSecret({ id })).resolves.toEqual(envelope);
  });

  it("destroys the secret on first read", async () => {
    // Start from a clean keyspace so the key count below is unambiguous.
    await raw.flushdb();
    const { id } = await storeFresh();
    expect(await raw.keys(`${REDIS_SECRET_PREFIX}*`)).toHaveLength(1);

    await expect(consumeSecret({ id })).resolves.not.toBeNull();
    await expect(consumeSecret({ id })).resolves.toBeNull();
    await expect(consumeSecret({ id })).resolves.toBeNull();

    expect(await raw.keys(`${REDIS_SECRET_PREFIX}*`)).toHaveLength(0);
  });

  it("hands the envelope to exactly one of many concurrent readers", async () => {
    const { id } = await storeFresh();

    const results = await Promise.all(
      Array.from({ length: 25 }, () => consumeSecret({ id })),
    );

    // This is the property GETDEL buys us: no read-then-delete window for a second
    // reader to slip through.
    expect(results.filter((value) => value !== null)).toHaveLength(1);
  });

  it("reports unknown, malformed and already-read ids identically", async () => {
    const { id } = await storeFresh();
    await consumeSecret({ id });

    for (const candidate of [id, "AAAAAAAAAAAAAAAAAAAAAA", "too-short", "", "!".repeat(22)]) {
      await expect(consumeSecret({ id: candidate })).resolves.toBeNull();
    }
  });

  it("treats a corrupt stored value as absent and still removes it", async () => {
    await raw.flushdb();
    const { id } = await storeFresh();
    const [key] = await raw.keys(`${REDIS_SECRET_PREFIX}*`);
    await raw.set(key, "{not-an-envelope", "KEEPTTL");

    await expect(consumeSecret({ id })).resolves.toBeNull();
    expect(await raw.exists(key)).toBe(0);
  });

  it("refuses TTLs outside the permitted range", async () => {
    const { envelope } = await encryptSecret({ plaintext: "x" });
    for (const ttlSeconds of [0, 30, 86_401, -1, 1.5, Number.NaN]) {
      await expect(createSecret({ envelope, ttlSeconds })).rejects.toMatchObject({
        code: "invalid_ttl",
      });
    }
  });

  it("refuses an envelope that does not match the schema", async () => {
    const { envelope } = await encryptSecret({ plaintext: "x" });
    await expect(
      createSecret({
        envelope: { ...envelope, ct: "!!!" } as typeof envelope,
        ttlSeconds: 300,
      }),
    ).rejects.toMatchObject({ code: "invalid_envelope" });
  });
});

suite("rate limiter (real Redis)", () => {
  let raw: Redis;
  let enforceRateLimit: typeof import("@/lib/server/rate-limit").enforceRateLimit;

  beforeAll(async () => {
    process.env.REDIS_URL = REDIS_URL;
    process.env.APP_SECRET = "test-app-secret-test-app-secret-0123456789";
    resetServerConfigCache();

    ({ enforceRateLimit } = await import("@/lib/server/rate-limit"));
    raw = new Redis(REDIS_URL!);
    await raw.flushdb();
  });

  afterAll(async () => {
    await raw?.flushdb();
    await raw?.quit();
  });

  const rules = [{ name: "m", limit: 3, windowMs: 60_000 }];

  it("allows up to the limit, then blocks", async () => {
    const identity = `client-${Math.random()}`;

    for (let attempt = 1; attempt <= 3; attempt += 1) {
      const decision = await enforceRateLimit({ scope: "test", identity, rules });
      expect(decision.allowed, `attempt ${attempt}`).toBe(true);
    }

    const blocked = await enforceRateLimit({ scope: "test", identity, rules });
    expect(blocked).toMatchObject({ allowed: false, reason: "limited" });
  });

  it("keeps identities and scopes independent", async () => {
    const a = `a-${Math.random()}`;
    const b = `b-${Math.random()}`;

    for (let i = 0; i < 4; i += 1) await enforceRateLimit({ scope: "test", identity: a, rules });

    await expect(enforceRateLimit({ scope: "test", identity: a, rules })).resolves.toMatchObject({
      allowed: false,
    });
    await expect(enforceRateLimit({ scope: "test", identity: b, rules })).resolves.toMatchObject({
      allowed: true,
    });
    await expect(
      enforceRateLimit({ scope: "other", identity: a, rules }),
    ).resolves.toMatchObject({ allowed: true });
  });

  it("counts concurrent bursts correctly", async () => {
    const identity = `burst-${Math.random()}`;
    const decisions = await Promise.all(
      Array.from({ length: 10 }, () => enforceRateLimit({ scope: "test", identity, rules })),
    );
    // Exactly `limit` requests may pass, no matter how they interleave.
    expect(decisions.filter((decision) => decision.allowed)).toHaveLength(3);
  });

  it("lets the window slide", async () => {
    const identity = `slide-${Math.random()}`;
    const start = Date.now();

    for (let i = 0; i < 4; i += 1) {
      await enforceRateLimit({ scope: "test", identity, rules, nowMs: start });
    }
    await expect(
      enforceRateLimit({ scope: "test", identity, rules, nowMs: start }),
    ).resolves.toMatchObject({ allowed: false });

    // One window later the earlier hits have aged out.
    await expect(
      enforceRateLimit({ scope: "test", identity, rules, nowMs: start + 60_001 }),
    ).resolves.toMatchObject({ allowed: true });
  });

  it("does not leak the identity into the Redis key", async () => {
    const identity = "198.51.100.77";
    await enforceRateLimit({ scope: "leak", identity, rules });

    const keys = await raw.keys("vv:rl:leak:*");
    expect(keys.length).toBeGreaterThan(0);
    expect(keys.some((key) => key.includes(identity))).toBe(false);
  });

  it("expires its own bookkeeping keys", async () => {
    const identity = `ttl-${Math.random()}`;
    await enforceRateLimit({ scope: "ttlcheck", identity, rules });
    const [key] = await raw.keys("vv:rl:ttlcheck:*");
    const pttl = await raw.pttl(key);
    expect(pttl).toBeGreaterThan(0);
    expect(pttl).toBeLessThanOrEqual(60_000);
  });

  it("fails closed when Redis is unreachable", async () => {
    const broken: SecretsRedis = {
      setIfAbsent: async () => {
        throw new Error("down");
      },
      getAndDelete: async () => {
        throw new Error("down");
      },
      slidingWindowHit: async () => {
        throw new Error("down");
      },
      ping: async () => {
        throw new Error("down");
      },
    };

    // A limiter that fails open would silently remove the only brute-force control.
    await expect(
      enforceRateLimit({ scope: "test", identity: "x", rules, redis: broken }),
    ).resolves.toMatchObject({ allowed: false, reason: "unavailable" });
  });
});
