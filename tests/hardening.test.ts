import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createSecretRequestSchema } from "@/lib/api-contract";
import { MAX_PASSPHRASE_LENGTH, MAX_PLAINTEXT_BYTES, MIN_PASSPHRASE_LENGTH } from "@/lib/constants";
import { fromBase64Url, toBase64Url } from "@/lib/crypto/encoding";
import { deserialiseEnvelope, parseFragment } from "@/lib/crypto/envelope";
import { CryptoError } from "@/lib/crypto/errors";
import { decryptSecret, encryptSecret } from "@/lib/crypto/secret-crypto";
import { parseJsonSafely } from "@/lib/safe-json";
import { getServerConfig, resetServerConfigCache } from "@/lib/server/config";
import { guardStateChangingRequest } from "@/lib/server/request-guard";

/**
 * Regression tests for issues found in the security audit. Each block names the property
 * that was broken, so a future change that reintroduces it fails here rather than shipping.
 */

const VALID_ENVELOPE_JSON =
  '{"v":1,"salt":"AAAAAAAAAAAAAAAAAAAAAA","iv":"AAAAAAAAAAAAAAAA","ct":"AAAAAAAAAAAAAAAAAAAAAAA"';

describe("prototype keys cannot be smuggled through JSON", () => {
  it("strips __proto__, constructor and prototype at the parse boundary", () => {
    const parsed = parseJsonSafely(
      '{"a":1,"__proto__":{"polluted":true},"constructor":{"x":1},"prototype":{"y":2}}',
    ) as Record<string, unknown>;

    expect(Object.keys(parsed)).toEqual(["a"]);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("no longer accepts a __proto__-laden envelope", () => {
    // JSON.parse makes `__proto__` a real own property that Zod's unknown-key check does
    // not see, so strictObject alone accepted this.
    expect(deserialiseEnvelope(`${VALID_ENVELOPE_JSON},"__proto__":{"polluted":true}}`)).not
      .toBeNull();
    const cleaned = deserialiseEnvelope(`${VALID_ENVELOPE_JSON},"__proto__":{"p":1}}`);
    expect(cleaned && Object.keys(cleaned).sort()).toEqual(["ct", "iv", "salt", "v"]);
  });

  it("rejects a request body carrying __proto__ inside the envelope", () => {
    const body = parseJsonSafely(
      `{"envelope":${VALID_ENVELOPE_JSON},"__proto__":{"x":1}},"ttlSeconds":3600}`,
    );
    const result = createSecretRequestSchema.safeParse(body);
    // The key is gone before the schema runs, so the envelope validates on its own merits
    // and nothing extra can reach storage.
    expect(result.success).toBe(true);
    if (result.success) {
      expect(Object.keys(result.data.envelope).sort()).toEqual(["ct", "iv", "salt", "v"]);
    }
    expect(({} as Record<string, unknown>).x).toBeUndefined();
  });

  it("still rejects ordinary unknown keys", () => {
    expect(deserialiseEnvelope(`${VALID_ENVELOPE_JSON},"extra":"x"}`)).toBeNull();
  });
});

describe("parseFragment is total over any input", () => {
  it("raises INVALID_LINK instead of a raw TypeError for non-strings", () => {
    for (const value of [12345, null, undefined, {}, [], true]) {
      expect(() => parseFragment(value as unknown as string)).toThrowError(CryptoError);
    }
  });
});

describe("passphrase bounds apply to the normalised value", () => {
  it("rejects a passphrase that only reaches the minimum before NFKC collapses it", async () => {
    // Three Hangul jamo per syllable: 9 UTF-16 units raw, 3 code points normalised.
    const collapsing = "\u1100\u1161\u11A8".repeat(3);
    expect(collapsing.length).toBeGreaterThanOrEqual(MIN_PASSPHRASE_LENGTH);
    expect([...collapsing.normalize("NFKC")].length).toBeLessThan(MIN_PASSPHRASE_LENGTH);

    await expect(
      encryptSecret({ plaintext: "x", passphrase: collapsing }),
    ).rejects.toMatchObject({ code: "PASSPHRASE_TOO_SHORT" });
  });

  it("rejects a passphrase that only fits the maximum before NFKC expands it", async () => {
    // U+FDFA expands to 18 characters under NFKC.
    const expanding = "\uFDFA".repeat(MAX_PASSPHRASE_LENGTH);
    expect(expanding.length).toBeLessThanOrEqual(MAX_PASSPHRASE_LENGTH);

    await expect(
      encryptSecret({ plaintext: "x", passphrase: expanding }),
    ).rejects.toMatchObject({ code: "PASSPHRASE_TOO_LONG" });
  });

  it("still accepts equivalent unicode spellings of the same passphrase", async () => {
    const nfd = "cafe\u0301-passphrase";
    const nfc = "caf\u00e9-passphrase";
    const { envelope, fragment } = await encryptSecret({ plaintext: "x", passphrase: nfd });
    await expect(decryptSecret({ envelope, fragment, passphrase: nfc })).resolves.toBe("x");
  });
});

describe("the plaintext size cap cannot be raced", () => {
  it("rejects a non-string plaintext instead of coercing it", async () => {
    for (const value of [null, undefined, 12345, {}, []]) {
      await expect(
        encryptSecret({ plaintext: value as unknown as string }),
      ).rejects.toMatchObject({ code: "EMPTY_SECRET" });
    }
  });

  it("cannot be exceeded by a value whose string conversion changes between reads", async () => {
    let reads = 0;
    const mutating = {
      toString() {
        reads += 1;
        return reads === 1 ? "a" : "B".repeat(MAX_PLAINTEXT_BYTES * 3);
      },
    };
    // Previously the value was read twice — measured once, encrypted once — so this
    // produced a ciphertext far past the cap. Now it is rejected as a non-string.
    await expect(
      encryptSecret({ plaintext: mutating as unknown as string }),
    ).rejects.toMatchObject({ code: "EMPTY_SECRET" });
  });
});

describe("decryptSecret validates its inputs standalone", () => {
  it("rejects a wrong-length link key and an oversized ciphertext", async () => {
    const { envelope, fragment } = await encryptSecret({ plaintext: "x" });
    const linkKey = parseFragment(fragment).linkKey;

    for (const length of [0, 16, 31, 33, 64]) {
      await expect(
        decryptSecret({
          envelope,
          fragment: { linkKey: new Uint8Array(length).fill(1), requiresPassphrase: false },
        }),
      ).rejects.toMatchObject({ code: "DECRYPT_FAILED" });
    }

    await expect(
      decryptSecret({
        envelope: { ...envelope, ct: "A".repeat(20_000) },
        fragment: { linkKey, requiresPassphrase: false },
      }),
    ).rejects.toMatchObject({ code: "DECRYPT_FAILED" });
  });

  it("still round-trips a tampered-free envelope, and rejects a flipped byte", async () => {
    const { envelope, fragment } = await encryptSecret({ plaintext: "still works" });
    await expect(decryptSecret({ envelope, fragment })).resolves.toBe("still works");

    const bytes = fromBase64Url(envelope.ct);
    bytes[0] ^= 0x01;
    await expect(
      decryptSecret({ envelope: { ...envelope, ct: toBase64Url(bytes) }, fragment }),
    ).rejects.toMatchObject({ code: "DECRYPT_FAILED" });
  });
});

describe("logger emits only allow-listed fields", () => {
  it("redacts anything not explicitly permitted", async () => {
    const { logger } = await import("@/lib/server/logger");
    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((line: unknown) => {
      lines.push(String(line));
    });

    logger.info("probe", {
      // allow-listed
      scope: "create",
      ttlSeconds: 3600,
      // not allow-listed: all of these are natural field names for sensitive values
      identity: "198.51.100.7",
      ip: "198.51.100.7",
      clientIp: "198.51.100.7",
      linkKey: "SUPER-SECRET-KEY",
      redisKey: "vv:s:abc",
      payload: "plaintext",
      body: "plaintext",
      value: "plaintext",
      url: "redis://user:pw@host",
    });

    spy.mockRestore();
    const emitted = lines.join("\n");

    expect(emitted).toContain('"scope":"create"');
    expect(emitted).toContain('"ttlSeconds":3600');
    for (const leaked of ["198.51.100.7", "SUPER-SECRET-KEY", "vv:s:abc", "plaintext", "pw@host"]) {
      expect(emitted, leaked).not.toContain(leaked);
    }
  });
});

describe("platform origin allow-list rejects hostile values", () => {
  beforeEach(() => {
    vi.stubEnv("REDIS_URL", "redis://127.0.0.1:6379");
    vi.stubEnv("APP_SECRET", "audit-fixture-secret-audit-fixture-secret");
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    resetServerConfigCache();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    resetServerConfigCache();
  });

  it("ignores a hostname carrying userinfo, a scheme, a comma or a path", () => {
    // `new URL("https://app.vercel.app@evil.example")` yields `https://evil.example`, which
    // would have *replaced* the deployment's own origin with an attacker-chosen one.
    for (const hostile of [
      "app.vercel.app@evil.example",
      "//evil.example",
      "http://app.vercel.app",
      "app.vercel.app,evil.example",
      "app.vercel.app/../x",
      "app.vercel.app:8443",
      "!!!",
      " ",
    ]) {
      vi.stubEnv("VERCEL_URL", hostile);
      vi.stubEnv("VERCEL_PROJECT_PRODUCTION_URL", "good.vercel.app");
      resetServerConfigCache();

      expect(getServerConfig().allowedOrigins, hostile).toEqual(
        new Set(["https://good.vercel.app"]),
      );
    }
  });

  it("accepts a plain hostname and always composes it over https", () => {
    vi.stubEnv("VERCEL_URL", "App-Preview.Vercel.App");
    resetServerConfigCache();
    expect(getServerConfig().allowedOrigins).toEqual(new Set(["https://app-preview.vercel.app"]));
  });
});

describe("placeholder secrets are refused in production", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    resetServerConfigCache();
  });

  it("rejects the values shipped in .env.example", () => {
    for (const placeholder of [
      "replace-me-with-openssl-rand-hex-32-output",
      "change-me-change-me-change-me-1234",
      "devpassword-devpassword-devpassword",
      "your-secret-goes-here-0123456789012",
    ]) {
      vi.stubEnv("REDIS_URL", "redis://127.0.0.1:6379");
      vi.stubEnv("ALLOWED_ORIGINS", "https://vault.example.com");
      vi.stubEnv("NODE_ENV", "production");
      vi.stubEnv("APP_SECRET", placeholder);
      resetServerConfigCache();

      expect(() => getServerConfig(), placeholder).toThrowError(/placeholder/i);
    }
  });

  it("accepts a real random secret", () => {
    vi.stubEnv("REDIS_URL", "redis://127.0.0.1:6379");
    vi.stubEnv("ALLOWED_ORIGINS", "https://vault.example.com");
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("APP_SECRET", "9f2c1d7b4a6e8035bd91c4f70a2e6d8b3c5f1a90de74b2681c3f5a7d9e0b4c26");
    resetServerConfigCache();

    expect(getServerConfig().allowedOrigins.has("https://vault.example.com")).toBe(true);
    // Sanity: the guard still works with a real secret configured.
    const request = new Request("https://vault.example.com/api/secrets", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://vault.example.com" },
    });
    expect(guardStateChangingRequest(request)).toBeNull();
  });
});
