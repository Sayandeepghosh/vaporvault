import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ConfigurationError, getServerConfig, resetServerConfigCache } from "@/lib/server/config";
import { guardStateChangingRequest } from "@/lib/server/request-guard";

/**
 * The CSRF gate, including the platform-supplied origin allow-list.
 *
 * These run without Redis: `guardStateChangingRequest` is pure header inspection, and the
 * origin allow-list is assembled from configuration alone.
 */

const PROD_HOST = "vault.example.com";
const PREVIEW_HOST = "vaporvault-abc123.vercel.app";
const BRANCH_HOST = "vaporvault-git-feat-x-acme.vercel.app";

function post(headers: Record<string, string>): Request {
  return new Request("https://vault.example.com/api/secrets", { method: "POST", headers });
}

const json = (extra: Record<string, string> = {}) => ({
  "content-type": "application/json",
  ...extra,
});

beforeEach(() => {
  vi.stubEnv("REDIS_URL", "redis://127.0.0.1:6379");
  vi.stubEnv("APP_SECRET", "test-app-secret-test-app-secret-0123456789");
  resetServerConfigCache();
});

afterEach(() => {
  vi.unstubAllEnvs();
  resetServerConfigCache();
});

describe("origin allow-list", () => {
  it("refuses to boot in production with no origin from any source", () => {
    vi.stubEnv("NODE_ENV", "production");
    resetServerConfigCache();
    expect(() => getServerConfig()).toThrowError(ConfigurationError);
  });

  it("accepts an explicitly configured origin and rejects everything else", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ALLOWED_ORIGINS", `https://${PROD_HOST}`);
    resetServerConfigCache();

    expect(guardStateChangingRequest(post(json({ origin: `https://${PROD_HOST}` })))).toBeNull();
    expect(guardStateChangingRequest(post(json({ origin: "https://evil.example" })))).toBe(
      "forbidden",
    );
  });

  it("trusts platform-supplied deployment URLs so preview deployments work", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("VERCEL_PROJECT_PRODUCTION_URL", PROD_HOST);
    vi.stubEnv("VERCEL_URL", PREVIEW_HOST);
    vi.stubEnv("VERCEL_BRANCH_URL", BRANCH_HOST);
    resetServerConfigCache();

    // No ALLOWED_ORIGINS at all: the platform values alone are enough to boot.
    expect(getServerConfig().allowedOrigins).toEqual(
      new Set([`https://${PROD_HOST}`, `https://${PREVIEW_HOST}`, `https://${BRANCH_HOST}`]),
    );

    for (const host of [PROD_HOST, PREVIEW_HOST, BRANCH_HOST]) {
      expect(guardStateChangingRequest(post(json({ origin: `https://${host}` })))).toBeNull();
    }
  });

  it("does not widen the allow-list beyond the deployment's own URLs", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("VERCEL_URL", PREVIEW_HOST);
    resetServerConfigCache();

    for (const origin of [
      "https://evil.example",
      // A lookalike subdomain, and http where the platform only serves https.
      "https://vaporvault-abc123.vercel.app.evil.example",
      `http://${PREVIEW_HOST}`,
    ]) {
      expect(guardStateChangingRequest(post(json({ origin }))), origin).toBe("forbidden");
    }
  });

  it("ignores platform variables when not running on the platform", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ALLOWED_ORIGINS", `https://${PROD_HOST}`);
    // Present but VERCEL itself is unset: a stray variable must not grant anything.
    vi.stubEnv("VERCEL_URL", PREVIEW_HOST);
    resetServerConfigCache();

    expect(guardStateChangingRequest(post(json({ origin: `https://${PREVIEW_HOST}` })))).toBe(
      "forbidden",
    );
  });
});

describe("request shape", () => {
  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ALLOWED_ORIGINS", `https://${PROD_HOST}`);
    resetServerConfigCache();
  });

  it("requires a JSON content type", () => {
    for (const contentType of [
      "application/x-www-form-urlencoded",
      "multipart/form-data",
      "text/plain",
    ]) {
      expect(
        guardStateChangingRequest(
          post({ "content-type": contentType, origin: `https://${PROD_HOST}` }),
        ),
        contentType,
      ).toBe("unsupported_media_type");
    }
  });

  it("accepts a JSON content type with parameters", () => {
    expect(
      guardStateChangingRequest(
        post({ "content-type": "application/json; charset=utf-8", origin: `https://${PROD_HOST}` }),
      ),
    ).toBeNull();
  });

  it("rejects an opaque origin", () => {
    expect(guardStateChangingRequest(post(json({ origin: "null" })))).toBe("forbidden");
  });

  it("rejects any non-same-origin fetch metadata, even with a good Origin", () => {
    for (const site of ["cross-site", "same-site", "none"]) {
      expect(
        guardStateChangingRequest(
          post(json({ origin: `https://${PROD_HOST}`, "sec-fetch-site": site })),
        ),
        site,
      ).toBe("forbidden");
    }
  });

  it("rejects a missing Origin in production but accepts a same-origin signal", () => {
    expect(guardStateChangingRequest(post(json()))).toBe("forbidden");
    expect(guardStateChangingRequest(post(json({ "sec-fetch-site": "same-origin" })))).toBeNull();
  });
});
