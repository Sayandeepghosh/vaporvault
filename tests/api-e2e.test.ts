import { request as httpRequest } from "node:http";

import { beforeAll, describe, expect, it } from "vitest";

import { MAX_PLAINTEXT_BYTES } from "@/lib/constants";
import { decryptSecret, encryptSecret } from "@/lib/crypto/secret-crypto";

/**
 * End-to-end tests over real HTTP against a running instance.
 *
 * These exercise the whole path a browser takes: encrypt locally, POST ciphertext, POST to
 * reveal, decrypt locally. Skipped unless `E2E_BASE_URL` is set.
 *
 *   E2E_BASE_URL=http://127.0.0.1:3000 E2E_ORIGIN=http://localhost:3000 npm test
 */

const BASE_URL = process.env.E2E_BASE_URL;
const ORIGIN = process.env.E2E_ORIGIN ?? BASE_URL;
const suite = BASE_URL ? describe : describe.skip;

const JSON_HEADERS = (): Record<string, string> => ({
  "content-type": "application/json",
  origin: ORIGIN!,
});

async function createSecret(plaintext: string, ttlSeconds = 300) {
  const { envelope, fragment } = await encryptSecret({ plaintext });
  const response = await fetch(`${BASE_URL}/api/secrets`, {
    method: "POST",
    headers: JSON_HEADERS(),
    body: JSON.stringify({ envelope, ttlSeconds }),
  });
  return { response, fragment, envelope };
}

function reveal(id: string, init: RequestInit = {}) {
  return fetch(`${BASE_URL}/api/secrets/${id}/reveal`, {
    method: "POST",
    headers: JSON_HEADERS(),
    body: "{}",
    ...init,
  });
}

/**
 * POST a body using chunked transfer encoding, i.e. with no `Content-Length` at all.
 * `fetch` always computes the header for a string body, so raw `node:http` is needed to
 * prove the server does not depend on it.
 */
function postChunked(path: string, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const url = new URL(`${BASE_URL}${path}`);
    const request = httpRequest(
      {
        hostname: url.hostname,
        port: url.port || 80,
        path: url.pathname,
        method: "POST",
        headers: { "content-type": "application/json", origin: ORIGIN! },
      },
      (response) => {
        let received = "";
        response.setEncoding("utf8");
        response.on("data", (chunk: string) => {
          received += chunk;
        });
        response.on("end", () => resolve({ status: response.statusCode ?? 0, body: received }));
      },
    );
    request.on("error", reject);
    request.write(body);
    request.end();
  });
}

suite("HTTP end to end", () => {
  beforeAll(async () => {
    const probe = await fetch(`${BASE_URL}/api/secrets`, { method: "GET" });
    expect(probe.status, "server should be reachable").toBe(405);
  });

  it("completes the full share-and-read cycle", async () => {
    const plaintext = "postgres://user:hunter2@db.internal:5432/prod";

    const { response, fragment } = await createSecret(plaintext);
    expect(response.status).toBe(201);

    const created = (await response.json()) as { id: string; expiresAt: string };
    expect(created.id).toMatch(/^[A-Za-z0-9_-]{22}$/);

    const revealed = await reveal(created.id);
    expect(revealed.status).toBe(200);
    expect(revealed.headers.get("cache-control")).toContain("no-store");

    const body = (await revealed.json()) as { envelope: Parameters<typeof decryptSecret>[0]["envelope"] };
    await expect(decryptSecret({ envelope: body.envelope, fragment })).resolves.toBe(plaintext);
  });

  it("returns ciphertext that does not contain the plaintext", async () => {
    const plaintext = "canary-abc-do-not-appear-in-transit";
    const { response, fragment } = await createSecret(plaintext);
    const { id } = (await response.json()) as { id: string };

    const revealed = await reveal(id);
    const text = await revealed.text();

    expect(text).not.toContain("canary");
    // ...and the key is nowhere in the server's reply either.
    expect(text).not.toContain(fragment.split(".")[1]);
  });

  it("destroys the secret on the first successful reveal", async () => {
    const { response } = await createSecret("burn-after-reading");
    const { id } = (await response.json()) as { id: string };

    expect((await reveal(id)).status).toBe(200);

    const second = await reveal(id);
    expect(second.status).toBe(404);
    expect(await second.json()).toEqual({
      error: "not_found",
      message: "Secret not found or already destroyed.",
    });
  });

  it("serves exactly one winner under a concurrent reveal race", async () => {
    const { response } = await createSecret("only-one-of-you");
    const { id } = (await response.json()) as { id: string };

    const statuses = (await Promise.all(Array.from({ length: 15 }, () => reveal(id)))).map(
      (r) => r.status,
    );

    expect(statuses.filter((status) => status === 200)).toHaveLength(1);
    expect(statuses.filter((status) => status === 404)).toHaveLength(14);
  });

  it("does not let GET burn a secret", async () => {
    const { response, fragment } = await createSecret("survives-link-previews");
    const { id } = (await response.json()) as { id: string };

    // What a chat unfurler, mail scanner or prefetcher would do.
    const preview = await fetch(`${BASE_URL}/api/secrets/${id}/reveal`, { method: "GET" });
    expect(preview.status).toBe(405);

    const page = await fetch(`${BASE_URL}/s/${id}`, { method: "GET" });
    expect(page.status).toBe(200);

    // The secret is still there afterwards.
    const revealed = await reveal(id);
    expect(revealed.status).toBe(200);
    const { envelope } = (await revealed.json()) as {
      envelope: Parameters<typeof decryptSecret>[0]["envelope"];
    };
    await expect(decryptSecret({ envelope, fragment })).resolves.toBe("survives-link-previews");
  });

  it("gives an identical 404 for unknown and malformed ids", async () => {
    const unknown = await reveal("AAAAAAAAAAAAAAAAAAAAAA");
    const malformed = await reveal("nope");

    expect(unknown.status).toBe(404);
    expect(malformed.status).toBe(404);
    expect(await unknown.json()).toEqual(await malformed.json());
  });

  it("rejects an oversized payload", async () => {
    const response = await fetch(`${BASE_URL}/api/secrets`, {
      method: "POST",
      headers: JSON_HEADERS(),
      body: JSON.stringify({
        envelope: { v: 1, salt: "A".repeat(22), iv: "A".repeat(16), ct: "A".repeat(60_000) },
        ttlSeconds: 300,
      }),
    });
    expect(response.status).toBe(413);
  });

  it("rejects an oversized payload sent without a Content-Length", async () => {
    // Chunked transfer encoding: there is no Content-Length to pre-check, so only the
    // streaming byte cap in `readJsonBody` can stop this. Sized just over the 20 KB limit
    // so the request completes and the rejection is deterministic.
    const { status } = await postChunked("/api/secrets", "x".repeat(25 * 1024));
    expect(status).toBe(413);
  });

  it("rejects a plaintext-sized secret submitted unencrypted", async () => {
    const response = await fetch(`${BASE_URL}/api/secrets`, {
      method: "POST",
      headers: JSON_HEADERS(),
      body: JSON.stringify({ secret: "please store this for me", ttlSeconds: 300 }),
    });
    // There is no code path that accepts a plaintext field.
    expect(response.status).toBe(400);
  });

  it("rejects a TTL beyond 24 hours", async () => {
    const { envelope } = await encryptSecret({ plaintext: "x" });
    const response = await fetch(`${BASE_URL}/api/secrets`, {
      method: "POST",
      headers: JSON_HEADERS(),
      body: JSON.stringify({ envelope, ttlSeconds: 86_401 }),
    });
    expect(response.status).toBe(400);
  });

  it("accepts a secret at exactly the size limit", async () => {
    const plaintext = "z".repeat(MAX_PLAINTEXT_BYTES);
    const { response, fragment } = await createSecret(plaintext);
    expect(response.status).toBe(201);

    const { id } = (await response.json()) as { id: string };
    const { envelope } = (await (await reveal(id)).json()) as {
      envelope: Parameters<typeof decryptSecret>[0]["envelope"];
    };
    await expect(decryptSecret({ envelope, fragment })).resolves.toBe(plaintext);
  });

  it("blocks cross-origin and origin-less state changes", async () => {
    const { envelope } = await encryptSecret({ plaintext: "x" });
    const payload = JSON.stringify({ envelope, ttlSeconds: 300 });

    const cases: Array<[string, Record<string, string>]> = [
      ["evil origin", { "content-type": "application/json", origin: "https://evil.example" }],
      ["opaque origin", { "content-type": "application/json", origin: "null" }],
      ["no origin", { "content-type": "application/json" }],
      [
        "cross-site fetch metadata",
        { "content-type": "application/json", origin: ORIGIN!, "sec-fetch-site": "cross-site" },
      ],
    ];

    for (const [label, headers] of cases) {
      const response = await fetch(`${BASE_URL}/api/secrets`, {
        method: "POST",
        headers,
        body: payload,
      });
      expect(response.status, label).toBe(403);
    }
  });

  it("rejects non-JSON content types", async () => {
    const response = await fetch(`${BASE_URL}/api/secrets`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN! },
      body: "envelope=x&ttlSeconds=300",
    });
    expect(response.status).toBe(415);
  });

  it("never sets a cookie", async () => {
    const { response } = await createSecret("no-ambient-credentials");
    expect(response.headers.get("set-cookie")).toBeNull();
  });

  /**
   * Header contract.
   *
   * The proxy matcher previously used an unanchored pattern with unescaped dots, so paths
   * like `/favicon.ico`, `/faviconXico` and `/_next/staticx` were excluded from it while
   * still rendering the full HTML app shell — served with no Content-Security-Policy at
   * all. A table test over paths is the cheapest way to stop that class of regression.
   */
  it("serves a nonce-based CSP on every path that returns HTML", async () => {
    const paths = [
      "/",
      "/s/AAAAAAAAAAAAAAAAAAAAAA",
      "/favicon.ico",
      "/faviconXico",
      "/robotsXtxt",
      "/_next/staticx",
      "/_next/imagex",
      "/definitely-not-a-route",
    ];

    for (const path of paths) {
      const response = await fetch(`${BASE_URL}${path}`);
      const contentType = response.headers.get("content-type") ?? "";
      if (!contentType.includes("text/html")) continue;

      const csp = response.headers.get("content-security-policy");
      expect(csp, `${path} must carry a CSP`).toBeTruthy();
      expect(csp, `${path} must use a nonce`).toMatch(/script-src [^;]*'nonce-[A-Za-z0-9+/=]+'/);
      expect(csp, `${path} must not allow inline script`).not.toContain(
        "script-src 'self' 'unsafe-inline'",
      );
      expect(csp, `${path} must block form submission`).toContain("form-action 'none'");
      expect(csp, `${path} must block framing`).toContain("frame-ancestors 'none'");
      expect(csp, `${path} must keep XHR same-origin`).toContain("connect-src 'self'");
    }
  });

  it("stamps every script tag with the nonce from that same response", async () => {
    for (const path of ["/", "/s/AAAAAAAAAAAAAAAAAAAAAA"]) {
      const response = await fetch(`${BASE_URL}${path}`);
      const html = await response.text();
      const nonce = /'nonce-([A-Za-z0-9+/=]+)'/.exec(
        response.headers.get("content-security-policy") ?? "",
      )?.[1];

      expect(nonce, `${path} nonce`).toBeTruthy();
      const scripts = html.match(/<script(?![^>]*\bsrc="https?:)[^>]*>/g) ?? [];
      expect(scripts.length, `${path} should render scripts`).toBeGreaterThan(0);
      for (const tag of scripts) {
        expect(tag, `${path}: un-nonced script`).toContain(`nonce="${nonce}"`);
      }
    }
  });

  it("issues a fresh nonce per response", async () => {
    const nonces = new Set<string>();
    for (let i = 0; i < 3; i += 1) {
      const csp = (await fetch(`${BASE_URL}/`)).headers.get("content-security-policy") ?? "";
      nonces.add(/'nonce-([A-Za-z0-9+/=]+)'/.exec(csp)?.[1] ?? "");
    }
    expect(nonces.size).toBe(3);
  });

  it("keeps secret pages uncacheable and unindexable", async () => {
    const response = await fetch(`${BASE_URL}/s/AAAAAAAAAAAAAAAAAAAAAA`);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("x-robots-tag")).toContain("noindex");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
  });

  it("has removed the image optimizer endpoint entirely", async () => {
    // Not merely locked down with `remotePatterns: []` — the route should not exist, so the
    // whole class of image-decoder advisories is unreachable.
    const response = await fetch(`${BASE_URL}/_next/image?url=%2Ficon.svg&w=64&q=75`);
    expect(response.status).toBe(404);
  });

  it("caps a body sent to an endpoint that takes no input", async () => {
    const response = await fetch(`${BASE_URL}/api/secrets/AAAAAAAAAAAAAAAAAAAAAA/reveal`, {
      method: "POST",
      headers: JSON_HEADERS(),
      body: "x".repeat(64 * 1024),
    });
    expect(response.status).toBe(413);
  });
});
