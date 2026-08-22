# VaporVault

> **🤖 Vibe Coded via "The Gauntlet Loop"**
>
> This project was architected and built using an adversarial AI prompting technique.
>
> - **Phase 1:** Drafted the initial architecture.
> - **Phase 2 (Red Team):** Executed a hostile Application Security Audit to find critical flaws (found 14 vulnerabilities including Read-Then-Delete race conditions, un-nonced CSPs, and XSS vectors).
> - **Phase 3:** Resolved all flaws securely before finalizing the codebase.
>
> *The result is a production-ready, zero-knowledge architecture built in a fraction of the standard development time.*

Zero-knowledge, one-time secret sharing. Paste a password or API key, get a link, and the
secret is destroyed the moment someone reads it.

The server never sees your plaintext. Encryption happens in the browser with AES-256-GCM,
and the decryption key travels in the URL fragment (`#...`), which browsers never send to a
server. VaporVault stores ciphertext it has no way to read.

**Stack:** Next.js 16 (App Router) · React 19 · Tailwind CSS 4 · Redis · Web Crypto API ·
TypeScript · Zod · Vitest

---

## Table of contents

- [How it works](#how-it-works)
- [Design decisions worth knowing](#design-decisions-worth-knowing)
- [Quick start (Docker Compose)](#quick-start-docker-compose)
- [Deploy to Vercel + Upstash Redis](#deploy-to-vercel--upstash-redis)
- [Local development](#local-development)
- [Scripts and tests](#scripts-and-tests)
- [Self-hosting behind a reverse proxy](#self-hosting-behind-a-reverse-proxy)
- [API](#api)
- [Threat model](#threat-model)
- [Project layout](#project-layout)

---

## How it works

```
 sender's browser                        server                    recipient's browser
 ────────────────                        ──────                    ───────────────────
 linkKey  = 32 random bytes
 salt     = 16 random bytes
 key      = HKDF(linkKey [+ PBKDF2(passphrase)], salt)
 ct       = AES-256-GCM(key, iv, secret, aad)
                          │
                          │  POST { v, salt, iv, ct }
                          ├──────────────────────────►  SET <hmac(id)> ... EX ttl NX
                          │  ◄─────── { id } ─────────
 link = /s/<id>#v1.<linkKey>
                                                        POST /api/secrets/<id>/reveal
                                     GETDEL <hmac(id)>  ◄──────────────────────────┤
                                     ─── { v, salt, iv, ct } ────────────────────► │
                                                                    key = HKDF(linkKey, salt)
                                                                    secret = decrypt(ct)
```

Everything left of the arrows stays in the browser. The server's entire view of a secret is
`{ v, salt, iv, ct }` plus a TTL.

The protocol, in full (version `v1`):

| Step | Value |
| --- | --- |
| Link key | 32 random bytes, base64url, lives only in the URL fragment |
| Salt | 16 random bytes, stored server-side (public) |
| Passphrase material | `PBKDF2-SHA256(NFKC(passphrase), salt, 600 000)` → 32 bytes, optional |
| Content key | `HKDF-SHA256(linkKey ‖ passMaterial, salt, "vaporvault.v1.content-key")` |
| Ciphertext | `AES-256-GCM(contentKey, iv, plaintext, aad)`, 96-bit iv, 128-bit tag |
| AAD | `"vaporvault.v1.p"` when a passphrase is set, `"vaporvault.v1.n"` otherwise |
| Fragment | `v1.<linkKey>` or `v1.<linkKey>.p` |

## Design decisions worth knowing

- **The key is in the fragment, not the path or query.** Fragments are stripped by the
  browser before a request is sent, never appear in server logs, and are never included in a
  `Referer`.
- **Reads destroy via `GETDEL`.** One Redis command reads and deletes atomically, so a race
  between two readers has exactly one winner. There is no read-then-delete window.
- **Destruction requires `POST`.** Link unfurlers, mail scanners and browser prefetchers all
  issue `GET`. If `GET` could burn a secret, secrets would routinely be destroyed before the
  recipient opened them. Visiting `/s/<id>` looks nothing up; only an explicit click does.
- **Algorithms are pinned by protocol version, not negotiated.** The wire format carries no
  cipher suite and no iteration count, which removes downgrade attacks and stops a hostile
  server from handing the browser a KDF cost that freezes the tab.
- **The passphrase flag lives in the fragment, not the envelope.** The server cannot be used
  as an oracle for how a secret is protected, and the flag is bound into the AAD so it cannot
  be stripped in transit.
- **Redis keys are `HMAC(APP_SECRET, id)`.** A stolen Redis snapshot cannot be turned back
  into working share links.
- **Rate limiting fails closed.** If Redis cannot answer, requests are refused rather than
  quietly running with no brute-force protection.
- **An optional passphrase is mixed into the key**, not checked by the server. It defends
  against the link itself leaking (chat history, clipboard managers, screen sharing).

---

## Quick start (Docker Compose)

```bash
cp .env.example .env

# Fill in the two required secrets.
printf 'APP_SECRET=%s\n'     "$(openssl rand -hex 32)" >> .env
printf 'REDIS_PASSWORD=%s\n' "$(openssl rand -hex 24)" >> .env

docker compose up --build
```

Open <http://localhost:3000>.

Redis runs with persistence disabled (`--save ""`, `--appendonly no`) on a `tmpfs`, so
ciphertext never touches a disk or a backup, and with `--maxmemory-policy noeviction` so
live secrets are never silently evicted under memory pressure.

---

## Deploy to Vercel + Upstash Redis

VaporVault runs on Vercel Functions unmodified. `output: "standalone"` is skipped
automatically when `VERCEL` is set, since the platform builds its own bundles.

### 1. Create the Redis database

Install the [Upstash integration](https://vercel.com/marketplace/upstash) from the Vercel
Marketplace, or create a database at [upstash.com](https://upstash.com) directly. Choose the
region **closest to your Vercel function region** — every request makes at least one Redis
round trip, so cross-continent latency is felt on every page.

Copy the **TCP** connection string, not the REST URL. It looks like:

```
rediss://default:<password>@<region>-<name>.upstash.io:6379
```

The `rediss://` scheme enables TLS automatically in `src/lib/server/redis.ts`. VaporVault
uses `GETDEL`, `SET NX EX` and `MULTI`/`EXEC`, all of which Upstash supports over TCP.

### 2. Push and import

```bash
./github_push.sh          # after editing YOUR_GITHUB_USERNAME
```

Then in Vercel: **Add New → Project → import the repository**. Framework detection picks up
Next.js on its own; no build settings need changing.

### 3. Set environment variables

See the [cheatsheet below](#environment-variables-for-vercel). Add them for **Production**,
**Preview** and **Development**, then redeploy so the first build picks them up.

### 4. Verify the deployment

```bash
curl -s https://<your-domain>/api/health                     # {"status":"ok"}
curl -sI https://<your-domain>/ | grep -i content-security   # nonce-... strict-dynamic
curl -s -o /dev/null -w '%{http_code}\n' \
     https://<your-domain>/api/secrets                       # 405 (POST only)
```

Then share a secret with yourself, open the link, and confirm a reload shows
*"Secret not found or already destroyed"*.

### Environment variables for Vercel

**Required**

| Variable | Value | Notes |
| --- | --- | --- |
| `REDIS_URL` | `rediss://default:<password>@<host>.upstash.io:6379` | Upstash **TCP** URL. Mark as Sensitive. |
| `APP_SECRET` | output of `openssl rand -hex 32` | 32+ chars. Mark as Sensitive. **Rotating it invalidates every outstanding link.** |

**Recommended**

| Variable | Value | Why |
| --- | --- | --- |
| `TRUSTED_PROXY_HOPS` | `1` | Vercel overwrites `X-Forwarded-For` with the real client IP and refuses to forward external values, precisely to stop spoofing — so exactly one hop is trustworthy. Leaving this at `0` puts every visitor in one shared rate-limit bucket. |
| `CLIENT_IP_HEADER` | `x-real-ip` | Mirrors `x-forwarded-for`, but cannot be clobbered by another proxy layered on top of Vercel. |
| `REDIS_COMMAND_TIMEOUT_MS` | `5000` | The 2 s default is tuned for a Redis on the same network. A cold function doing a TLS handshake to a managed provider needs more headroom. |

**Optional**

| Variable | Default | Notes |
| --- | --- | --- |
| `ALLOWED_ORIGINS` | derived | Not needed for `*.vercel.app`: the deployment's production, preview and branch URLs are added automatically from `VERCEL_PROJECT_PRODUCTION_URL`, `VERCEL_URL` and `VERCEL_BRANCH_URL`, which the platform sets and a caller cannot influence. **Do** set it if you serve from a custom domain, e.g. `https://vault.example.com`. |
| `RATE_LIMIT_CREATE_PER_MINUTE` | `10` | Per client. |
| `RATE_LIMIT_CREATE_PER_HOUR` | `60` | Per client. |
| `RATE_LIMIT_REVEAL_PER_MINUTE` | `30` | Per client. |
| `RATE_LIMIT_REVEAL_PER_HOUR` | `200` | Per client. |
| `RATE_LIMIT_GLOBAL_CREATE_PER_MINUTE` | `300` | Whole deployment. Lower this to cap Upstash spend. |
| `RATE_LIMIT_GLOBAL_REVEAL_PER_MINUTE` | `900` | Whole deployment. |
| `RATE_LIMIT_UNATTRIBUTED_PER_MINUTE` | `120` | Shared bucket, only used when no client IP is trustworthy. |
| `REDIS_CONNECT_TIMEOUT_MS` | `5000` | |

`NODE_ENV` is set to `production` by Vercel; do not add it yourself.

### Vercel-specific caveats

- **Enable Fluid Compute** (default on new projects). It reuses function instances, so the
  pooled Redis connection in `src/lib/server/redis.ts` is actually reused instead of
  reconnecting on every invocation.
- **Upstash is durable.** Unlike the Compose setup, a managed provider writes your data to
  disk and replicates it. The zero-knowledge guarantee is unaffected — it is ciphertext with
  no key — but the "nothing ever touches a disk" property of the self-hosted stack does not
  carry over.
- **Every page is a function invocation.** The nonce-based CSP requires per-request
  rendering, so the root layout sets `dynamic = "force-dynamic"`. There is no static HTML to
  cache, which is also what you want for a page that displays secrets.
- **Under very high concurrency**, TCP clients in serverless can exhaust connection limits.
  Upstash's own guidance is to switch to their HTTP SDK at that point; for this workload the
  rate limits cap concurrency long before it becomes an issue.

---

## Local development

```bash
npm install
cp .env.example .env.local

# A Redis is all you need; the bundled one works:
docker compose up -d redis

npm run dev
```

`APP_SECRET` may be omitted outside production — an ephemeral one is generated per boot, and
existing links stop resolving on restart.

## Scripts and tests

| Command | What it does |
| --- | --- |
| `npm run dev` | Dev server |
| `npm run build` | Production build (type-checks as part of the build) |
| `npm start` | Serve the production build |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run lint` | ESLint |
| `npm test` | Vitest |

Unit tests (crypto, codecs, envelope validation, the CSRF gate) need nothing. The integration
and end-to-end suites are skipped unless you point them at real infrastructure:

```bash
# Redis-backed: burn-on-read, concurrency, TTLs, the rate limiter
TEST_REDIS_URL=redis://:devpassword@127.0.0.1:6379 npm test

# Plus full HTTP round-trips against a running instance
TEST_REDIS_URL=redis://:devpassword@127.0.0.1:6379 \
E2E_BASE_URL=http://127.0.0.1:3000 \
E2E_ORIGIN=http://localhost:3000 npm test
```

---

## Self-hosting behind a reverse proxy

This matters more than it looks. Next.js populates `X-Forwarded-For` from the socket address
only when the client did not send one; a client-supplied value is passed through untouched.
A directly exposed app therefore cannot tell a real client address from an invented one,
so `TRUSTED_PROXY_HOPS` defaults to `0`, meaning "ignore that header". Rate limiting still
works, but every caller shares one pool. The app logs a warning once at startup when this is
the case.

With nginx in front:

```nginx
location / {
    proxy_pass         http://app:3000;
    proxy_set_header   Host              $host;
    proxy_set_header   X-Real-IP         $remote_addr;   # nginx overwrites; unspoofable
    proxy_set_header   X-Forwarded-Proto $scheme;
}
```

```env
TRUSTED_PROXY_HOPS=1
CLIENT_IP_HEADER=x-real-ip
```

Only ever set `TRUSTED_PROXY_HOPS` to the number of proxies that genuinely exist. Claiming
one that does not lets any client mint unlimited rate-limit identities.

Serve over HTTPS. The Web Crypto API is unavailable in non-secure contexts, so over plain
HTTP the app cannot encrypt at all (it says so rather than failing quietly).

---

## API

Two endpoints, both `POST`-only, both JSON, neither uses cookies.

### `POST /api/secrets`

```jsonc
// request
{
  "envelope": { "v": 1, "salt": "<b64url 16B>", "iv": "<b64url 12B>", "ct": "<b64url>" },
  "ttlSeconds": 3600 // 60 .. 86400
}

// 201
{ "id": "8Kd2mQ...", "expiresAt": "2026-08-22T12:00:00.000Z" }
```

### `POST /api/secrets/:id/reveal`

Reads and destroys in one atomic step.

```jsonc
// 200
{ "envelope": { "v": 1, "salt": "...", "iv": "...", "ct": "..." } }

// 404 - identical for missing, expired, already-read, and malformed ids
{ "error": "not_found", "message": "Secret not found or already destroyed." }
```

Errors are `{ error, message }` with a fixed message per code:
`400 invalid_request`, `403 forbidden`, `404 not_found`, `405 method_not_allowed`,
`413 payload_too_large`, `415 unsupported_media_type`, `429 rate_limited` (with
`Retry-After`), `503 service_unavailable`.

`GET /api/health` returns `{"status":"ok"}` or `503`. It is unauthenticated so a load
balancer can reach it, and returns nothing beyond up/down.

---

## Threat model

**Protected against**

| Threat | Control |
| --- | --- |
| Server or database compromise | Server holds only ciphertext; the key never reaches it |
| Ciphertext tampering | AES-GCM, with version and passphrase flag bound in as AAD |
| Two people reading one secret | Atomic `GETDEL` |
| Link previews / crawlers burning secrets | Destruction is `POST`-only; `GET` returns `405`; `noindex` and `no-store` on `/s/*` |
| Id enumeration | 128-bit ids, uniform `404`s, per-client and instance-wide rate limits |
| XSS | Nonce-based CSP with `strict-dynamic`, no `dangerouslySetInnerHTML`, React escaping |
| CSRF | No cookies at all, JSON-only content type, `Origin` allow-list, `Sec-Fetch-Site` |
| Exfiltration via injected markup | `form-action 'none'`, `connect-src 'self'`, `frame-ancestors 'none'`, `base-uri 'none'` |
| Secret id leaking to third parties | `Referrer-Policy: no-referrer` |
| Plaintext leaking to editor extensions | Grammarly/password-manager opt-outs on the secret field; the field has no `name` |
| Oversized payload DoS | 10 KB plaintext cap, streaming 20 KB body cap that ignores `Content-Length` |
| Rate-limit evasion via `X-Forwarded-For` | Hop-counted from the right; header ignored unless proxies are declared |
| Redis outage silently disabling limits | Limiter fails closed (`503`) |
| Secrets surviving in backups | Persistence disabled and `tmpfs` for `/data` (self-hosted; see the Vercel caveats) |
| Secret ids or ciphertext in logs | Redacting structured logger |

**Not protected against — by construction**

- **A compromised server can serve malicious JavaScript.** This is inherent to browser
  crypto: the code doing the encrypting is delivered by the server. Zero-knowledge protects
  data at rest and in transit, not against a hostile origin. The strict CSP and the absence
  of any third-party script reduce the blast radius; verifying the delivered code is beyond
  what a web app can do for you.
- **Anyone holding the link can read the secret.** The link *is* the credential. Use the
  optional passphrase when the channel is not trustworthy.
- **Denial of service is always available to whoever holds the ciphertext.** A hostile
  server can corrupt or drop an envelope. It still cannot read it.
- **Traffic analysis.** Ciphertext length reveals roughly how long the secret was.
- **A read that never arrives is a lost secret.** `GETDEL` destroys the value before the
  response is delivered, so a connection dropped mid-response loses the secret. Failing in
  the "destroyed" direction is the safe choice for a one-time secret. Within a single page
  view the fetched envelope is kept in memory, so a mistyped passphrase can be retried
  without losing anything.

---

## Project layout

```
src/
├── app/                      routes; api/secrets is the only write path
├── components/               UI; encryption is invoked from CreateSecretForm only
├── lib/
│   ├── crypto/               isomorphic: codec, envelope, AES-GCM + HKDF core
│   ├── server/               server-only: config, redis port, store, limiter, guards
│   ├── api-contract.ts       shared Zod schemas, so client and server cannot drift
│   └── constants.ts          the wire protocol, in one file
└── proxy.ts                  per-request nonce CSP
tests/                        crypto · CSRF gate · Redis integration · HTTP end-to-end
```

The crypto layer has no server imports and the server layer is fenced off with
`server-only`, so plaintext has no path to the backend even by accident.

## Licence

MIT — see [LICENSE](./LICENSE).
