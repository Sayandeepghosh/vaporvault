# Security policy

## Reporting a vulnerability

Please report security issues privately using
[GitHub's private vulnerability reporting](https://github.com/Sayandeepghosh/vaporvault/security/advisories/new)
rather than opening a public issue.

Include what you need to make the report actionable: affected version or commit, the
component, a description of the impact, and reproduction steps or a proof of concept.

I aim to acknowledge a report within a few days. Please give me a reasonable window to ship
a fix before disclosing publicly.

## Scope

In scope:

- Anything that lets the server, the database, or a network observer recover a plaintext
  secret or a content key.
- Reading a secret more than once, or a secret surviving a successful read.
- Destroying a secret without an explicit user action (for example via `GET`, a link
  unfurler, or a prefetch).
- Distinguishing a secret that exists from one that does not.
- XSS, CSRF, or any channel that exfiltrates the URL fragment or the decrypted plaintext.
- Rate-limit bypass, or forcing the limiter to fail open.

Out of scope, because they are properties of the design rather than defects:

- **A compromised server can serve malicious JavaScript.** Browser-delivered crypto cannot
  defend against a hostile origin. Zero-knowledge protects data at rest and in transit.
- **Whoever holds the link can read the secret.** The link is the credential.
- **Denial of service by whoever holds the ciphertext.** The server can always drop or
  corrupt an envelope. It still cannot read it.
- **Ciphertext length reveals the approximate plaintext length.** There is no padding.
- **A read whose response is lost destroys the secret.** Deletion is atomic and happens
  before the response is delivered. Failing toward "destroyed" is deliberate.

The threat model in the README lists what is defended and how.

## Supported versions

`main` only. This is a single-branch project; fixes land there.

## Operator responsibilities

Several controls depend on deployment configuration and will not protect you if it is wrong:

- `APP_SECRET` must be 32+ random characters. It keys the HMAC that maps secret ids onto
  Redis keys. The app refuses to start in production without it and rejects
  placeholder-looking values.
- `ALLOWED_ORIGINS` is the CSRF allow-list and must match how users reach the app.
- `TRUSTED_PROXY_HOPS` must equal the number of reverse proxies you actually operate.
  Setting it higher lets any client mint unlimited rate-limit identities and lock other
  users out of their own buckets.
- Serve over HTTPS. Web Crypto is unavailable in non-secure contexts, so the app cannot
  encrypt at all over plain HTTP.
