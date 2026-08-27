import { NextResponse, type NextRequest } from "next/server";

/**
 * Per-request security headers.
 *
 * Only the Content-Security-Policy lives here, because a strict, nonce-based policy has
 * to be generated fresh for every response. All static headers are declared in
 * `next.config.ts` so they still apply to anything this matcher does not cover.
 *
 * (Next.js 16 renamed the `middleware` convention to `proxy`; the API is unchanged.)
 */

function generateNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function buildCsp(nonce: string, isProduction: boolean): string {
  const scriptSrc = isProduction
    ? // 'strict-dynamic' lets Next's nonced bootstrap load its own chunks while making
      // any injected <script> without the nonce unexecutable.
      `'self' 'nonce-${nonce}' 'strict-dynamic'`
    : // The dev server needs eval for hot reloading. Never reached in production.
      `'self' 'unsafe-eval' 'unsafe-inline'`;

  const directives = [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
    // React and Next inline a small amount of CSS. Inline *styles* cannot execute code;
    // this is a deliberate, bounded relaxation and does not weaken script-src.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    // Same-origin XHR only. Nothing may phone home with a secret.
    "connect-src 'self'",
    "worker-src 'self' blob:",
    "manifest-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    // The UI never performs a native form submission, so no destination is legitimate.
    // This blocks a whole class of exfiltration-by-form-injection.
    "form-action 'none'",
    "frame-ancestors 'none'",
    "frame-src 'none'",
  ];

  if (isProduction) directives.push("upgrade-insecure-requests");

  return directives.join("; ");
}

export function proxy(request: NextRequest): NextResponse {
  const isProduction = process.env.NODE_ENV === "production";
  const nonce = generateNonce();
  const csp = buildCsp(nonce, isProduction);

  // Next.js reads the nonce back out of the CSP request header to stamp its own scripts.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("content-security-policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("content-security-policy", csp);

  // Secret pages must never be cached or indexed. The id in the path is half of the
  // capability needed to burn the secret.
  if (request.nextUrl.pathname.startsWith("/s/")) {
    response.headers.set("cache-control", "no-store, no-cache, must-revalidate, private");
    response.headers.set("x-robots-tag", "noindex, nofollow, noarchive, nosnippet");
  }

  return response;
}

export const config = {
  /**
   * Skip build assets: they need long-lived caching, carry no user data, and must not
   * receive a per-request nonce that would then sit in shared caches.
   *
   * Every exclusion is anchored and has its dots escaped. An unanchored pattern with a
   * bare `.` is a real hole rather than a cosmetic one: `favicon.ico` would also match
   * `/faviconXico`, and a prefix-only `_next/static` would also match `/_next/staticx`.
   * Those paths render the full HTML app shell, so they would have been served with no
   * Content-Security-Policy at all.
   */
  /*
   * Only genuinely static, non-HTML responses are excluded, and each has been verified to
   * be so: `_next/static/` serves JS and CSS, `icon.svg` an image, `robots.txt` plain text.
   *
   * `favicon.ico` is deliberately NOT excluded. There is no `public/favicon.ico`, so Next
   * falls through and serves the HTML 404 page for it — and browsers request that path on
   * every page load, which made it the single most-fetched un-CSP'd HTML response in the
   * app. Anything that can return HTML must go through the proxy.
   */
  matcher: ["/((?!_next/static/|icon\\.svg$|robots\\.txt$).*)"],
};
