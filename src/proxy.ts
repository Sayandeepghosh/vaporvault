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
  // Skip build assets: they need long-lived caching and carry no user data.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|robots.txt).*)"],
};
