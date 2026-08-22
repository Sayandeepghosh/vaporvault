import type { NextConfig } from "next";

/**
 * Static security headers live here rather than in `proxy.ts` so they are applied by the
 * server for every route, independent of the proxy matcher. The nonce-based CSP is the
 * one exception: it must be generated per request (see `src/proxy.ts`).
 */
const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  /**
   * Critical for this application: without it, the secret id in the path would be sent to
   * any third-party origin the user navigates to. (URL fragments are never sent in a
   * Referer, so the decryption key is unaffected either way.)
   */
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
  { key: "Origin-Agent-Cluster", value: "?1" },
  {
    key: "Permissions-Policy",
    value: [
      "accelerometer=()",
      "autoplay=()",
      "camera=()",
      "display-capture=()",
      "encrypted-media=()",
      "geolocation=()",
      "gyroscope=()",
      "magnetometer=()",
      "microphone=()",
      "midi=()",
      "payment=()",
      "usb=()",
      "xr-spatial-tracking=()",
    ].join(", "),
  },
];

const productionOnlyHeaders = [
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
];

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Required for the slim runtime image in the Dockerfile.
  output: "standalone",
  // Do not advertise the framework version.
  poweredByHeader: false,
  async headers() {
    const headers = [
      ...securityHeaders,
      ...(process.env.NODE_ENV === "production" ? productionOnlyHeaders : []),
    ];
    return [
      { source: "/:path*", headers },
      {
        // Belt and braces: even if the proxy is bypassed, secret pages stay uncached.
        source: "/s/:path*",
        headers: [
          { key: "Cache-Control", value: "no-store, no-cache, must-revalidate, private" },
          { key: "X-Robots-Tag", value: "noindex, nofollow, noarchive, nosnippet" },
        ],
      },
      {
        source: "/api/:path*",
        headers: [{ key: "Cache-Control", value: "no-store, no-cache, must-revalidate, private" }],
      },
    ];
  },
};

export default nextConfig;
