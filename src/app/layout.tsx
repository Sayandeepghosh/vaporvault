import type { Metadata, Viewport } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "VaporVault — one-time secret sharing",
    template: "%s · VaporVault",
  },
  description:
    "Share passwords and API keys through a link that self-destructs after one view. Encrypted in your browser; the server never sees the plaintext or the key.",
  applicationName: "VaporVault",
  // Reduce the chance of a browser turning parts of a secret into a tel:/mailto: link.
  formatDetection: { telephone: false, email: false, address: false },
};

export const viewport: Viewport = {
  colorScheme: "dark",
  themeColor: "#020617",
};

/**
 * Every page renders per request, for two reasons.
 *
 * 1. Correctness: the strict CSP in `src/proxy.ts` uses a per-response nonce, and Next can
 *    only stamp that nonce onto its script tags while rendering. A prerendered page would
 *    ship script tags with no nonce, and `'strict-dynamic'` would then block them — the app
 *    would silently fail to hydrate in production.
 * 2. Privacy: no HTML for this app should ever sit in a shared cache.
 *
 * Declared on the root layout so it covers every segment, including the 404 page.
 */
export const dynamic = "force-dynamic";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-dvh">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-emerald-500 focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-slate-950"
        >
          Skip to content
        </a>

        <div className="mx-auto flex min-h-dvh max-w-3xl flex-col px-4 py-10 sm:px-6 sm:py-14">
          <header className="mb-10">
            <p className="flex items-baseline gap-2 text-lg font-semibold tracking-tight">
              <span aria-hidden="true" className="text-emerald-400">
                ▚
              </span>
              VaporVault
            </p>
            <p className="mt-1 text-sm text-slate-400">
              Zero-knowledge, one-time secret sharing.
            </p>
          </header>

          <main id="main" className="flex-1">
            {children}
          </main>

          <footer className="mt-14 border-t border-slate-800 pt-6 text-xs leading-relaxed text-slate-500">
            <p>
              Secrets are encrypted with AES-256-GCM in your browser. The decryption key
              travels in the URL fragment, which browsers never send to a server, so
              VaporVault stores ciphertext it cannot read. Reading a secret deletes it in the
              same atomic operation.
            </p>
          </footer>
        </div>
      </body>
    </html>
  );
}
