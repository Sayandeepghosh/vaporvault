import type { Metadata } from "next";

import { RevealSecretPanel } from "@/components/RevealSecretPanel";
import { Callout } from "@/components/ui/Callout";
import { isSecretId } from "@/lib/secret-id";

/**
 * The reveal page.
 *
 * Rendering this page is deliberately side-effect free: it performs no lookup and reveals
 * nothing about whether the id exists. Destruction happens only when the visitor posts to
 * the reveal endpoint. That separation is what keeps link unfurlers, mail scanners and
 * browser prefetch from consuming secrets before the recipient arrives.
 */

export const metadata: Metadata = {
  title: "Reveal secret",
  robots: { index: false, follow: false, nocache: true, noarchive: true, nosnippet: true },
};

export default async function RevealPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;

  return (
    <div className="space-y-8">
      <section className="space-y-3">
        <h1 className="text-2xl font-semibold tracking-tight text-slate-50 sm:text-3xl">
          Someone shared a secret with you
        </h1>
        <p className="max-w-2xl text-sm leading-relaxed text-slate-400">
          It is decrypted here in your browser and erased from the server as you read it.
        </p>
      </section>

      {isSecretId(id) ? (
        <RevealSecretPanel secretId={id} />
      ) : (
        // Same copy as a genuinely missing secret: a malformed id must not be
        // distinguishable from one that has already been read.
        <Callout tone="danger" role="alert" title="Secret not found or already destroyed">
          One-time links work exactly once. This one has been opened, has expired, or never
          existed. Ask the sender for a new link.
        </Callout>
      )}
    </div>
  );
}
