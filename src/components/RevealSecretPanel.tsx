"use client";

import { useCallback, useEffect, useId, useMemo, useRef, useState, useSyncExternalStore } from "react";

import { Button } from "@/components/ui/Button";
import { Callout } from "@/components/ui/Callout";
import { CopyButton } from "@/components/ui/CopyButton";
import { revealSecretResponseSchema } from "@/lib/api-contract";
import { NETWORK_FAILURE_MESSAGE, describeApiFailure } from "@/lib/client/api-errors";
import { MAX_PASSPHRASE_LENGTH } from "@/lib/constants";
import { parseFragment, type LinkFragment, type SecretEnvelope } from "@/lib/crypto/envelope";
import { isCryptoError } from "@/lib/crypto/errors";
import { decryptSecret } from "@/lib/crypto/secret-crypto";

/** Never notifies: the value we care about ("are we in the browser yet") changes once. */
const subscribeNever = () => () => {};
const snapshotClient = () => true;
const snapshotServer = () => false;

type Stage = "idle" | "revealing" | "revealed" | "gone";

type Link =
  | { status: "pending" }
  | { status: "invalid" }
  | { status: "ok"; fragment: LinkFragment };

export interface RevealSecretPanelProps {
  secretId: string;
}

export function RevealSecretPanel({ secretId }: RevealSecretPanelProps) {
  const passphraseFieldId = useId();

  /**
   * `location.hash` only exists in the browser, and the server render must not disagree
   * with the first client render. `useSyncExternalStore` gives us a hydration-safe
   * "mounted" signal without setting state from an effect.
   */
  const mounted = useSyncExternalStore(subscribeNever, snapshotClient, snapshotServer);

  /**
   * Parsed once, when `mounted` flips to true.
   *
   * Note that a successful reveal calls `history.replaceState` to drop the key from the
   * address bar, after which `location.hash` is empty. The render below therefore checks
   * for a decrypted secret *before* it looks at link status, so this value going stale can
   * never flip a revealed secret back to an "invalid link" screen.
   */
  const link = useMemo<Link>(() => {
    if (!mounted) return { status: "pending" };
    try {
      return { status: "ok", fragment: parseFragment(window.location.hash) };
    } catch {
      return { status: "invalid" };
    }
  }, [mounted]);

  const requiresPassphrase = link.status === "ok" && link.fragment.requiresPassphrase;

  const [stage, setStage] = useState<Stage>("idle");
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [plaintext, setPlaintext] = useState<string | null>(null);
  /** Mirrors `envelopeRef` for rendering; refs must not be read during render. */
  const [envelopeHeld, setEnvelopeHeld] = useState(false);

  /**
   * The fetched envelope is cached for the lifetime of this view.
   *
   * Revealing destroys the secret server-side, so a wrong passphrase must be retryable
   * locally. Without this, one typo would vaporise the secret for good.
   */
  const envelopeRef = useRef<SecretEnvelope | null>(null);
  const outputRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (stage === "revealed") outputRef.current?.focus();
  }, [stage]);

  const reveal = useCallback(async () => {
    if (link.status !== "ok") return;

    setError(null);
    setStage("revealing");

    try {
      let envelope = envelopeRef.current;

      if (!envelope) {
        // The destructive step. Only ever issued from here, after an explicit click, which
        // is why unfurlers and prefetchers cannot consume a secret.
        const response = await fetch(`/api/secrets/${encodeURIComponent(secretId)}/reveal`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
          cache: "no-store",
          credentials: "omit",
          redirect: "error",
        });

        if (!response.ok) {
          setError(await describeApiFailure(response));
          setStage(response.status === 404 ? "gone" : "idle");
          return;
        }

        const parsed = revealSecretResponseSchema.safeParse(await response.json());
        if (!parsed.success) {
          setError(NETWORK_FAILURE_MESSAGE);
          setStage("idle");
          return;
        }

        envelope = parsed.data.envelope;
        envelopeRef.current = envelope;
        setEnvelopeHeld(true);
      }

      const decrypted = await decryptSecret({
        envelope,
        fragment: link.fragment,
        passphrase,
      });

      setPlaintext(decrypted);
      setStage("revealed");
      envelopeRef.current = null;
      setEnvelopeHeld(false);
      setPassphrase("");
      // Take the key out of the address bar and session history now that it has been used.
      // Only on success: a reload before this point must still work.
      window.history.replaceState(null, "", window.location.pathname);
    } catch (caught) {
      setError(isCryptoError(caught) ? caught.message : NETWORK_FAILURE_MESSAGE);
      setStage("idle");
    }
  }, [link, passphrase, secretId]);

  // Checked first, deliberately: see the note on `link` above.
  if (plaintext !== null) {
    return (
      <div className="space-y-5">
        <Callout tone="success" role="status" title="Decrypted in your browser">
          This secret has now been destroyed on the server. Reloading will not bring it back.
        </Callout>

        <div className="space-y-2">
          <p className="text-sm font-medium text-slate-200">Secret</p>
          {/*
            Rendered as a text child so React escapes it. There is no
            dangerouslySetInnerHTML anywhere in this codebase; the plaintext is entirely
            attacker-controlled input.
          */}
          <pre
            ref={outputRef}
            tabIndex={-1}
            className="max-h-96 overflow-auto rounded-lg border border-slate-700 bg-slate-950 p-4 font-mono text-sm whitespace-pre-wrap break-all text-emerald-200"
          >
            {plaintext}
          </pre>
          <CopyButton getValue={() => plaintext} label="Copy secret" variant="primary" />
        </div>
      </div>
    );
  }

  if (link.status === "pending") {
    return (
      <p role="status" className="text-sm text-slate-400">
        Checking link…
      </p>
    );
  }

  if (link.status === "invalid") {
    return (
      <Callout tone="danger" role="alert" title="This link is incomplete">
        The decryption key is missing from the URL. It sits after the{" "}
        <code className="font-mono">#</code>, and some chat clients and email scanners strip
        it. Ask the sender for the full link, or for a new one.
      </Callout>
    );
  }

  if (stage === "gone") {
    return (
      <Callout tone="danger" role="alert" title="Secret not found or already destroyed">
        One-time links work exactly once. This one has been opened, has expired, or never
        existed. Ask the sender for a new link.
      </Callout>
    );
  }

  return (
    <div className="space-y-5">
      <Callout tone="warning" title="You can only do this once">
        Revealing destroys the secret immediately. Make sure you can store it somewhere safe
        before you continue.
      </Callout>

      {requiresPassphrase ? (
        <div className="space-y-2">
          <label htmlFor={passphraseFieldId} className="block text-sm font-medium text-slate-200">
            Passphrase
          </label>
          <input
            id={passphraseFieldId}
            type="password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
            maxLength={MAX_PASSPHRASE_LENGTH}
            autoComplete="off"
            spellCheck={false}
            data-1p-ignore="true"
            data-lpignore="true"
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 font-mono text-sm text-slate-100 sm:max-w-md"
          />
          <p className="text-xs text-slate-400">
            The sender protected this secret with a passphrase. It is combined with the key in
            your link and never leaves this tab.
          </p>
        </div>
      ) : null}

      {error ? (
        <Callout tone="danger" role="alert" title="Could not reveal the secret">
          {error}
          {envelopeHeld
            ? " The encrypted data is still held in this tab, so you can correct the passphrase and try again without losing it."
            : ""}
        </Callout>
      ) : null}

      <Button
        variant="danger"
        busy={stage === "revealing"}
        disabled={stage === "revealing" || (requiresPassphrase && passphrase.length === 0)}
        onClick={reveal}
      >
        {stage === "revealing" ? "Decrypting…" : "Reveal and destroy"}
      </Button>
    </div>
  );
}
