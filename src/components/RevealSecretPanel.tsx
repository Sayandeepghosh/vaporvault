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

type Stage = "idle" | "revealing" | "revealed" | "gone" | "lost";

type Link =
  | { status: "pending" }
  | { status: "invalid" }
  /** The fragment was already used and stripped in this tab. */
  | { status: "consumed" }
  | { status: "ok"; fragment: LinkFragment };

/** Marker written into the history entry once a secret has been read in this tab. */
const READ_MARKER = "vaporvaultRead";

/** Statuses the guard pipeline returns before the store is ever consulted. */
const RETRY_IS_SAFE = new Set([403, 413, 415, 429]);

function historyMarksRead(): boolean {
  const state: unknown = window.history.state;
  return typeof state === "object" && state !== null && READ_MARKER in state;
}

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
      /**
       * No usable fragment. Distinguish "you already read this here" from "the key never
       * arrived": after a successful reveal we strip the fragment ourselves, so on reload
       * this branch is reached for a secret the user consumed. Telling them the key was
       * stripped in transit would be actively misleading — it blames the transport and
       * invites them to ask for a re-share, which puts the same plaintext on the wire twice.
       */
      return historyMarksRead() ? { status: "consumed" } : { status: "invalid" };
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
  /**
   * Latched immediately before the destructive POST is dispatched.
   *
   * The server deletes atomically, so once the request is on the wire the secret is gone
   * whether or not we ever see the response. If the response is lost we must NOT re-enable
   * a "try again" button: the retry cannot succeed, and offering it makes the user believe
   * a network blip is at fault and ask the sender to share the secret a second time.
   */
  const postIssuedRef = useRef(false);
  /** Mutual exclusion that does not depend on React's commit timing or the DOM. */
  const inFlightRef = useRef(false);

  useEffect(() => {
    if (stage === "revealed") outputRef.current?.focus();
  }, [stage]);

  const reveal = useCallback(async () => {
    if (link.status !== "ok") return;
    // A ref, not the disabled attribute: three programmatic clicks in one task would
    // otherwise fire three destructive POSTs before React committed the disabled state.
    if (inFlightRef.current) return;
    inFlightRef.current = true;

    setError(null);
    setStage("revealing");

    try {
      let envelope = envelopeRef.current;

      if (!envelope) {
        postIssuedRef.current = true;
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
          // These statuses are produced by the guard pipeline before the store is touched,
          // so the secret provably survives and a retry is legitimate. A 503 is genuinely
          // ambiguous — it can be a fail-closed limiter, or a store command that timed out
          // after it had already deleted — so the latch stays set and a later failure is
          // reported as unrecoverable rather than as a network blip.
          if (RETRY_IS_SAFE.has(response.status)) postIssuedRef.current = false;
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
      // Only on success: a reload before this point must still work. The marker lets a
      // later reload explain what happened instead of claiming the link was incomplete.
      window.history.replaceState({ [READ_MARKER]: true }, "", window.location.pathname);
    } catch (caught) {
      /**
       * If the POST went out but we never got a usable envelope, the secret is already
       * destroyed and no retry can recover it. Say so, terminally.
       */
      if (postIssuedRef.current && envelopeRef.current === null) {
        setStage("lost");
        return;
      }
      setError(isCryptoError(caught) ? caught.message : NETWORK_FAILURE_MESSAGE);
      setStage("idle");
    } finally {
      inFlightRef.current = false;
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

  if (link.status === "consumed") {
    return (
      <Callout tone="warning" role="alert" title="You already read this secret">
        It was decrypted in this tab and destroyed on the server at that moment. Reloading
        cannot bring it back, and neither can we. If you still need the value, ask the sender
        to share a new one.
      </Callout>
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

  if (stage === "lost") {
    return (
      <Callout tone="danger" role="alert" title="This secret could not be recovered">
        The request to read it reached the server, which destroys a secret the moment it is
        read — but the reply never made it back here, so it could not be decrypted. Retrying
        will not help: the ciphertext no longer exists. Ask the sender for a new link.
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
      {/* role="alert" so the destructive consequence is announced, not just displayed. */}
      <Callout tone="warning" role="alert" title="You can only do this once">
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
