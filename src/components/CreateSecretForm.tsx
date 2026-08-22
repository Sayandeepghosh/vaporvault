"use client";

import { useCallback, useId, useMemo, useState, type FormEvent } from "react";

import { SecretLinkPanel } from "@/components/SecretLinkPanel";
import { Button } from "@/components/ui/Button";
import { Callout } from "@/components/ui/Callout";
import { createSecretResponseSchema, type CreateSecretRequest } from "@/lib/api-contract";
import { NETWORK_FAILURE_MESSAGE, describeApiFailure } from "@/lib/client/api-errors";
import {
  DEFAULT_TTL_SECONDS,
  MAX_PASSPHRASE_LENGTH,
  MAX_PLAINTEXT_BYTES,
  MIN_PASSPHRASE_LENGTH,
  TTL_CHOICES,
} from "@/lib/constants";
import { utf8ByteLength } from "@/lib/crypto/encoding";
import { isCryptoError } from "@/lib/crypto/errors";
import { encryptSecret } from "@/lib/crypto/secret-crypto";

interface CreatedLink {
  url: string;
  expiresAt: string;
}

export function CreateSecretForm() {
  const secretFieldId = useId();
  const ttlFieldId = useId();
  const passphraseFieldId = useId();
  const counterId = useId();
  const passphraseHintId = useId();

  const [secret, setSecret] = useState("");
  const [ttlSeconds, setTtlSeconds] = useState<number>(DEFAULT_TTL_SECONDS);
  const [usePassphrase, setUsePassphrase] = useState(false);
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<CreatedLink | null>(null);

  const byteLength = useMemo(() => utf8ByteLength(secret), [secret]);
  const tooLarge = byteLength > MAX_PLAINTEXT_BYTES;
  const passphraseTooShort = usePassphrase && passphrase.length < MIN_PASSPHRASE_LENGTH;
  const canSubmit = byteLength > 0 && !tooLarge && !passphraseTooShort && !busy;

  const reset = useCallback(() => {
    setCreated(null);
    setSecret("");
    setPassphrase("");
    setUsePassphrase(false);
    setError(null);
  }, []);

  const handleSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      // The form must never submit natively: that would put the plaintext on the wire.
      event.preventDefault();
      if (!canSubmit) return;

      setBusy(true);
      setError(null);

      try {
        // Encryption happens here, before anything touches the network.
        const { envelope, fragment } = await encryptSecret({
          plaintext: secret,
          passphrase: usePassphrase ? passphrase : undefined,
        });

        const payload: CreateSecretRequest = { envelope, ttlSeconds };

        const response = await fetch("/api/secrets", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
          cache: "no-store",
          credentials: "omit",
          redirect: "error",
        });

        if (!response.ok) {
          setError(await describeApiFailure(response));
          return;
        }

        const parsed = createSecretResponseSchema.safeParse(await response.json());
        if (!parsed.success) {
          setError(NETWORK_FAILURE_MESSAGE);
          return;
        }

        // The fragment is assembled client-side and never sent anywhere.
        setCreated({
          url: `${window.location.origin}/s/${parsed.data.id}#${fragment}`,
          expiresAt: parsed.data.expiresAt,
        });
        // Drop the plaintext from component state as soon as it is no longer needed.
        setSecret("");
        setPassphrase("");
      } catch (caught) {
        setError(isCryptoError(caught) ? caught.message : NETWORK_FAILURE_MESSAGE);
      } finally {
        setBusy(false);
      }
    },
    [canSubmit, passphrase, secret, ttlSeconds, usePassphrase],
  );

  if (created) {
    return <SecretLinkPanel url={created.url} expiresAt={created.expiresAt} onReset={reset} />;
  }

  return (
    <form onSubmit={handleSubmit} noValidate className="space-y-6">
      <div className="space-y-2">
        <label htmlFor={secretFieldId} className="block text-sm font-medium text-slate-200">
          Secret
        </label>
        <textarea
          id={secretFieldId}
          value={secret}
          onChange={(event) => setSecret(event.target.value)}
          rows={7}
          required
          aria-describedby={counterId}
          aria-invalid={tooLarge || undefined}
          placeholder="Paste a password, API key, or connection string"
          /*
           * No `name`: the value can never be picked up by a native form submission.
           * Autofill, spellcheck and third-party editor extensions are all disabled —
           * Grammarly and similar tools upload textarea contents to their own servers,
           * which would defeat the entire point of encrypting in the browser.
           */
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          spellCheck={false}
          data-gramm="false"
          data-gramm_editor="false"
          data-enable-grammarly="false"
          data-1p-ignore="true"
          data-lpignore="true"
          className="w-full resize-y rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 font-mono text-sm text-slate-100 placeholder:text-slate-600"
        />
        <p
          id={counterId}
          className={`text-xs ${tooLarge ? "text-rose-300" : "text-slate-400"}`}
        >
          {byteLength.toLocaleString()} / {MAX_PLAINTEXT_BYTES.toLocaleString()} bytes
          {tooLarge ? " — too large to encrypt" : ""}
        </p>
      </div>

      <div className="space-y-2">
        <label htmlFor={ttlFieldId} className="block text-sm font-medium text-slate-200">
          Self-destruct after
        </label>
        <select
          id={ttlFieldId}
          value={ttlSeconds}
          onChange={(event) => setTtlSeconds(Number(event.target.value))}
          className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-100 sm:w-64"
        >
          {TTL_CHOICES.map((choice) => (
            <option key={choice.seconds} value={choice.seconds}>
              {choice.label}
            </option>
          ))}
        </select>
        <p className="text-xs text-slate-400">
          Whichever comes first: the first view, or this deadline.
        </p>
      </div>

      <fieldset className="space-y-3 rounded-lg border border-slate-800 p-4">
        <legend className="px-1 text-sm font-medium text-slate-200">
          Extra passphrase (optional)
        </legend>
        <label className="flex items-start gap-3 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={usePassphrase}
            onChange={(event) => {
              setUsePassphrase(event.target.checked);
              if (!event.target.checked) setPassphrase("");
            }}
            className="mt-0.5 size-4 rounded border-slate-600 bg-slate-950 accent-emerald-500"
          />
          <span>
            Require a passphrase in addition to the link. Useful when the link travels over
            a channel you do not fully trust, such as chat or email.
          </span>
        </label>

        {usePassphrase ? (
          <div className="space-y-2">
            <label
              htmlFor={passphraseFieldId}
              className="block text-sm font-medium text-slate-200"
            >
              Passphrase
            </label>
            <input
              id={passphraseFieldId}
              type="password"
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              maxLength={MAX_PASSPHRASE_LENGTH}
              aria-describedby={passphraseHintId}
              aria-invalid={passphraseTooShort || undefined}
              autoComplete="new-password"
              spellCheck={false}
              data-1p-ignore="true"
              data-lpignore="true"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 font-mono text-sm text-slate-100"
            />
            <p
              id={passphraseHintId}
              className={`text-xs ${passphraseTooShort ? "text-rose-300" : "text-slate-400"}`}
            >
              At least {MIN_PASSPHRASE_LENGTH} characters. Share it separately from the link —
              it is mixed into the key and never sent to the server.
            </p>
          </div>
        ) : null}
      </fieldset>

      {error ? (
        <Callout tone="danger" role="alert" title="Could not create the link">
          {error}
        </Callout>
      ) : null}

      <Button type="submit" busy={busy} disabled={!canSubmit} className="w-full sm:w-auto">
        {busy ? "Encrypting…" : "Encrypt and create link"}
      </Button>

      <p className="text-xs text-slate-500">
        Encryption runs in this tab. The server receives ciphertext, a nonce and a salt —
        never your secret, and never the key.
      </p>
    </form>
  );
}
