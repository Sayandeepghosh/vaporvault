"use client";

import { useCallback, useId, useRef } from "react";

import { Button } from "@/components/ui/Button";
import { Callout } from "@/components/ui/Callout";
import { CopyButton } from "@/components/ui/CopyButton";

export interface SecretLinkPanelProps {
  url: string;
  expiresAt: string;
  onReset: () => void;
}

function formatExpiry(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "shortly";
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function SecretLinkPanel({ url, expiresAt, onReset }: SecretLinkPanelProps) {
  const input = useRef<HTMLInputElement>(null);
  // useId rather than a hardcoded id: a fixed global selector is both a duplicate-id
  // hazard and a stable handle for any extension or bookmarklet looking for the key.
  const linkFieldId = useId();
  const getUrl = useCallback(() => url, [url]);

  return (
    <div className="space-y-5">
      <Callout tone="success" role="status" title="Link ready">
        The secret is encrypted. Anyone with this link can read it exactly once.
      </Callout>

      <div className="space-y-2">
        <label htmlFor={linkFieldId} className="block text-sm font-medium text-slate-200">
          One-time link
        </label>
        <div className="flex flex-col gap-2 sm:flex-row">
          <input
            ref={input}
            id={linkFieldId}
            type="text"
            readOnly
            value={url}
            /*
             * This field holds the decryption key in its fragment, so it gets exactly the
             * same extension and password-manager opt-outs as the plaintext textarea.
             * Shielding only the textarea would protect half of the sensitive surface.
             */
            autoComplete="off"
            autoCorrect="off"
            spellCheck={false}
            data-gramm="false"
            data-gramm_editor="false"
            data-enable-grammarly="false"
            data-1p-ignore="true"
            data-lpignore="true"
            // Select the whole link on focus so keyboard users can copy in two keystrokes.
            onFocus={(event) => event.currentTarget.select()}
            onClick={() => input.current?.select()}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 font-mono text-xs text-emerald-200 sm:text-sm"
          />
          <CopyButton getValue={getUrl} label="Copy link" variant="primary" />
        </div>
        <p className="text-xs text-slate-400">
          Expires {formatExpiry(expiresAt)} if nobody opens it first.
        </p>
      </div>

      <Callout tone="warning" role="alert" title="This link is shown once">
        <ul className="list-disc space-y-1 pl-5">
          <li>
            The decryption key lives in the <code className="font-mono">#fragment</code> of the
            URL. Copy the whole thing, including everything after the <code>#</code>.
          </li>
          <li>
            We cannot recover or resend it. Nothing on the server can decrypt this secret.
          </li>
          <li>Opening the link yourself will destroy the secret.</li>
        </ul>
      </Callout>

      <Button variant="secondary" onClick={onReset}>
        Share another secret
      </Button>
    </div>
  );
}
