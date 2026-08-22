"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { Button } from "@/components/ui/Button";

type CopyState = "idle" | "copied" | "failed";

export interface CopyButtonProps {
  /** Resolved lazily so the caller never has to keep a stale copy of the value around. */
  getValue: () => string;
  label?: string;
  variant?: "primary" | "secondary";
  className?: string;
}

/**
 * Clipboard copy with an accessible result announcement.
 *
 * `navigator.clipboard` is only available in secure contexts, so failure is a real path
 * and is reported instead of silently doing nothing.
 */
export function CopyButton({
  getValue,
  label = "Copy",
  variant = "secondary",
  className = "",
}: CopyButtonProps) {
  const [state, setState] = useState<CopyState>("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );

  const copy = useCallback(async () => {
    if (timer.current) clearTimeout(timer.current);
    try {
      if (!navigator.clipboard) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(getValue());
      setState("copied");
    } catch {
      setState("failed");
    }
    timer.current = setTimeout(() => setState("idle"), 2500);
  }, [getValue]);

  return (
    <span className={`inline-flex items-center gap-2 ${className}`}>
      <Button variant={variant} onClick={copy}>
        {state === "copied" ? "Copied" : label}
      </Button>
      {/* Announced without moving focus. */}
      <span aria-live="polite" className="sr-only">
        {state === "copied" ? "Copied to clipboard" : ""}
        {state === "failed" ? "Copy failed. Select the text and copy manually." : ""}
      </span>
      {state === "failed" ? (
        <span className="text-xs text-rose-300">Copy failed — select and copy manually.</span>
      ) : null}
    </span>
  );
}
