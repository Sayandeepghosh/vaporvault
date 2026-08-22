import type { ReactNode } from "react";

type Tone = "info" | "warning" | "danger" | "success";

const TONES: Record<Tone, string> = {
  info: "border-slate-700 bg-slate-900/70 text-slate-300",
  warning: "border-amber-500/40 bg-amber-500/10 text-amber-200",
  danger: "border-rose-500/40 bg-rose-500/10 text-rose-200",
  success: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
};

export interface CalloutProps {
  tone?: Tone;
  title?: string;
  children: ReactNode;
  /**
   * `alert` interrupts a screen reader (use for errors); `status` announces politely.
   * Omit for purely decorative/explanatory copy.
   */
  role?: "alert" | "status";
  className?: string;
}

export function Callout({ tone = "info", title, children, role, className = "" }: CalloutProps) {
  return (
    <div
      role={role}
      className={`rounded-lg border px-4 py-3 text-sm ${TONES[tone]} ${className}`}
    >
      {title ? <p className="mb-1 font-semibold">{title}</p> : null}
      <div className="[&_a]:underline">{children}</div>
    </div>
  );
}
