import Link from "next/link";

import { Callout } from "@/components/ui/Callout";

export default function NotFound() {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight text-slate-50">Page not found</h1>
      <Callout tone="info">
        There is nothing at this address.{" "}
        <Link href="/" className="text-emerald-300 underline">
          Share a secret instead
        </Link>
        .
      </Callout>
    </div>
  );
}
