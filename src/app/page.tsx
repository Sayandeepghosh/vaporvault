import { CreateSecretForm } from "@/components/CreateSecretForm";
import { MAX_PLAINTEXT_BYTES } from "@/lib/constants";

export default function HomePage() {
  return (
    <div className="space-y-8">
      <section className="space-y-3">
        <h1 className="text-2xl font-semibold tracking-tight text-slate-50 sm:text-3xl">
          Share a secret that deletes itself
        </h1>
        <p className="max-w-2xl text-sm leading-relaxed text-slate-400">
          Paste up to {(MAX_PLAINTEXT_BYTES / 1024).toFixed(0)} KB of text. It is encrypted in
          this tab, stored as ciphertext, and destroyed the moment someone reads it — or when
          the timer runs out, whichever happens first.
        </p>
      </section>

      <CreateSecretForm />
    </div>
  );
}
