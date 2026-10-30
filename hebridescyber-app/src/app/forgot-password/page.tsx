"use client";

import { useState } from "react";
import Link from "next/link";
import { requestPasswordReset } from "@/lib/auth";

// Recovery path for the password sign-in option (src/lib/auth.ts's
// signInWithPassword) — the default magic-link flow has no password to
// forget, so this only matters for seeded demo accounts and any real
// customer who has set a password. Deliberately never reveals whether the
// email exists: the same "check your email" message shows whether or not
// resetPasswordForEmail actually found an account, since Supabase itself
// doesn't error on an unknown address either.
export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    const { error: resetError } = await requestPasswordReset(email);
    setSubmitting(false);
    if (resetError) {
      setError(resetError.message);
    } else {
      setSent(true);
    }
  }

  return (
    <div className="bg-cyberbg min-h-screen flex items-center justify-center px-6">
      <div className="w-full max-w-sm">
        <p className="font-mono text-xs text-neon mb-2" aria-hidden="true">$ ./forgot-password</p>
        <h1 className="mb-2 text-2xl font-bold text-cybertext">Reset your password</h1>
        <p className="mb-8 text-sm text-cybertext/60">
          Enter your account email and we&apos;ll send a link to set a new password.
        </p>

        {sent ? (
          <div className="rounded-lg border border-neon/20 bg-neon/10 p-4 text-sm text-neon">
            If an account exists for <strong>{email}</strong>, a reset link is on its way. You can close this tab.
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <label htmlFor="email" className="sr-only">Email address</label>
            <input
              id="email"
              autoComplete="email"
              type="email"
              required
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-hidden focus-visible:ring-2 focus-visible:ring-neon/40 transition-colors"
            />
            {error && (
              <p role="alert" className="text-sm text-red-400">{error}</p>
            )}
            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-md bg-neon px-4 py-2.5 text-sm font-semibold text-cyberbg hover:opacity-90 disabled:opacity-50 shadow-glowsm transition-opacity"
            >
              {submitting ? "Sending…" : "Send reset link"}
            </button>
          </form>
        )}

        <p className="mt-10 text-center text-xs text-cybermuted">
          <Link href="/login" className="text-neon hover:underline">Back to sign in</Link>
        </p>
      </div>
    </div>
  );
}
