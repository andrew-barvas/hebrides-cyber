"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getSession, signInWithGoogle, signInWithMagicLink, signInWithPassword } from "@/lib/auth";

// Passwordless magic link is the primary flow (see src/lib/auth.ts for
// why), with Google OAuth and password sign-in as alternatives. Password
// sign-in exists mainly so the seeded demo accounts
// (src/scripts/seed-users.ts — admin + basic/pro/agency/no-plan
// customers) are actually usable without inbox access; real customers
// aren't required to set one.
export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [usePassword, setUsePassword] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    getSession().then((session) => {
      if (session) router.replace("/dashboard");
    });
  }, [router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    if (usePassword) {
      const { error: signInError } = await signInWithPassword(email, password);
      setSubmitting(false);
      if (signInError) {
        setError(signInError.message);
      } else {
        router.replace("/dashboard"); // dashboard itself handles the MFA-challenge redirect if needed
      }
      return;
    }

    const { error: signInError } = await signInWithMagicLink(email);
    setSubmitting(false);
    if (signInError) {
      setError(signInError.message);
    } else {
      setSent(true);
    }
  }

  return (
    <div className="mx-auto max-w-sm px-6 py-24">
      <h1 className="mb-2 text-2xl font-bold text-atlantic">Sign in</h1>
      <p className="mb-8 text-sm text-slatedark/80">
        {usePassword ? "Sign in with a password." : "No password needed — we'll email you a one-time link."}
      </p>

      {sent ? (
        <p className="rounded-md bg-seafoam/20 p-4 text-sm text-slatedark">
          Check <strong>{email}</strong> for a sign-in link. You can close this tab.
        </p>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="email"
            required
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
          />
          {usePassword && (
            <input
              type="password"
              required
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
            />
          )}
          {error && <p className="text-sm text-red-600">{error}</p>}
          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-md bg-atlantic px-4 py-2 text-sm font-semibold text-white hover:opacity-90 disabled:opacity-50"
          >
            {submitting ? "Signing in…" : usePassword ? "Sign in" : "Send magic link"}
          </button>
          <button
            type="button"
            onClick={() => setUsePassword((v) => !v)}
            className="w-full text-center text-xs text-slatedark/60 underline"
          >
            {usePassword ? "Use a magic link instead" : "Have a password? Sign in with it instead"}
          </button>
        </form>
      )}

      <div className="my-6 flex items-center gap-3 text-xs text-slatedark/50">
        <div className="h-px flex-1 bg-slate-200" />
        or
        <div className="h-px flex-1 bg-slate-200" />
      </div>

      <button
        onClick={() => signInWithGoogle()}
        className="w-full rounded-md border border-slate-300 px-4 py-2 text-sm font-semibold hover:bg-slate-50"
      >
        Continue with Google
      </button>
      {/* TODO: enable the Google provider in the Supabase Dashboard before this works. */}

      <p className="mt-8 text-center text-xs text-slatedark/40">
        Demo accounts: run <code>npm run seed:users</code> then sign in with password using the
        credentials it prints (admin, and basic/pro/agency/no-plan customers).
      </p>
    </div>
  );
}
