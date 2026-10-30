"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { getSession, signInWithMagicLink } from "@/lib/auth";

// Explicit "create an account" entry point. Mechanically this is the same
// magic-link call as /login (Supabase's signInWithOtp creates a new
// auth.users row on first use by default) — what this page adds is: a
// discoverable URL for a brand-new visitor, copy that says "create" rather
// than "sign in", and an optional company-name field that migration 059's
// handle_new_user() trigger reads into the new public.users profile row.
export default function SignupPage() {
  return (
    <Suspense>
      <SignupForm />
    </Suspense>
  );
}

function SignupForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectTo = searchParams?.get("redirect") ?? "/dashboard";
  const [email, setEmail] = useState("");
  const [companyName, setCompanyName] = useState("");
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    getSession().then((session) => {
      if (session) router.replace(redirectTo);
    });
  }, [router, redirectTo]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    const { error: signUpError } = await signInWithMagicLink(
      email,
      companyName.trim() ? { company_name: companyName.trim() } : undefined
    );
    setSubmitting(false);
    if (signUpError) {
      setError(signUpError.message);
    } else {
      setSent(true);
    }
  }

  return (
    <div className="bg-cyberbg min-h-screen flex items-center justify-center px-6">
      <div className="w-full max-w-sm">
        <p className="font-mono text-xs text-neon mb-2" aria-hidden="true">$ ./signup</p>
        <h1 className="mb-2 text-2xl font-bold text-cybertext">Create your account</h1>
        <p className="mb-8 text-sm text-cybertext/60">
          No password to set — we&apos;ll email you a one-time link to get started.
        </p>

        {sent ? (
          <div className="rounded-lg border border-neon/20 bg-neon/10 p-4 text-sm text-neon">
            Check <strong>{email}</strong> for a link to finish creating your account. You can close this tab.
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
            <label htmlFor="company" className="sr-only">Company name</label>
            <input
              id="company"
              autoComplete="organization"
              type="text"
              placeholder="Company name (optional)"
              value={companyName}
              onChange={(e) => setCompanyName(e.target.value)}
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
              {submitting ? "Sending…" : "Create account"}
            </button>
          </form>
        )}

        <p className="mt-10 text-center text-xs text-cybermuted">
          Already have an account?{" "}
          <Link href="/login" className="text-neon hover:underline">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
