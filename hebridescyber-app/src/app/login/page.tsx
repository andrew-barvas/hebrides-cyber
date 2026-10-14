"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { getSession, signInWithMagicLink, signInWithPassword } from "@/lib/auth";

// Magic link is the primary sign-in flow. Password sign-in is available so
// the seeded demo accounts (admin, basic/pro/agency/no-plan customers from
// `npm run seed:users`) are usable without inbox access.
export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectTo = searchParams?.get("redirect") ?? "/dashboard";
  const callbackError = searchParams?.get("error");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [usePassword, setUsePassword] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(
    callbackError === "auth_callback_failed" ? "Sign-in failed — please try again." : null
  );
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

    if (usePassword) {
      const { error: signInError } = await signInWithPassword(email, password);
      setSubmitting(false);
      if (signInError) {
        setError(signInError.message);
      } else {
        router.replace(redirectTo);
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
    <div className="bg-cyberbg min-h-screen flex items-center justify-center px-6">
      <div className="w-full max-w-sm">
        <p className="font-mono text-xs text-neon mb-2" aria-hidden="true">$ ./login</p>
        <h1 className="mb-2 text-2xl font-bold text-cybertext">Sign in</h1>
        <p className="mb-8 text-sm text-cybertext/60">
          {usePassword
            ? "Sign in with your password."
            : "No password needed — we'll email you a one-time link."}
        </p>

        {sent ? (
          <div className="rounded-lg border border-neon/20 bg-neon/10 p-4 text-sm text-neon">
            Check <strong>{email}</strong> for a sign-in link. You can close this tab.
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <input
              type="email"
              required
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
            />
            {usePassword && (
              <input
                type="password"
                required
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
              />
            )}
            {error && (
              <p role="alert" className="text-sm text-red-400">{error}</p>
            )}
            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-md bg-neon px-4 py-2.5 text-sm font-semibold text-cyberbg hover:opacity-90 disabled:opacity-50 shadow-glowsm transition-opacity"
            >
              {submitting ? "Signing in…" : usePassword ? "Sign in" : "Send magic link"}
            </button>
            <button
              type="button"
              onClick={() => setUsePassword((v) => !v)}
              className="w-full text-center text-xs text-cybertext/40 hover:text-cybertext/70 underline"
            >
              {usePassword ? "Use a magic link instead" : "Have a password? Sign in with it"}
            </button>
            {usePassword && (
              <Link
                href="/forgot-password"
                className="block w-full text-center text-xs text-cybertext/40 hover:text-cybertext/70 underline"
              >
                Forgot your password?
              </Link>
            )}
          </form>
        )}

        <p className="mt-6 text-center text-xs text-cybertext/40">
          New here?{" "}
          <Link href="/signup" className="text-neon hover:underline">Create an account</Link>
        </p>

        <p className="mt-10 text-center text-xs text-cybertext/30">
          Demo accounts: run <code className="text-neon">npm run seed:users</code> then sign in with the
          printed credentials.
        </p>
      </div>
    </div>
  );
}
