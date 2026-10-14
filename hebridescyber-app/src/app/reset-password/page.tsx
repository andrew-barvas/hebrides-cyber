"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { getSession, updatePassword } from "@/lib/auth";

// Lands here after the reset-password email link's ?code= is exchanged for
// a session server-side (src/app/auth/callback/route.ts, via the `next`
// param requestPasswordReset() sets). A session must already exist — this
// page never accepts an email/token itself, Supabase's own link does that.
export default function ResetPasswordPage() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [hasSession, setHasSession] = useState(false);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    getSession().then((session) => {
      setHasSession(Boolean(session));
      setReady(true);
    });
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirmPassword) {
      setError("Passwords don't match.");
      return;
    }
    setSubmitting(true);
    setError(null);
    const { error: updateError } = await updatePassword(password);
    setSubmitting(false);
    if (updateError) {
      setError(updateError.message);
    } else {
      setDone(true);
      setTimeout(() => router.replace("/dashboard"), 2000);
    }
  }

  return (
    <div className="bg-cyberbg min-h-screen flex items-center justify-center px-6">
      <div className="w-full max-w-sm">
        <p className="font-mono text-xs text-neon mb-2" aria-hidden="true">$ ./reset-password</p>
        <h1 className="mb-2 text-2xl font-bold text-cybertext">Set a new password</h1>

        {!ready ? (
          <p className="text-sm text-cybertext/40">Loading…</p>
        ) : !hasSession ? (
          <div className="space-y-4">
            <p className="text-sm text-cybertext/60">
              This link has expired or is invalid. Request a new one below.
            </p>
            <Link
              href="/forgot-password"
              className="block w-full rounded-md bg-neon px-4 py-2.5 text-center text-sm font-semibold text-cyberbg hover:opacity-90 shadow-glowsm transition-opacity"
            >
              Request a new link
            </Link>
          </div>
        ) : done ? (
          <div className="rounded-lg border border-neon/20 bg-neon/10 p-4 text-sm text-neon">
            Password updated. Taking you to your dashboard…
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <input
              type="password"
              required
              minLength={8}
              placeholder="New password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
            />
            <input
              type="password"
              required
              minLength={8}
              placeholder="Confirm new password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
            />
            {error && (
              <p role="alert" className="text-sm text-red-400">{error}</p>
            )}
            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-md bg-neon px-4 py-2.5 text-sm font-semibold text-cyberbg hover:opacity-90 disabled:opacity-50 shadow-glowsm transition-opacity"
            >
              {submitting ? "Saving…" : "Set new password"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
