"use client";

// "Continue with Google" on /login and /signup. Shown only when
// NEXT_PUBLIC_GOOGLE_SIGNIN is "true" (inlined at build time by deploy.yml),
// because until the Google provider is set up in Supabase (OWNER-TODO OT-63)
// the redirect would land on an error page. Signing up with Google needs no
// email link, so it also sidesteps the email rate limit on magic links.
import { useState } from "react";
import { signInWithGoogle } from "@/lib/auth";

export function googleSignInEnabled(env: string | undefined = process.env.NEXT_PUBLIC_GOOGLE_SIGNIN): boolean {
  return env === "true";
}

export default function GoogleSignInButton({ next, enabled = googleSignInEnabled() }: { next?: string; enabled?: boolean }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!enabled) return null;

  async function go() {
    setBusy(true);
    setError(null);
    const { error: oauthError } = await signInWithGoogle(next);
    // On success the browser is already leaving for Google.
    if (oauthError) {
      setError("Couldn't start Google sign-in. Try the email link instead.");
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <button
        type="button"
        onClick={go}
        disabled={busy}
        className="flex w-full items-center justify-center gap-2 rounded-md border border-cyberborder bg-cyberbg px-4 py-2.5 text-sm font-semibold text-cybertext hover:border-neon disabled:opacity-50 transition-colors"
      >
        <svg aria-hidden="true" width="16" height="16" viewBox="0 0 48 48">
          <path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z" />
          <path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z" />
          <path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z" />
          <path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z" />
        </svg>
        {busy ? "Opening Google…" : "Continue with Google"}
      </button>
      {error && (
        <p role="alert" className="text-sm text-red-400">
          {error}
        </p>
      )}
      <div className="flex items-center gap-3 text-xs text-cybermuted">
        <span className="h-px flex-1 bg-cyberborder" />
        or with email
        <span className="h-px flex-1 bg-cyberborder" />
      </div>
    </div>
  );
}
