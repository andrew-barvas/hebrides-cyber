"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabaseClient";

// OAuth (Google) redirect target — supabase-js v2 uses the PKCE flow for
// OAuth providers, which requires explicitly exchanging the ?code= in the
// URL for a session (unlike magic links, which the client auto-detects
// from the URL hash on any page). Set as the redirectTo for
// signInWithGoogle() in src/lib/auth.ts.
export default function AuthCallbackPage() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const { error: exchangeError } = await supabase.auth.exchangeCodeForSession(window.location.href);
      if (exchangeError) {
        setError(exchangeError.message);
        return;
      }
      router.replace("/dashboard");
    })();
  }, [router]);

  if (error) {
    return (
      <div className="mx-auto max-w-sm px-6 py-24 text-center">
        <p className="text-sm text-red-600">Sign-in failed: {error}</p>
      </div>
    );
  }

  return <div className="px-6 py-24 text-center text-sm text-slatedark/60">Signing you in…</div>;
}
