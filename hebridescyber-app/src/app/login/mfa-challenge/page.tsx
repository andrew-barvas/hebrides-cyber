"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { listMfaFactors, challengeMfaFactor, verifyMfaFactor, getMfaAssuranceLevel } from "@/lib/auth";

// Shown after magic-link/OAuth sign-in when the account has an MFA factor
// enrolled but the current session hasn't satisfied it yet (aal1, not
// aal2) — see getMfaAssuranceLevel() in src/lib/auth.ts and the check in
// src/app/dashboard/page.tsx that redirects here.
export default function MfaChallengePage() {
  const router = useRouter();
  const [factorId, setFactorId] = useState<string | null>(null);
  const [challengeId, setChallengeId] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const { nextLevel, currentLevel } = await getMfaAssuranceLevel();
      if (!nextLevel || currentLevel === nextLevel) {
        // Nothing to challenge — send them straight through.
        router.replace("/dashboard");
        return;
      }

      const factors = await listMfaFactors();
      const factor = factors.totp?.[0];
      if (!factor) {
        router.replace("/dashboard");
        return;
      }
      setFactorId(factor.id);

      const { data, error: challengeError } = await challengeMfaFactor(factor.id);
      if (challengeError || !data) {
        setError(challengeError?.message ?? "Could not start challenge");
      } else {
        setChallengeId(data.id);
      }
      setLoading(false);
    })();
  }, [router]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!factorId || !challengeId) return;
    setError(null);
    const { error: verifyError } = await verifyMfaFactor(factorId, challengeId, code);
    if (verifyError) {
      setError(verifyError.message);
      return;
    }
    router.replace("/dashboard");
  }

  if (loading) return <div className="px-6 py-24 text-center text-sm text-slatedark/60">Checking…</div>;

  return (
    <div className="mx-auto max-w-sm px-6 py-24">
      <h1 className="mb-2 text-2xl font-bold text-atlantic">Enter your 2FA code</h1>
      <p className="mb-8 text-sm text-slatedark/80">Open your authenticator app for the current code.</p>
      <form onSubmit={submit} className="space-y-4">
        <input
          type="text"
          inputMode="numeric"
          autoFocus
          required
          placeholder="6-digit code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
        />
        {error && <p className="text-sm text-red-600">{error}</p>}
        <button type="submit" className="w-full rounded-md bg-atlantic px-4 py-2 text-sm font-semibold text-white hover:opacity-90">
          Verify
        </button>
      </form>
    </div>
  );
}
