"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  getSession,
  listMfaFactors,
  enrollMfaTotp,
  challengeMfaFactor,
  verifyMfaFactor,
  unenrollMfaFactor,
} from "@/lib/auth";

type Factor = { id: string; friendly_name?: string; status: string };

// TOTP enrollment via Supabase Auth's built-in MFA (auth.mfa.*) — no
// third-party MFA service needed. Once a factor is verified here, future
// sign-ins are challenged for it at /login/mfa-challenge before the
// session reaches "aal2" (see src/lib/auth.ts and the dashboard's auth
// check for how that's enforced).
export default function SecuritySettingsPage() {
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [factors, setFactors] = useState<Factor[]>([]);
  const [enrolling, setEnrolling] = useState(false);
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [pendingFactorId, setPendingFactorId] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  async function refresh() {
    const data = await listMfaFactors();
    setFactors((data.totp ?? []) as Factor[]);
  }

  useEffect(() => {
    (async () => {
      const session = await getSession();
      setAuthed(Boolean(session));
      if (session) await refresh();
    })();
  }, []);

  async function startEnroll() {
    setError(null);
    setEnrolling(true);
    const { data, error: enrollError } = await enrollMfaTotp();
    if (enrollError || !data) {
      setError(enrollError?.message ?? "Could not start enrollment");
      setEnrolling(false);
      return;
    }
    setQrCode(data.totp.qr_code);
    setSecret(data.totp.secret);
    setPendingFactorId(data.id);
  }

  async function confirmEnroll(e: React.FormEvent) {
    e.preventDefault();
    if (!pendingFactorId) return;
    setError(null);

    const { data: challenge, error: challengeError } = await challengeMfaFactor(pendingFactorId);
    if (challengeError || !challenge) {
      setError(challengeError?.message ?? "Could not create challenge");
      return;
    }

    const { error: verifyError } = await verifyMfaFactor(pendingFactorId, challenge.id, code);
    if (verifyError) {
      setError(verifyError.message);
      return;
    }

    setMessage("Two-factor authentication enabled.");
    setQrCode(null);
    setSecret(null);
    setPendingFactorId(null);
    setCode("");
    setEnrolling(false);
    await refresh();
  }

  async function remove(factorId: string) {
    await unenrollMfaFactor(factorId);
    await refresh();
  }

  if (authed === null) return <div className="px-6 py-16 text-center">Loading…</div>;
  if (!authed) {
    return (
      <div className="mx-auto max-w-md px-6 py-24 text-center">
        <h1 className="text-2xl font-bold text-atlantic">Sign in required</h1>
        <Link href="/login" className="mt-6 inline-block text-atlantic underline">
          Sign in
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-lg px-6 py-16">
      <h1 className="mb-2 text-2xl font-bold text-atlantic">Two-factor authentication</h1>
      <p className="mb-8 text-sm text-slatedark/80">
        Add an authenticator app (Google Authenticator, 1Password, Authy,
        etc.) as a second factor. You'll be asked for a code at sign-in
        whenever this is enabled.
      </p>

      {message && <p className="mb-4 text-sm text-green-700">{message}</p>}
      {error && <p className="mb-4 text-sm text-red-600">{error}</p>}

      {factors.length > 0 && (
        <ul className="mb-8 divide-y divide-slate-100 rounded-lg border border-slate-200 text-sm">
          {factors.map((f) => (
            <li key={f.id} className="flex items-center justify-between p-4">
              <span>
                Authenticator app <span className="text-slatedark/50">({f.status})</span>
              </span>
              <button onClick={() => remove(f.id)} className="text-red-600 hover:underline">
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}

      {!qrCode && (
        <button
          onClick={startEnroll}
          disabled={enrolling}
          className="rounded-md bg-atlantic px-4 py-2 text-sm font-semibold text-white hover:opacity-90 disabled:opacity-50"
        >
          {factors.length > 0 ? "Add another authenticator" : "Enable two-factor authentication"}
        </button>
      )}

      {qrCode && (
        <form onSubmit={confirmEnroll} className="space-y-4 rounded-lg border border-slate-200 p-4">
          <p className="text-sm">Scan this QR code with your authenticator app:</p>
          {/* Supabase returns qr_code as an inline SVG data URI — safe to render directly as an <img> src. */}
          <img src={qrCode} alt="TOTP QR code" className="h-40 w-40" />
          <p className="text-xs text-slatedark/60">
            Can't scan it? Enter this code manually: <code className="break-all">{secret}</code>
          </p>
          <input
            type="text"
            inputMode="numeric"
            required
            placeholder="6-digit code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
          />
          <button type="submit" className="rounded-md bg-seafoam px-4 py-2 text-sm font-semibold text-slatedark hover:opacity-90">
            Confirm
          </button>
        </form>
      )}
    </div>
  );
}
