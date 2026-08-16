"use client";

import { useEffect, useState } from "react";
import {
  listMfaFactors,
  enrollMfaTotp,
  challengeMfaFactor,
  verifyMfaFactor,
  unenrollMfaFactor,
} from "@/lib/auth";

type Factor = { id: string; friendly_name?: string; status: string };

// TOTP enrollment via Supabase Auth's built-in MFA (auth.mfa.*) — no
// third-party MFA service needed. Once a factor is verified here, future
// sign-ins are challenged for it at /login/mfa-challenge before the session
// reaches "aal2" (see src/lib/auth.ts and the dashboard's auth check).
export default function TwoFactor() {
  const [factors, setFactors] = useState<Factor[]>([]);
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [pendingFactorId, setPendingFactorId] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [enrolling, setEnrolling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  async function refresh() {
    const data = await listMfaFactors();
    setFactors((data.totp ?? []) as Factor[]);
  }

  useEffect(() => {
    refresh().catch(() => {
      /* Not fatal — the section just shows no factors. */
    });
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

  return (
    <section className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <h2 className="font-mono text-xs text-cybertext/40 uppercase tracking-wide">// security</h2>
        {factors.length > 0 && (
          <span className="rounded-full border border-neon/30 bg-neon/10 px-2 py-0.5 text-xs font-medium text-neon">
            2FA on
          </span>
        )}
      </div>

      <p className="mb-4 text-xs text-cybertext/50 leading-relaxed">
        Add an authenticator app (1Password, Authy, Google Authenticator) as a
        second factor. You&apos;ll be asked for a code when you sign in.
      </p>

      {message && <p className="mb-3 text-xs text-neon">{message}</p>}
      {error && <p className="mb-3 text-xs text-red-400" role="alert">{error}</p>}

      {factors.length > 0 && (
        <ul className="mb-4 divide-y divide-cyberborder rounded-lg border border-cyberborder">
          {factors.map((f) => (
            <li key={f.id} className="flex items-center justify-between gap-2 p-3">
              <span className="text-sm text-cybertext/80">
                Authenticator app <span className="text-cybertext/40">({f.status})</span>
              </span>
              <button
                onClick={() => remove(f.id)}
                className="text-xs text-cybertext/40 hover:text-red-400 transition-colors"
              >
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
          className="rounded-md border border-cyberborder px-4 py-2 text-sm font-medium text-cybertext/70 hover:border-neon hover:text-neon disabled:opacity-40 transition-colors"
        >
          {factors.length > 0 ? "Add another authenticator" : "Enable two-factor authentication"}
        </button>
      )}

      {qrCode && (
        <form onSubmit={confirmEnroll} className="space-y-3 rounded-lg border border-cyberborder bg-cyberbg p-4">
          <p className="text-sm text-cybertext/80">Scan this with your authenticator app:</p>
          {/* Supabase returns qr_code as an inline SVG data URI — safe as an <img> src. */}
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={qrCode} alt="Two-factor authentication QR code" className="h-40 w-40 rounded bg-white p-1" />
          <p className="text-xs text-cybertext/40">
            Can&apos;t scan? Enter manually:{" "}
            <code className="break-all font-mono text-neon/80">{secret}</code>
          </p>
          <input
            type="text"
            inputMode="numeric"
            required
            placeholder="6-digit code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
          />
          <button
            type="submit"
            className="rounded-md bg-neon px-4 py-2 text-sm font-semibold text-cyberbg shadow-glowsm hover:opacity-90 transition-opacity"
          >
            Confirm
          </button>
        </form>
      )}
    </section>
  );
}
