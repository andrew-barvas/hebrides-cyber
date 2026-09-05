"use client";

import { useState } from "react";

// Customer-facing half of E-10's GDPR erasure commitment (docs/ENHANCEMENTS.md,
// /privacy §7's 30-day response promise). Calls
// /api/account/request-deletion, which only records the request and emails
// the account owner — it does not delete anything itself, so this button is
// safe to click without a scarier confirmation flow than the two-step one
// below.
export default function AccountDeletion({ token }: { token: string }) {
  const [confirming, setConfirming] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submitRequest() {
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch("/api/account/request-deletion", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error ?? `Request failed (${res.status})`);
      }
      setDone(true);
      setConfirming(false);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="rounded-xl border border-red-900/40 bg-cyberpanel p-5">
      <h2 className="font-mono text-xs text-red-400/70 uppercase tracking-wide mb-4">// danger zone</h2>

      {done ? (
        <p className="text-sm text-cybertext/70">
          Request received — we&apos;ll action it within 30 days, per our{" "}
          <a href="/privacy" className="text-neon hover:underline">Privacy Policy</a>.
        </p>
      ) : (
        <>
          <p className="text-sm text-cybertext/60">
            Request deletion of your account and all associated data (scans,
            reports, subscription). This can&apos;t be undone once actioned.
          </p>
          {error && (
            <p className="mt-3 text-xs text-red-400" role="alert">{error}</p>
          )}
          <div className="mt-4">
            {!confirming ? (
              <button
                onClick={() => setConfirming(true)}
                className="rounded-md border border-red-900/50 px-4 py-2 text-sm font-medium text-red-400 hover:bg-red-950/40 transition-colors"
              >
                Request account deletion
              </button>
            ) : (
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-sm text-cybertext/70">Are you sure?</span>
                <button
                  onClick={submitRequest}
                  disabled={submitting}
                  className="rounded-md bg-red-900/60 px-4 py-2 text-sm font-semibold text-red-100 hover:bg-red-900 disabled:opacity-50 transition-colors"
                >
                  {submitting ? "Submitting…" : "Yes, request deletion"}
                </button>
                <button
                  onClick={() => setConfirming(false)}
                  disabled={submitting}
                  className="rounded-md border border-cyberborder px-4 py-2 text-sm font-medium text-cybertext/70 hover:border-neon hover:text-neon disabled:opacity-40 transition-colors"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>
        </>
      )}
    </section>
  );
}
