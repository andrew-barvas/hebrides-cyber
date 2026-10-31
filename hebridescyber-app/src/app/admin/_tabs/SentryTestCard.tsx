"use client";

// One-click check that API-side error tracking reaches Sentry
// (POST /api/admin/sentry-test; OWNER-TODO.md OT-08, LAUNCH-PRIORITY.md item 2 AC1).
import { useState } from "react";
import { apiFetch } from "../_shared";

type SentryTestResult = { configured: boolean; eventId: string | null; delivered: boolean };

export default function SentryTestCard({ token }: { token: string }) {
  const [result, setResult] = useState<SentryTestResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function send() {
    setBusy(true);
    setErr(null);
    try {
      setResult(await apiFetch<SentryTestResult>("/api/admin/sentry-test", token, { method: "POST" }));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <h3 className="mb-2 font-mono text-xs uppercase tracking-wide text-cybermuted">// error tracking</h3>
      <p className="mb-3 text-sm text-cybertext/70">
        Sends one tagged test error (<code className="font-mono text-xs">sentry_test:true</code>) from the API to Sentry.
      </p>
      <button
        type="button"
        onClick={send}
        disabled={busy}
        className="rounded border border-neon/40 px-3 py-1.5 font-mono text-xs text-neon hover:bg-neon/10 disabled:opacity-50"
      >
        {busy ? "Sending…" : "Send test error"}
      </button>
      {err && <p className="mt-3 text-sm text-red-400">{err}</p>}
      {result && !result.configured && (
        <p className="mt-3 text-sm text-amber-400">No Sentry DSN is configured for the API (set SENTRY_DSN in Azure), so nothing was sent.</p>
      )}
      {result?.configured && (
        <p className={`mt-3 text-sm ${result.delivered ? "text-neon" : "text-amber-400"}`}>
          {result.delivered ? "Delivered" : "Captured but not confirmed delivered within 5s"}. Event id{" "}
          <span className="font-mono text-xs">{result.eventId}</span>: search for it in Sentry.
        </p>
      )}
    </div>
  );
}
