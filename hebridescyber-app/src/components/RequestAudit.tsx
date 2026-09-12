"use client";

// Lets a logged-in user request one of the three one-off audit tiers
// without leaving the app — posts to /api/account/request-audit, which
// reuses the same contact_enquiries pipeline the public /contact form
// writes to. Tier copy is the shared src/lib/auditTiers.ts, the same
// numbers src/app/pricing/page.tsx shows publicly.
import { useState } from "react";
import { AUDIT_TIERS, type AuditTierId } from "@/lib/auditTiers";

export default function RequestAudit({ token }: { token: string }) {
  const [targetUrl, setTargetUrl] = useState("");
  const [notes, setNotes] = useState("");
  const [requestingTier, setRequestingTier] = useState<AuditTierId | null>(null);
  const [sentTier, setSentTier] = useState<AuditTierId | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function request(tier: AuditTierId) {
    setRequestingTier(tier);
    setError(null);
    setSentTier(null);
    try {
      const res = await fetch("/api/account/request-audit", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ tier, targetUrl: targetUrl.trim() || undefined, notes: notes.trim() || undefined }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not send request");
      setSentTier(tier);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setRequestingTier(null);
    }
  }

  return (
    <section className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <h2 className="mb-4 font-mono text-xs text-cybertext/40 uppercase tracking-wide">// request an audit</h2>
      <p className="mb-4 text-xs text-cybertext/50 leading-relaxed">
        Want a scoped, invoiced engagement instead of continuous monitoring? Request one of
        these directly — we&apos;ll follow up at your account email.
      </p>

      <div className="mb-4 grid gap-2 sm:grid-cols-2">
        <input
          type="url"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          placeholder="Target URL (optional)"
          className="rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
        />
        <input
          type="text"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="Notes (optional)"
          className="rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
        />
      </div>

      {error && <p className="mb-3 text-xs text-red-400" role="alert">{error}</p>}

      <ul className="divide-y divide-cyberborder rounded-lg border border-cyberborder">
        {AUDIT_TIERS.map((tier) => (
          <li key={tier.id} className="flex flex-wrap items-center justify-between gap-3 p-3">
            <div className="min-w-0">
              <p className="text-sm font-medium text-cybertext/80">
                {tier.name} <span className="font-mono text-neon/80">{tier.price}</span>
              </p>
              <p className="text-xs text-cybertext/50">{tier.desc}</p>
            </div>
            <button
              onClick={() => request(tier.id)}
              disabled={requestingTier !== null}
              className="shrink-0 rounded-md border border-neon/40 px-3 py-1.5 text-xs font-medium text-neon hover:bg-neon/10 disabled:opacity-40 transition-colors"
            >
              {requestingTier === tier.id
                ? "Sending…"
                : sentTier === tier.id
                  ? "Requested ✓"
                  : "Request this audit"}
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
