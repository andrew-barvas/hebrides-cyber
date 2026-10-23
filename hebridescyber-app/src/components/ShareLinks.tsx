"use client";

import { useCallback, useEffect, useState } from "react";

type Share = {
  id: string;
  token: string;
  share_url: string;
  expires_at: string | null;
  revoked_at: string | null;
  view_count: number;
  created_at: string;
};

const EXPIRY_OPTIONS = [
  { label: "7 days", days: 7 },
  { label: "30 days", days: 30 },
  { label: "No expiry", days: null },
] as const;

export default function ShareLinks({ scanId, token }: { scanId: string; token: string }) {
  const [shares, setShares] = useState<Share[]>([]);
  const [loading, setLoading] = useState(true);
  const [expiryDays, setExpiryDays] = useState<number | null>(30);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch(`/api/scans/${scanId}/shares`, { headers: { Authorization: `Bearer ${token}` } });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not load share links");
      setShares(body.shares ?? []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [scanId, token]);

  useEffect(() => {
    load();
  }, [load]);

  async function create() {
    setCreating(true);
    setError(null);
    try {
      const res = await fetch(`/api/scans/${scanId}/shares`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(expiryDays ? { expires_in_days: expiryDays } : {}),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not create share link");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setCreating(false);
    }
  }

  async function remove(id: string) {
    setError(null);
    try {
      const res = await fetch(`/api/scans/${scanId}/shares`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not remove share link");
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function copy(share: Share) {
    await navigator.clipboard.writeText(share.share_url);
    setCopiedId(share.id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  const active = shares.filter((s) => !s.revoked_at);

  return (
    <div className="no-print rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <h2 className="mb-4 font-mono text-xs text-cybermuted uppercase tracking-wide">// share this report</h2>

      <p className="mb-4 text-xs text-cybertext/50 leading-relaxed">
        Anyone with a share link can view a read-only copy of this report — no
        login needed. Useful for sending to a client or auditor.
      </p>

      {error && <p className="mb-3 text-xs text-red-400" role="alert">{error}</p>}

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <select
          value={expiryDays ?? "none"}
          onChange={(e) => setExpiryDays(e.target.value === "none" ? null : Number(e.target.value))}
          className="rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext focus:border-neon focus:outline-none transition-colors"
        >
          {EXPIRY_OPTIONS.map((opt) => (
            <option key={opt.label} value={opt.days ?? "none"}>{opt.label}</option>
          ))}
        </select>
        <button
          onClick={create}
          disabled={creating}
          className="rounded-md bg-neon px-4 py-2 text-sm font-semibold text-cyberbg shadow-glowsm hover:opacity-90 disabled:opacity-40 transition-opacity"
        >
          {creating ? "Creating…" : "Create link"}
        </button>
      </div>

      {loading ? (
        <p className="font-mono text-xs text-cybermuted">// loading…</p>
      ) : active.length === 0 ? (
        <p className="text-xs text-cybermuted">No share links yet.</p>
      ) : (
        <ul className="divide-y divide-cyberborder rounded-lg border border-cyberborder">
          {active.map((s) => (
            <li key={s.id} className="flex flex-wrap items-center justify-between gap-2 p-3">
              <div className="min-w-0">
                <code className="block break-all font-mono text-xs text-neon/80">{s.share_url}</code>
                <p className="mt-0.5 text-xs text-cybermuted">
                  {s.view_count} view{s.view_count !== 1 ? "s" : ""}
                  {s.expires_at
                    ? ` · expires ${new Date(s.expires_at).toLocaleDateString("en-GB")}`
                    : " · never expires"}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-3">
                <button
                  onClick={() => copy(s)}
                  className="text-xs font-medium text-neon hover:underline"
                >
                  {copiedId === s.id ? "Copied" : "Copy"}
                </button>
                <button
                  onClick={() => remove(s.id)}
                  className="text-xs text-cybermuted hover:text-red-400 transition-colors"
                >
                  Revoke
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
