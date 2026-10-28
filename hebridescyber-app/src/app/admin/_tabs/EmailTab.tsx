"use client";

import { useEffect, useState } from "react";
import { reltime, apiFetch } from "../_shared";

type EmailHealth = {
  windowHours: number;
  total: number;
  sent: number;
  failed: number;
  failureRatePct: number | null;
  recentFailures: { subject: string | null; domain: string | null; error: string | null; at: string }[];
};

export default function EmailHealthTab({ token }: { token: string }) {
  const [health, setHealth] = useState<EmailHealth | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<EmailHealth>("/api/admin/email-health", token)
      .then(setHealth)
      .catch((e) => setErr((e as Error).message));
  }, [token]);

  if (err) return <p className="text-sm text-red-400">{err}</p>;
  if (!health) return <p className="font-mono text-sm text-cybermuted">// loading…</p>;

  const rate = health.failureRatePct;
  const rateColor = rate === null ? "text-cybermuted" : rate >= 20 ? "text-red-400" : rate > 0 ? "text-amber-400" : "text-neon";

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
        <h3 className="mb-3 font-mono text-xs uppercase tracking-wide text-cybermuted">// email deliverability · last {health.windowHours}h</h3>
        <div className="grid grid-cols-3 gap-4">
          <div>
            <p className="text-2xl font-bold text-cybertext">{health.total}</p>
            <p className="text-xs text-cybertext/50">Sends attempted</p>
          </div>
          <div>
            <p className="text-2xl font-bold text-neon">{health.sent}</p>
            <p className="text-xs text-cybertext/50">Delivered to provider</p>
          </div>
          <div>
            <p className={`text-2xl font-bold ${rateColor}`}>{rate === null ? "—" : `${rate.toFixed(1)}%`}</p>
            <p className="text-xs text-cybertext/50">Failure rate ({health.failed} failed)</p>
          </div>
        </div>
        {health.total === 0 && <p className="mt-3 text-xs text-cybermuted">No send attempts recorded in this window (or migration 056 not yet applied).</p>}
      </div>

      {health.recentFailures.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-cyberborder bg-cyberpanel">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-cyberborder bg-cyberbg text-left text-xs text-cybermuted">
                <th className="px-4 py-3">When</th>
                <th className="px-4 py-3">Recipient domain</th>
                <th className="px-4 py-3">Subject</th>
                <th className="px-4 py-3">Error</th>
              </tr>
            </thead>
            <tbody>
              {health.recentFailures.map((f, i) => (
                <tr key={i} className="border-b border-cyberborder/50">
                  <td className="px-4 py-2 font-mono text-xs text-cybermuted whitespace-nowrap">{reltime(f.at)}</td>
                  <td className="px-4 py-2 font-mono text-xs text-cybertext/70">{f.domain ?? "—"}</td>
                  <td className="px-4 py-2 text-xs text-cybertext/60 max-w-48 truncate">{f.subject ?? "—"}</td>
                  <td className="px-4 py-2 text-xs text-red-400 max-w-64 truncate">{f.error ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
