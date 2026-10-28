"use client";

import { useEffect, useState } from "react";
import { Metrics, statusBadge, reltime, apiFetch, StatCard } from "../_shared";

export default function OverviewTab({ token }: { token: string }) {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<Metrics>("/api/admin/metrics", token)
      .then(setMetrics)
      .catch((e) => setErr(e.message));
  }, [token]);

  if (err) return <p className="text-red-400 text-sm">{err}</p>;
  if (!metrics) return <p className="text-cybermuted text-sm font-mono">// loading…</p>;

  return (
    <div className="space-y-8">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Customers" value={metrics.totalCustomers} />
        <StatCard label="Active subscriptions" value={metrics.activeSubscriptions} />
        <StatCard label="Total scans" value={metrics.totalScans} sub={`${metrics.scansLast30d} last 30 days`} />
        {/* Paying MRR: real Stripe subscriptions × this product's published
            prices, excluding admin comps and bespoke Tier A (see
            revenueMetrics.ts). Detail is in the Revenue panel below. */}
        <StatCard
          label="Paying MRR"
          value={`£${metrics.revenue.payingMrrGbp.toLocaleString()}`}
          sub={`${metrics.revenue.payingCount} paying · basic £20 · pro £35 · agency £75`}
        />
      </div>

      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
        <h3 className="mb-3 font-mono text-xs text-cybermuted uppercase tracking-wide">// revenue &amp; churn</h3>
        <div className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
          <div>
            <p className="text-xl font-bold text-neon">£{metrics.revenue.payingMrrGbp.toLocaleString()}</p>
            <p className="text-xs text-cybertext/50">Paying MRR · {metrics.revenue.payingCount} subs</p>
          </div>
          <div>
            <p className="text-xl font-bold text-cybertext">
              {metrics.revenue.churnRatePct === null ? "—" : `${metrics.revenue.churnRatePct.toFixed(1)}%`}
            </p>
            <p className="text-xs text-cybertext/50">Monthly churn</p>
          </div>
          <div>
            <p className="text-xl font-bold text-seafoam">+{metrics.revenue.newSubs30d}</p>
            <p className="text-xs text-cybertext/50">New (30d)</p>
          </div>
          <div>
            <p className={`text-xl font-bold ${metrics.revenue.cancellations30d > 0 ? "text-red-400" : "text-cybertext"}`}>
              −{metrics.revenue.cancellations30d}
            </p>
            <p className="text-xs text-cybertext/50">Cancelled (30d)</p>
          </div>
        </div>
        {(metrics.revenue.compedCount > 0 || metrics.revenue.bespokeCount > 0 || metrics.revenue.pastDueCount > 0) && (
          <p className="mt-3 border-t border-cyberborder/50 pt-3 text-xs text-cybermuted">
            {metrics.revenue.pastDueCount > 0 && <span className="text-amber-400">{metrics.revenue.pastDueCount} past-due (at risk)</span>}
            {metrics.revenue.pastDueCount > 0 && (metrics.revenue.compedCount > 0 || metrics.revenue.bespokeCount > 0) && " · "}
            {metrics.revenue.compedCount > 0 && `${metrics.revenue.compedCount} admin-comped (£0)`}
            {metrics.revenue.compedCount > 0 && metrics.revenue.bespokeCount > 0 && " · "}
            {metrics.revenue.bespokeCount > 0 && `${metrics.revenue.bespokeCount} Tier A (bespoke, not in MRR)`}
          </p>
        )}
      </div>

      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
        <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
          <h3 className="mb-3 font-mono text-xs text-cybermuted uppercase tracking-wide">// plans</h3>
          <div className="space-y-2">
            {metrics.planBreakdown.map((p) => (
              <div key={p.plan} className="flex items-center justify-between">
                <span className="capitalize text-sm text-cybertext/70">{p.plan}</span>
                <span className="text-sm font-medium text-neon">{p.count}</span>
              </div>
            ))}
            {metrics.planBreakdown.length === 0 && (
              <p className="text-xs text-cybermuted">No active subscriptions</p>
            )}
          </div>
        </div>

        <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
          <h3 className="mb-3 font-mono text-xs text-cybermuted uppercase tracking-wide">// scan status</h3>
          <div className="space-y-2">
            {Object.entries(metrics.scansByStatus).map(([status, count]) => (
              <div key={status} className="flex items-center justify-between">
                {statusBadge(status)}
                <span className="text-sm font-medium text-neon">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
        <h3 className="mb-3 font-mono text-xs text-cybermuted uppercase tracking-wide">// recent signups</h3>
        <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-cyberborder text-left text-xs text-cybermuted">
              <th className="pb-2 pr-4">Email</th>
              <th className="pb-2 pr-4">Company</th>
              <th className="pb-2">Joined</th>
            </tr>
          </thead>
          <tbody>
            {metrics.recentSignups.map((u) => (
              <tr key={u.id} className="border-b border-cyberborder/50">
                <td className="py-1.5 pr-4 font-mono text-xs text-cybertext">{u.email}</td>
                <td className="py-1.5 pr-4 text-cybertext/50">{u.company_name ?? "—"}</td>
                <td className="py-1.5 text-cybermuted">{reltime(u.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      </div>
    </div>
  );
}
