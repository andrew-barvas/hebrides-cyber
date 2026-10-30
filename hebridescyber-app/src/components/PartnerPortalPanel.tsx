"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

type PartnerStats = {
  brandName: string | null;
  brandLogoUrl: string | null;
  monitoredTargetCount: number;
  totalScans: number;
  latestScore: number | null;
  avgScore: number | null;
};

export default function PartnerPortalPanel() {
  const [stats, setStats] = useState<PartnerStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      const res = await fetch("/api/account/partner-portal");
      // 403 = not on Agency plan — hide the panel silently.
      if (res.status === 403) {
        setLoading(false);
        return;
      }
      if (!res.ok) {
        setLoading(false);
        return;
      }
      const data = (await res.json()) as PartnerStats;
      setStats(data);
      setLoading(false);
    }

    load();
  }, []);

  if (loading) {
    return (
      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5 animate-pulse">
        <div className="h-4 w-32 rounded-sm bg-cyberborder/50 mb-4" />
        <div className="h-20 rounded-sm bg-cyberborder/30" />
      </div>
    );
  }

  if (!stats) return null;

  return (
    <div className="rounded-xl border border-neon/20 bg-cyberpanel p-5">
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-mono text-xs text-cybermuted uppercase tracking-wide">// partner portal</h2>
        <Link
          href="/account"
          className="text-[10px] text-neon hover:underline"
        >
          Manage branding
        </Link>
      </div>

      {/* White-label status */}
      <div className="mb-4 flex items-center gap-3">
        {stats.brandLogoUrl ? (
          <img
            src={stats.brandLogoUrl}
            alt={stats.brandName ?? "Brand logo"}
            className="h-8 w-8 rounded-sm object-contain bg-cyberbg border border-cyberborder"
          />
        ) : (
          <div className="h-8 w-8 rounded-sm bg-cyberbg border border-cyberborder flex items-center justify-center">
            <span className="text-xs text-cybermuted">?</span>
          </div>
        )}
        <div>
          <p className="text-sm font-medium text-cybertext">
            {stats.brandName ?? "No brand name set"}
          </p>
          <p className="text-[10px] text-cybermuted">
            {stats.brandLogoUrl ? "White-label active" : "No custom branding — reports use HebridesCyber branding"}
          </p>
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <div className="rounded-lg border border-cyberborder bg-cyberbg/50 p-2.5 text-center">
          <p className="text-lg font-bold text-cybertext">{stats.monitoredTargetCount}</p>
          <p className="text-[10px] text-cybermuted">Monitored sites</p>
        </div>
        <div className="rounded-lg border border-cyberborder bg-cyberbg/50 p-2.5 text-center">
          <p className="text-lg font-bold text-cybertext">{stats.totalScans}</p>
          <p className="text-[10px] text-cybermuted">Total scans</p>
        </div>
        <div className="rounded-lg border border-cyberborder bg-cyberbg/50 p-2.5 text-center">
          <p className={`text-lg font-bold ${stats.latestScore !== null && stats.latestScore >= 70 ? "text-neon" : stats.latestScore !== null && stats.latestScore >= 40 ? "text-yellow-400" : "text-red-400"}`}>
            {stats.latestScore ?? "—"}
          </p>
          <p className="text-[10px] text-cybermuted">Latest score</p>
        </div>
        <div className="rounded-lg border border-cyberborder bg-cyberbg/50 p-2.5 text-center">
          <p className={`text-lg font-bold ${stats.avgScore !== null && stats.avgScore >= 70 ? "text-neon" : stats.avgScore !== null && stats.avgScore >= 40 ? "text-yellow-400" : "text-red-400"}`}>
            {stats.avgScore ?? "—"}
          </p>
          <p className="text-[10px] text-cybermuted">Avg score</p>
        </div>
      </div>
    </div>
  );
}
