"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";

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
      const [subRes, targetsRes, scansRes] = await Promise.all([
        supabase
          .from("subscriptions")
          .select("brand_logo_url, brand_name")
          .maybeSingle(),
        supabase
          .from("monitored_targets")
          .select("id", { count: "exact", head: true }),
        supabase
          .from("scans")
          .select("id, status")
          .eq("status", "completed"),
      ]);

      const brandName = (subRes.data?.brand_name as string | null) ?? null;
      const brandLogoUrl = (subRes.data?.brand_logo_url as string | null) ?? null;
      const monitoredTargetCount = targetsRes.count ?? 0;
      const totalScans = scansRes.data?.length ?? 0;

      let latestScore: number | null = null;
      let avgScore: number | null = null;
      if (totalScans > 0) {
        const { data: scoreData } = await supabase
          .from("scan_results")
          .select("score, scan_id")
          .order("created_at", { ascending: false })
          .limit(20);

        if (scoreData && scoreData.length > 0) {
          const scores = scoreData
            .map((r) => r.score as number | null)
            .filter((s): s is number => s !== null);
          if (scores.length > 0) {
            latestScore = scores[0];
            avgScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
          }
        }
      }

      setStats({ brandName, brandLogoUrl, monitoredTargetCount, totalScans, latestScore, avgScore });
      setLoading(false);
    }

    load();
  }, []);

  if (loading) {
    return (
      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5 animate-pulse">
        <div className="h-4 w-32 rounded bg-cyberborder/50 mb-4" />
        <div className="h-20 rounded bg-cyberborder/30" />
      </div>
    );
  }

  if (!stats) return null;

  return (
    <div className="rounded-xl border border-neon/20 bg-cyberpanel p-5">
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-mono text-xs text-cybertext/40 uppercase tracking-wide">// partner portal</h2>
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
            className="h-8 w-8 rounded object-contain bg-cyberbg border border-cyberborder"
          />
        ) : (
          <div className="h-8 w-8 rounded bg-cyberbg border border-cyberborder flex items-center justify-center">
            <span className="text-xs text-cybertext/30">?</span>
          </div>
        )}
        <div>
          <p className="text-sm font-medium text-cybertext">
            {stats.brandName ?? "No brand name set"}
          </p>
          <p className="text-[10px] text-cybertext/40">
            {stats.brandLogoUrl ? "White-label active" : "No custom branding — reports use HebridesCyber branding"}
          </p>
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <div className="rounded-lg border border-cyberborder bg-cyberbg/50 p-2.5 text-center">
          <p className="text-lg font-bold text-cybertext">{stats.monitoredTargetCount}</p>
          <p className="text-[10px] text-cybertext/40">Monitored sites</p>
        </div>
        <div className="rounded-lg border border-cyberborder bg-cyberbg/50 p-2.5 text-center">
          <p className="text-lg font-bold text-cybertext">{stats.totalScans}</p>
          <p className="text-[10px] text-cybertext/40">Total scans</p>
        </div>
        <div className="rounded-lg border border-cyberborder bg-cyberbg/50 p-2.5 text-center">
          <p className={`text-lg font-bold ${stats.latestScore !== null && stats.latestScore >= 70 ? "text-neon" : stats.latestScore !== null && stats.latestScore >= 40 ? "text-yellow-400" : "text-red-400"}`}>
            {stats.latestScore ?? "—"}
          </p>
          <p className="text-[10px] text-cybertext/40">Latest score</p>
        </div>
        <div className="rounded-lg border border-cyberborder bg-cyberbg/50 p-2.5 text-center">
          <p className={`text-lg font-bold ${stats.avgScore !== null && stats.avgScore >= 70 ? "text-neon" : stats.avgScore !== null && stats.avgScore >= 40 ? "text-yellow-400" : "text-red-400"}`}>
            {stats.avgScore ?? "—"}
          </p>
          <p className="text-[10px] text-cybertext/40">Avg score</p>
        </div>
      </div>
    </div>
  );
}
