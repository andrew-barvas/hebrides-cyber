"use client";

// E-27 (docs/ENHANCEMENTS.md): the dashboard's "Security Overview" only
// ever shows the most-recently-completed scan across *all* monitored
// targets — an Agency account with several sites has no way to see them
// all at a glance, only whichever one happened to finish scanning last.
// This is that fleet-wide view: one row per monitored target, each
// carrying its own latest score/last-scanned/open-findings, computed from
// the same hostname-matching convention clientScanHistory.ts already
// established (target_url isn't byte-identical across scans of "the same"
// site — protocol, trailing slash, case — so matching is by hostname, not
// exact string).
//
// Deliberately renders nothing for 0-1 targets — a single-target account
// already gets an equivalent (arguably better, since it includes trend/
// diff data) view from the existing Security Overview immediately below
// this component, and a one-row fleet table would just duplicate it.

import { useEffect, useState } from "react";
import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";
import type { Finding } from "@/lib/scanners";

type FleetRow = {
  targetId: string;
  targetUrl: string;
  latestScanId: string | null;
  latestScore: number | null;
  lastScannedAt: string | null;
  openFindingsCount: number | null;
  scoreHistory: number[];
};

type ScanCandidate = {
  id: string;
  target_url: string;
  created_at: string;
  scan_results: { score: number | null; results: { findings?: Finding[] } | null }[];
};

function hostnameOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function scoreColor(score: number): string {
  if (score >= 80) return "text-neon";
  if (score >= 50) return "text-amber-400";
  return "text-red-400";
}

const SPARK_W = 64;
const SPARK_H = 20;

function MiniSparkline({ points }: { points: number[] }) {
  if (points.length < 2) return null;
  const min = Math.min(...points);
  const max = Math.max(...points);
  const range = max - min || 1;
  const xFor = (i: number) => (i / (points.length - 1)) * SPARK_W;
  const yFor = (v: number) => SPARK_H - ((v - min) / range) * (SPARK_H - 2) - 1;
  const d = points.map((v, i) => `${i === 0 ? "M" : "L"}${xFor(i).toFixed(1)},${yFor(v).toFixed(1)}`).join(" ");
  const last = points[points.length - 1];
  const prev = points[points.length - 2];
  const color = last >= prev ? "var(--c-neon)" : "#f87171";
  return (
    <svg viewBox={`0 0 ${SPARK_W} ${SPARK_H}`} className="inline-block h-5 w-16" role="img" aria-label={`Score trend: ${points.join(", ")}`}>
      <path d={d} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function relativeTime(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 7) return `${days}d ago`;
  const weeks = Math.floor(days / 7);
  if (weeks < 5) return `${weeks}w ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

export default function FleetOverview() {
  const [rows, setRows] = useState<FleetRow[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const { data: targets } = await supabase
        .from("monitored_targets")
        .select("id, target_url")
        .order("created_at", { ascending: true });

      const targetList = (targets ?? []) as Array<{ id: string; target_url: string }>;
      if (targetList.length < 2) {
        setLoading(false);
        return;
      }

      // One batch fetch of recent completed scans across every target,
      // matched client-side by hostname — same shape as
      // clientScanHistory.ts's existing 100-scan window, wide enough to
      // very likely contain each target's latest scan without an
      // indexed hostname column to query against directly.
      const { data: scans } = await supabase
        .from("scans")
        .select("id, target_url, created_at, scan_results(score, results)")
        .eq("status", "completed")
        .order("created_at", { ascending: false })
        .limit(200);

      const candidates = (scans ?? []) as ScanCandidate[];

      const rowsOut: FleetRow[] = targetList.map((t) => {
        const targetHost = hostnameOf(t.target_url);
        const matching = targetHost
          ? candidates.filter((c) => hostnameOf(c.target_url) === targetHost)
          : [];
        const latest = matching[0];
        const result = latest?.scan_results?.[0];
        const findings = result?.results?.findings ?? [];
        const scoreHistory = matching
          .slice(0, 7)
          .reverse()
          .map((c) => c.scan_results?.[0]?.score)
          .filter((s): s is number => s != null);
        return {
          targetId: t.id,
          targetUrl: t.target_url,
          latestScanId: latest?.id ?? null,
          latestScore: result?.score ?? null,
          lastScannedAt: latest?.created_at ?? null,
          openFindingsCount: latest ? findings.filter((f) => f.severity !== "info").length : null,
          scoreHistory,
        };
      });

      // Worst score first — the sites that most need attention surface at
      // the top, not whichever was added to the account first.
      rowsOut.sort((a, b) => (a.latestScore ?? -1) - (b.latestScore ?? -1));
      setRows(rowsOut);
      setLoading(false);
    })();
  }, []);

  if (loading || rows.length === 0) return null;

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <h2 className="mb-3 font-mono text-xs text-cybermuted uppercase tracking-wide">// fleet overview ({rows.length} sites)</h2>
      <div className="sm:overflow-x-auto">
        <table className="block w-full text-sm sm:table">
          <thead className="hidden sm:table-header-group">
            <tr className="border-b border-cyberborder text-left text-xs text-cybermuted">
              <th className="pb-2 font-normal">Site</th>
              <th className="pb-2 font-normal">Score</th>
              <th className="pb-2 font-normal">Trend</th>
              <th className="pb-2 font-normal">Open findings</th>
              <th className="pb-2 font-normal">Last scanned</th>
            </tr>
          </thead>
          <tbody className="block space-y-2 sm:table-row-group sm:space-y-0 sm:divide-y sm:divide-cyberborder">
            {rows.map((row) => (
              <tr
                key={row.targetId}
                className="block rounded-lg border border-cyberborder/60 bg-cyberbg/20 p-3 sm:table-row sm:border-0 sm:bg-transparent sm:p-0"
              >
                <td className="py-0.5 font-mono text-xs text-cybertext/80 break-all sm:table-cell sm:max-w-[180px] sm:py-2.5 sm:pr-3">{row.targetUrl}</td>
                <td
                  data-label="Score"
                  className="flex items-center justify-between gap-3 py-0.5 before:font-mono before:text-[10px] before:uppercase before:tracking-wide before:text-cybermuted before:content-[attr(data-label)] sm:table-cell sm:py-2.5 sm:pr-3 sm:before:hidden"
                >
                  {row.latestScore !== null ? (
                    <span className={`font-semibold ${scoreColor(row.latestScore)}`}>{row.latestScore}/100</span>
                  ) : (
                    <span className="text-cybermuted">—</span>
                  )}
                </td>
                <td
                  data-label="Trend"
                  className="flex items-center justify-between gap-3 py-0.5 before:font-mono before:text-[10px] before:uppercase before:tracking-wide before:text-cybermuted before:content-[attr(data-label)] sm:table-cell sm:py-2.5 sm:pr-3 sm:before:hidden"
                >
                  <MiniSparkline points={row.scoreHistory} />
                </td>
                <td
                  data-label="Open findings"
                  className="flex items-center justify-between gap-3 py-0.5 text-cybertext/70 before:font-mono before:text-[10px] before:uppercase before:tracking-wide before:text-cybermuted before:content-[attr(data-label)] sm:table-cell sm:py-2.5 sm:pr-3 sm:before:hidden"
                >
                  {row.openFindingsCount !== null ? row.openFindingsCount : <span className="text-cybermuted">—</span>}
                </td>
                <td
                  data-label="Last scanned"
                  className="flex items-center justify-between gap-3 py-0.5 before:font-mono before:text-[10px] before:uppercase before:tracking-wide before:text-cybermuted before:content-[attr(data-label)] sm:table-cell sm:py-2.5 sm:before:hidden"
                >
                  {row.lastScannedAt ? (
                    row.latestScanId ? (
                      <Link href={`/dashboard/scans/${row.latestScanId}`} className="text-neon hover:underline">
                        {relativeTime(row.lastScannedAt)}
                      </Link>
                    ) : (
                      relativeTime(row.lastScannedAt)
                    )
                  ) : (
                    <span className="text-cybermuted">Never scanned</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
