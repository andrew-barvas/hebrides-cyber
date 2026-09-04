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
        const latest = targetHost
          ? candidates.find((c) => hostnameOf(c.target_url) === targetHost)
          : undefined;
        const result = latest?.scan_results?.[0];
        const findings = result?.results?.findings ?? [];
        return {
          targetId: t.id,
          targetUrl: t.target_url,
          latestScanId: latest?.id ?? null,
          latestScore: result?.score ?? null,
          lastScannedAt: latest?.created_at ?? null,
          openFindingsCount: latest ? findings.filter((f) => f.severity !== "info").length : null,
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
      <h2 className="mb-3 font-mono text-xs text-cybertext/40 uppercase tracking-wide">// fleet overview ({rows.length} sites)</h2>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-cyberborder text-left text-xs text-cybertext/40">
              <th className="pb-2 font-normal">Site</th>
              <th className="pb-2 font-normal">Score</th>
              <th className="pb-2 font-normal">Open findings</th>
              <th className="pb-2 font-normal">Last scanned</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyberborder">
            {rows.map((row) => (
              <tr key={row.targetId}>
                <td className="py-2.5 pr-3 font-mono text-xs text-cybertext/80">{row.targetUrl}</td>
                <td className="py-2.5 pr-3">
                  {row.latestScore !== null ? (
                    <span className={`font-semibold ${scoreColor(row.latestScore)}`}>{row.latestScore}/100</span>
                  ) : (
                    <span className="text-cybertext/30">—</span>
                  )}
                </td>
                <td className="py-2.5 pr-3 text-cybertext/70">
                  {row.openFindingsCount !== null ? row.openFindingsCount : <span className="text-cybertext/30">—</span>}
                </td>
                <td className="py-2.5">
                  {row.lastScannedAt ? (
                    row.latestScanId ? (
                      <Link href={`/dashboard/scans/${row.latestScanId}`} className="text-neon hover:underline">
                        {relativeTime(row.lastScannedAt)}
                      </Link>
                    ) : (
                      relativeTime(row.lastScannedAt)
                    )
                  ) : (
                    <span className="text-cybertext/30">Never scanned</span>
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
