"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";
import { getSession } from "@/lib/auth";
import { diffFindings, type FindingsDiff } from "@/lib/findingsDiff";
import { SEVERITY_META, ScoreGauge, FindingCard, CheckRow, buildFindingsView, type ViewFinding } from "@/components/ScanReportView";
import ShareLinks from "@/components/ShareLinks";
import ScoreTrend, { type ScorePoint } from "@/components/ScoreTrend";
import { findPreviousFindingsClient, findScoreHistoryClient } from "@/lib/clientScanHistory";

type Finding = ViewFinding;

type ScanResult = {
  id: string;
  scan_id: string;
  results: {
    target_url?: string;
    checked_at?: string;
    tls?: { grade?: string; daysUntilExpiry?: number | null; issues?: string[]; valid?: boolean };
    headers?: { missing?: string[]; issues?: string[]; present?: Record<string, string> };
    dns?: { spf?: boolean; dmarc?: boolean; issues?: string[] };
    exposure?: { exposedPaths?: string[]; issues?: string[] };
    findings?: Finding[];
  };
  summary: string | null;
  score: number | null;
  created_at: string;
};

// findPreviousFindings / findScoreHistory now live in
// src/lib/clientScanHistory.ts (findPreviousFindingsClient /
// findScoreHistoryClient) — extracted so the dashboard overview
// (src/app/dashboard/page.tsx) can reuse the exact same hostname-matching
// logic rather than a second, drifting copy.

export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [diff, setDiff] = useState<FindingsDiff | null>(null);
  const [filter, setFilter] = useState<"all" | "new" | "fixed">("all");
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [scoreHistory, setScoreHistory] = useState<ScorePoint[]>([]);

  useEffect(() => {
    getSession().then((session) => setSessionToken(session?.access_token ?? null));
  }, []);

  useEffect(() => {
    if (!params?.id) return;
    (async () => {
      const { data, error: fetchError } = await supabase
        .from("scan_results")
        .select("id, scan_id, results, summary, score, created_at")
        .eq("scan_id", params.id)
        .maybeSingle();
      if (fetchError) setError(fetchError.message);
      setResult(data as ScanResult | null);
      setLoading(false);
    })().catch((err) => {
      setError((err as Error).message);
      setLoading(false);
    });
  }, [params?.id]);

  // Runs after the current scan loads, not alongside it — the previous-scan
  // lookup needs this scan's target_url and created_at first, and failing to
  // find a previous scan should never block rendering the current report.
  useEffect(() => {
    if (!result?.results?.target_url) return;
    const currentFindings = (result.results.findings as Finding[] | undefined) ?? [];

    findPreviousFindingsClient(result.scan_id, result.results.target_url, result.created_at)
      .then((previousFindings) => {
        if (previousFindings) setDiff(diffFindings(currentFindings, previousFindings));
      })
      .catch(() => {
        // Non-fatal — the report still renders fully without the New/Fixed filter.
      });
  }, [result]);

  useEffect(() => {
    if (!result?.results?.target_url) return;
    findScoreHistoryClient(result.scan_id, result.results.target_url, result.score, result.created_at)
      .then(setScoreHistory)
      .catch(() => {
        // Non-fatal — the report still renders fully without the trend chart.
      });
  }, [result]);

  if (loading) {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center">
        <p className="font-mono text-sm text-cybertext/30">// loading scan report…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center">
        <p className="text-sm text-red-400">{error}</p>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center text-center px-6">
        <p className="text-sm text-cybertext/50">
          No results yet — the scan may still be running.{" "}
          <Link href="/dashboard" className="text-neon underline">← Dashboard</Link>
        </p>
      </div>
    );
  }

  const findings: Finding[] = (result.results?.findings as Finding[] | undefined) ?? [];
  const taggedOrdered = buildFindingsView(findings, diff, "all");
  const newOrdered = buildFindingsView(findings, diff, "new");
  const fixedOrdered = buildFindingsView(findings, diff, "fixed");
  const visibleFindings = buildFindingsView(findings, diff, filter);
  const criticalOrHighCount = findings.filter((f) => f.severity === "critical" || f.severity === "high").length;

  const targetUrl = result.results?.target_url ?? `Scan ${result.scan_id.slice(0, 8)}`;
  const checkedAt = result.results?.checked_at
    ? new Date(result.results.checked_at).toLocaleString()
    : new Date(result.created_at).toLocaleString();

  const tls = result.results?.tls;
  const dns = result.results?.dns;
  const headers = result.results?.headers;
  const exposure = result.results?.exposure;

  return (
    <>
      {/* Print styles — keep PDF light-on-white */}
      <style>{`
        @media print {
          body { font-family: system-ui, sans-serif; color: #1e293b; background: #fff; }
          .no-print { display: none !important; }
          .page-break-before { page-break-before: always; }
          a { color: inherit; text-decoration: none; }
        }
        @page { margin: 1.5cm; }
      `}</style>

      <div className="bg-cyberbg min-h-screen text-cybertext print:bg-white print:text-slate-800">
        <div className="bg-grid pointer-events-none fixed inset-0 opacity-20 print:hidden" />

        <div className="relative mx-auto max-w-3xl px-6 py-12 space-y-8 print:py-0 print:space-y-6">
          {/* Header */}
          <div>
            <Link
              href="/dashboard"
              className="no-print inline-block mb-3 font-mono text-xs text-cybertext/40 hover:text-neon transition-colors"
            >
              ← Back to dashboard
            </Link>
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="font-mono text-xs text-neon/50" aria-hidden="true">$ ./report</p>
                <h1 className="text-2xl font-bold text-cybertext break-all print:text-slate-800">{targetUrl}</h1>
                <p className="mt-1 text-sm text-cybertext/40 print:text-slate-500">Security scan report · {checkedAt}</p>
              </div>
              <button
                onClick={() => window.print()}
                className="no-print shrink-0 rounded-md border border-cyberborder px-4 py-2 text-sm font-medium text-cybertext/60 hover:border-neon hover:text-neon transition-colors"
              >
                ↓ Download PDF
              </button>
            </div>
          </div>

          {/* Score + summary */}
          <div className="flex flex-col items-start gap-6 rounded-xl border border-cyberborder bg-cyberpanel p-6 sm:flex-row sm:items-center print:border-slate-200 print:bg-white">
            {result.score !== null && <ScoreGauge score={result.score} />}
            <div>
              <p className="text-sm font-semibold text-neon mb-1 print:text-slate-800">Executive summary</p>
              <p className="text-sm text-cybertext/70 leading-relaxed print:text-slate-600">
                {result.summary ?? "Scan complete. Review findings below."}
              </p>
              {findings.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-2 text-xs">
                  {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
                    const count = findings.filter((f) => f.severity === sev).length;
                    if (count === 0) return null;
                    const meta = SEVERITY_META[sev];
                    return (
                      <span key={sev} className={`rounded-full ${meta.bg} border ${meta.border} px-2 py-0.5 ${meta.text} font-medium`}>
                        {count} {sev}
                      </span>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* Score trend */}
          {scoreHistory.length >= 2 && (
            <div className="no-print rounded-xl border border-cyberborder bg-cyberpanel p-5">
              <ScoreTrend points={scoreHistory} />
            </div>
          )}

          {/* Check breakdown */}
          <div>
            <h2 className="mb-3 font-mono text-xs text-cybertext/40 uppercase tracking-wide">// check breakdown</h2>
            <div className="grid gap-2 sm:grid-cols-2">
              {tls && (
                <CheckRow
                  label="TLS / HTTPS"
                  pass={tls.valid !== false && (tls.daysUntilExpiry ?? 999) > 0}
                  detail={[
                    tls.grade ? `Grade ${tls.grade}` : null,
                    tls.daysUntilExpiry != null ? `${tls.daysUntilExpiry} days until expiry` : null,
                    tls.issues?.length ? tls.issues.join(", ") : "No issues",
                  ].filter(Boolean).join(" · ")}
                />
              )}
              {headers && (
                <CheckRow
                  label="Security headers"
                  pass={(headers.missing?.length ?? 0) === 0}
                  detail={
                    (headers.missing?.length ?? 0) === 0
                      ? "All required headers present"
                      : `Missing: ${headers.missing?.join(", ")}`
                  }
                />
              )}
              {dns && (
                <CheckRow
                  label="Email authentication"
                  pass={dns.spf && dns.dmarc}
                  detail={`SPF ${dns.spf ? "✓" : "missing"} · DMARC ${dns.dmarc ? "✓" : "missing"}`}
                />
              )}
              {exposure && (
                <CheckRow
                  label="Exposed sensitive paths"
                  pass={(exposure.exposedPaths?.length ?? 0) === 0}
                  detail={
                    (exposure.exposedPaths?.length ?? 0) === 0
                      ? "No sensitive files exposed"
                      : `Exposed: ${exposure.exposedPaths?.join(", ")}`
                  }
                />
              )}
            </div>
          </div>

          {/* Findings */}
          {taggedOrdered.length > 0 || (diff && diff.fixed.length > 0) ? (
            <div>
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <h2 className="font-mono text-xs text-cybertext/40 uppercase tracking-wide">// findings</h2>
                {diff && (
                  <div className="no-print flex gap-2 text-xs">
                    {([
                      ["all", `All (${taggedOrdered.length})`],
                      ["new", `New (${newOrdered.length})`],
                      ["fixed", `Fixed (${fixedOrdered.length})`],
                    ] as const).map(([key, label]) => (
                      <button
                        key={key}
                        onClick={() => setFilter(key)}
                        className={`rounded-full border px-3 py-1 font-medium transition-colors ${
                          filter === key
                            ? "border-neon/40 bg-neon/10 text-neon"
                            : "border-cyberborder text-cybertext/50 hover:border-cybertext/30 hover:text-cybertext/70"
                        }`}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              {visibleFindings.length > 0 ? (
                <div className="space-y-3">
                  {visibleFindings.map((f, i) => (
                    <FindingCard
                      key={f.checkId ?? i}
                      finding={f}
                      scanId={result.scan_id}
                      token={sessionToken ?? undefined}
                    />
                  ))}
                </div>
              ) : (
                <p className="text-sm text-cybertext/40">
                  {filter === "new"
                    ? "No new findings since your last scan of this target."
                    : "No findings were fixed since your last scan of this target."}
                </p>
              )}
            </div>
          ) : (
            <div className="rounded-lg border border-neon/20 bg-neon/5 p-5 text-sm text-neon">
              No significant findings detected. TLS, headers, DNS authentication, and common exposure paths all checked out.
            </div>
          )}

          {/* Remediation prompt */}
          {criticalOrHighCount > 0 && (
            <div className="no-print rounded-lg border border-orange-400/30 bg-orange-400/10 p-4 text-sm text-orange-400">
              <strong>{criticalOrHighCount} critical/high finding{criticalOrHighCount !== 1 ? "s" : ""} found.</strong>{" "}
              Hebrides Cyber can open remediation PRs directly in your repository — contact us or{" "}
              <Link href="/services" className="underline hover:text-cybertext">see how it works</Link>.
            </div>
          )}

          {/* Share this report */}
          {sessionToken && <ShareLinks scanId={result.scan_id} token={sessionToken} />}

          {/* Score badge embed */}
          <div className="no-print rounded-xl border border-cyberborder bg-cyberpanel p-5">
            <p className="font-mono text-xs text-cybertext/40 uppercase tracking-wide mb-3">// embed your score badge</p>
            <code className="block break-all rounded border border-cyberborder bg-cyberbg p-3 text-xs text-neon">
              {`<img src="https://hebridescyber.com/api/badge/${result.scan_id}.svg" alt="Security Score ${result.score ?? '?'}/100" />`}
            </code>
          </div>

          {/* Print footer */}
          <div className="hidden print:block mt-8 pt-4 border-t border-slate-200 text-xs text-slate-400 text-center">
            <p>Generated by Hebrides Cyber Security Score · hebridescyber.com · {checkedAt}</p>
            <p className="mt-1">This report is confidential. Findings represent a point-in-time snapshot and should be verified before remediation.</p>
          </div>
        </div>
      </div>
    </>
  );
}
