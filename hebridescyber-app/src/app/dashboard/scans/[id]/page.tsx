"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";
import { getSession } from "@/lib/auth";
import { diffFindings, type FindingsDiff, type DiffStatus } from "@/lib/findingsDiff";
import { SEVERITY_META, ScoreGauge, FindingCard, CheckRow, type Severity, type ViewFinding } from "@/components/ScanReportView";
import ShareLinks from "@/components/ShareLinks";
import ScoreTrend, { type ScorePoint } from "@/components/ScoreTrend";

type Finding = ViewFinding;

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
function sortBySeverity<T extends { severity: Severity }>(list: T[]): T[] {
  return [...list].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

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

/**
 * Finds the most recent completed scan of the same target that predates this
 * one, and returns its findings — or null if none exists (first scan of this
 * target) or the target's hostname can't be parsed.
 *
 * Matches by hostname rather than exact target_url: two scans of "the same"
 * site aren't guaranteed byte-identical strings (protocol, trailing slash,
 * case — target_url is stored raw, unnormalised, at scan-creation time).
 *
 * Fetches the 100 most recent completed scans across all of the user's
 * targets and filters client-side, since there's no indexed hostname column
 * to query against directly. Fine at today's scale; if a user regularly runs
 * 100+ scans of other targets between two scans of the same one, the match
 * will be missed and no previous scan can be found — worth revisiting with a
 * proper indexed hostname/target column if that starts happening in practice.
 */
async function findPreviousFindings(
  currentScanId: string,
  currentTargetUrl: string,
  currentCreatedAt: string
): Promise<Finding[] | null> {
  let hostname: string;
  try {
    hostname = new URL(currentTargetUrl).hostname.toLowerCase();
  } catch {
    return null;
  }

  const { data: candidates } = await supabase
    .from("scans")
    .select("id, target_url, created_at, scan_results(results)")
    .eq("status", "completed")
    .neq("id", currentScanId)
    .lt("created_at", currentCreatedAt)
    .order("created_at", { ascending: false })
    .limit(100);

  for (const c of (candidates ?? []) as Array<{
    id: string;
    target_url: string;
    scan_results: { results: { findings?: Finding[] } }[];
  }>) {
    let candidateHost: string;
    try {
      candidateHost = new URL(c.target_url).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (candidateHost !== hostname) continue;
    const prevFindings = c.scan_results?.[0]?.results?.findings;
    if (prevFindings) return prevFindings;
  }

  return null;
}

/**
 * Score history for every completed scan of the same target (by hostname,
 * same reasoning as findPreviousFindings above), oldest first, including the
 * current scan itself so the trend line ends at "now." Capped at 20 points —
 * a trend line, not a full audit log.
 */
async function findScoreHistory(
  currentScanId: string,
  currentTargetUrl: string,
  currentScore: number | null,
  currentCreatedAt: string
): Promise<ScorePoint[]> {
  let hostname: string;
  try {
    hostname = new URL(currentTargetUrl).hostname.toLowerCase();
  } catch {
    return [];
  }

  const { data: candidates } = await supabase
    .from("scans")
    .select("id, target_url, created_at, scan_results(score, created_at)")
    .eq("status", "completed")
    .neq("id", currentScanId)
    .order("created_at", { ascending: false })
    .limit(100);

  const points: ScorePoint[] = [];
  for (const c of (candidates ?? []) as Array<{
    target_url: string;
    scan_results: { score: number | null; created_at: string }[];
  }>) {
    let candidateHost: string;
    try {
      candidateHost = new URL(c.target_url).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (candidateHost !== hostname) continue;
    const result = c.scan_results?.[0];
    if (result?.score == null) continue;
    points.push({ date: result.created_at, score: result.score });
    if (points.length >= 19) break; // + the current scan = 20
  }

  if (currentScore !== null) points.push({ date: currentCreatedAt, score: currentScore });

  return points.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
}

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

    findPreviousFindings(result.scan_id, result.results.target_url, result.created_at)
      .then((previousFindings) => {
        if (previousFindings) setDiff(diffFindings(currentFindings, previousFindings));
      })
      .catch(() => {
        // Non-fatal — the report still renders fully without the New/Fixed filter.
      });
  }, [result]);

  useEffect(() => {
    if (!result?.results?.target_url) return;
    findScoreHistory(result.scan_id, result.results.target_url, result.score, result.created_at)
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
  const bySeverity = (s: Severity) => findings.filter((f) => f.severity === s);
  const critical = bySeverity("critical");
  const high = bySeverity("high");
  const medium = bySeverity("medium");
  const low = bySeverity("low");
  const info = bySeverity("info");
  const allOrdered = [...critical, ...high, ...medium, ...low, ...info];

  // Tag each current finding with its diff status without disturbing the
  // severity ordering above — diff.added/unchanged are re-derived copies, not
  // the same array references, so matching happens by checkId.
  const statusByCheckId = new Map<string, DiffStatus>();
  if (diff) {
    diff.added.forEach((f) => f.checkId && statusByCheckId.set(f.checkId, "new"));
    diff.unchanged.forEach((f) => f.checkId && statusByCheckId.set(f.checkId, "unchanged"));
  }
  const taggedOrdered: (Finding & { status?: DiffStatus })[] = allOrdered.map((f) => ({
    ...f,
    status: f.checkId ? statusByCheckId.get(f.checkId) : undefined,
  }));
  const newOrdered = taggedOrdered.filter((f) => f.status === "new");
  const fixedOrdered = diff ? sortBySeverity(diff.fixed) : [];

  const visibleFindings: (Finding & { status?: DiffStatus })[] =
    filter === "new" ? newOrdered : filter === "fixed" ? fixedOrdered : taggedOrdered;

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
                  {critical.length > 0 && <span className="rounded-full bg-red-400/10 border border-red-400/20 px-2 py-0.5 text-red-400 font-medium">{critical.length} critical</span>}
                  {high.length > 0 && <span className="rounded-full bg-orange-400/10 border border-orange-400/20 px-2 py-0.5 text-orange-400 font-medium">{high.length} high</span>}
                  {medium.length > 0 && <span className="rounded-full bg-yellow-400/10 border border-yellow-400/20 px-2 py-0.5 text-yellow-400 font-medium">{medium.length} medium</span>}
                  {low.length > 0 && <span className="rounded-full bg-blue-400/10 border border-blue-400/20 px-2 py-0.5 text-blue-400 font-medium">{low.length} low</span>}
                  {info.length > 0 && <span className="rounded-full bg-cybertext/5 border border-cyberborder px-2 py-0.5 text-cybertext/60 font-medium">{info.length} info</span>}
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
          {allOrdered.length > 0 || (diff && diff.fixed.length > 0) ? (
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
                  {visibleFindings.map((f, i) => <FindingCard key={f.checkId ?? i} finding={f} />)}
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
          {(critical.length + high.length) > 0 && (
            <div className="no-print rounded-lg border border-orange-400/30 bg-orange-400/10 p-4 text-sm text-orange-400">
              <strong>{critical.length + high.length} critical/high finding{(critical.length + high.length) !== 1 ? "s" : ""} found.</strong>{" "}
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
