"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";
import { diffFindings, type FindingsDiff, type DiffStatus } from "@/lib/findingsDiff";

type Severity = "critical" | "high" | "medium" | "low" | "info";

type Finding = {
  severity: Severity;
  title: string;
  detail: string;
  // Absent on scans stored before remediation text was added — always guard.
  remediation?: string;
  // Absent on scans stored before finding identity existed — always guard.
  // See the same field on scanners/index.ts's Finding for the full rationale.
  checkId?: string;
};

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

const SEVERITY_META: Record<Severity, { label: string; bg: string; text: string; dot: string; border: string }> = {
  critical: { label: "Critical", bg: "bg-red-400/10",    text: "text-red-400",    dot: "bg-red-400",    border: "border-red-400/20" },
  high:     { label: "High",     bg: "bg-orange-400/10", text: "text-orange-400", dot: "bg-orange-400", border: "border-orange-400/20" },
  medium:   { label: "Medium",   bg: "bg-yellow-400/10", text: "text-yellow-400", dot: "bg-yellow-400", border: "border-yellow-400/20" },
  low:      { label: "Low",      bg: "bg-blue-400/10",   text: "text-blue-400",   dot: "bg-blue-400",   border: "border-blue-400/20" },
  info:     { label: "Info",     bg: "bg-cybertext/5",       text: "text-cybertext/60",   dot: "bg-cybertext/40",   border: "border-cyberborder" },
};

function ScoreGauge({ score }: { score: number }) {
  const colour = score >= 80 ? "text-neon" : score >= 60 ? "text-yellow-400" : score >= 40 ? "text-orange-400" : "text-red-400";
  const ring   = score >= 80 ? "border-neon" : score >= 60 ? "border-yellow-400" : score >= 40 ? "border-orange-400" : "border-red-400";
  const label  = score >= 80 ? "Good" : score >= 60 ? "Fair" : score >= 40 ? "Poor" : "Critical";
  return (
    <div className={`inline-flex flex-col items-center justify-center rounded-full border-4 ${ring} h-28 w-28 flex-shrink-0`}>
      <span className={`text-4xl font-bold ${colour}`}>{score}</span>
      <span className="text-xs text-cybertext/40">/100 · {label}</span>
    </div>
  );
}

/**
 * Renders the small Markdown subset used by remediation text: fenced code
 * blocks, bullet lists, and inline `code` / **bold**. Deliberately not a full
 * Markdown parser — the input is our own constants in
 * src/lib/scanners/remediationText.ts, never user content.
 */
function RemediationBody({ markdown }: { markdown: string }) {
  // Split on fences, keeping them: even indexes are prose, odd are code.
  const segments = markdown.split(/```(?:[a-z]*)\n?/);

  return (
    <div className="space-y-3">
      {segments.map((segment, i) => {
        if (!segment.trim()) return null;

        if (i % 2 === 1) {
          return (
            <pre
              key={i}
              className="overflow-x-auto rounded-md border border-cyberborder bg-cyberbg p-3 font-mono text-[11px] leading-relaxed text-neon print:border-slate-300 print:bg-slate-50 print:text-slate-800"
            >
              <code>{segment.replace(/\n$/, "")}</code>
            </pre>
          );
        }

        return (
          <div key={i} className="space-y-2">
            {segment
              .split(/\n{2,}/)
              .filter((block) => block.trim())
              .map((block, j) => {
                const lines = block.split("\n").filter((l) => l.trim());
                const isList = lines.every((l) => /^\s*[-*\d]/.test(l));

                if (isList) {
                  return (
                    <ul key={j} className="list-disc space-y-1 pl-5 text-xs leading-relaxed text-cybertext/70 print:text-slate-700">
                      {lines.map((line, k) => (
                        <li key={k}>{renderInline(line.replace(/^\s*(?:[-*]|\d+\.)\s*/, ""))}</li>
                      ))}
                    </ul>
                  );
                }

                return (
                  <p key={j} className="text-xs leading-relaxed text-cybertext/70 print:text-slate-700">
                    {renderInline(block.replace(/\n/g, " "))}
                  </p>
                );
              })}
          </div>
        );
      })}
    </div>
  );
}

/** Handles **bold** and `code` spans within a line. */
function renderInline(text: string) {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return (
        <strong key={i} className="font-semibold text-cybertext/90 print:text-slate-900">
          {part.slice(2, -2)}
        </strong>
      );
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code
          key={i}
          className="rounded bg-cyberbg px-1 py-0.5 font-mono text-[11px] text-neon print:bg-slate-100 print:text-slate-800"
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    return part;
  });
}

function FindingCard({ finding }: { finding: Finding & { status?: DiffStatus } }) {
  const meta = SEVERITY_META[finding.severity] ?? SEVERITY_META.info;

  // A resolved finding is good news — de-emphasised rather than alarming,
  // so it doesn't compete visually with the still-open findings above it.
  if (finding.status === "fixed") {
    return (
      <div className="rounded-lg border border-cyberborder bg-cyberbg/40 p-4">
        <div className="mb-1 flex items-center gap-2">
          <span className="text-sm text-neon">✓</span>
          <span className="text-xs font-semibold uppercase tracking-wide text-cybertext/40">Fixed</span>
        </div>
        <p className="text-sm text-cybertext/50 line-through decoration-cybertext/30">{finding.title}</p>
      </div>
    );
  }

  return (
    <div className={`rounded-lg border ${meta.border} ${meta.bg} p-4`}>
      <div className="mb-1 flex items-center gap-2">
        <span className={`inline-block h-2 w-2 rounded-full flex-shrink-0 ${meta.dot}`} />
        <span className={`text-xs font-semibold uppercase tracking-wide ${meta.text}`}>{meta.label}</span>
        {finding.status === "new" && (
          <span className="rounded-full border border-neon/30 bg-neon/10 px-1.5 py-0.5 text-[10px] font-semibold text-neon">NEW</span>
        )}
      </div>
      <p className="font-medium text-cybertext text-sm">{finding.title}</p>
      {finding.detail && <p className="mt-1 text-xs text-cybertext/60 leading-relaxed">{finding.detail}</p>}

      {finding.remediation && (
        // .remediation-details is force-expanded in print — see globals.css, so
        // the PDF export always contains the fix steps.
        <details className="group remediation-details mt-3">
          <summary className="cursor-pointer list-none text-xs font-semibold text-neon hover:text-neon/80 print:hidden">
            <span className="inline-block transition-transform group-open:rotate-90">▸</span> How to fix
          </summary>
          <p className="hidden text-xs font-semibold text-slate-900 print:block">How to fix</p>
          <div className="mt-3 border-l-2 border-cyberborder pl-3 print:border-slate-300">
            <RemediationBody markdown={finding.remediation} />
          </div>
        </details>
      )}
    </div>
  );
}

function CheckRow({ label, pass, detail }: { label: string; pass: boolean | undefined; detail: string }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-cyberborder bg-cyberbg/50 p-3">
      <span className={`mt-0.5 flex-shrink-0 text-sm font-bold ${pass ? "text-neon" : "text-red-400"}`}>
        {pass ? "✓" : "✗"}
      </span>
      <div>
        <p className="text-sm font-medium text-cybertext/80">{label}</p>
        <p className="text-xs text-cybertext/40">{detail}</p>
      </div>
    </div>
  );
}

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

export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [diff, setDiff] = useState<FindingsDiff | null>(null);
  const [filter, setFilter] = useState<"all" | "new" | "fixed">("all");

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
