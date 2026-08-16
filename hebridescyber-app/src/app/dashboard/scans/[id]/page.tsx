"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";

type Severity = "critical" | "high" | "medium" | "low" | "info";

type Finding = {
  severity: Severity;
  title: string;
  detail: string;
};

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
  info:     { label: "Info",     bg: "bg-white/5",       text: "text-white/60",   dot: "bg-white/40",   border: "border-cyberborder" },
};

function ScoreGauge({ score }: { score: number }) {
  const colour = score >= 80 ? "text-neon" : score >= 60 ? "text-yellow-400" : score >= 40 ? "text-orange-400" : "text-red-400";
  const ring   = score >= 80 ? "border-neon" : score >= 60 ? "border-yellow-400" : score >= 40 ? "border-orange-400" : "border-red-400";
  const label  = score >= 80 ? "Good" : score >= 60 ? "Fair" : score >= 40 ? "Poor" : "Critical";
  return (
    <div className={`inline-flex flex-col items-center justify-center rounded-full border-4 ${ring} h-28 w-28 flex-shrink-0`}>
      <span className={`text-4xl font-bold ${colour}`}>{score}</span>
      <span className="text-xs text-white/40">/100 · {label}</span>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const meta = SEVERITY_META[finding.severity] ?? SEVERITY_META.info;
  return (
    <div className={`rounded-lg border ${meta.border} ${meta.bg} p-4`}>
      <div className="mb-1 flex items-center gap-2">
        <span className={`inline-block h-2 w-2 rounded-full flex-shrink-0 ${meta.dot}`} />
        <span className={`text-xs font-semibold uppercase tracking-wide ${meta.text}`}>{meta.label}</span>
      </div>
      <p className="font-medium text-white text-sm">{finding.title}</p>
      {finding.detail && <p className="mt-1 text-xs text-white/60 leading-relaxed">{finding.detail}</p>}
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
        <p className="text-sm font-medium text-white/80">{label}</p>
        <p className="text-xs text-white/40">{detail}</p>
      </div>
    </div>
  );
}

export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  if (loading) {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center">
        <p className="font-mono text-sm text-white/30">// loading scan report…</p>
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
        <p className="text-sm text-white/50">
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

      <div className="bg-cyberbg min-h-screen text-white print:bg-white print:text-slate-800">
        <div className="bg-grid pointer-events-none fixed inset-0 opacity-20 print:hidden" />

        <div className="relative mx-auto max-w-3xl px-6 py-12 space-y-8 print:py-0 print:space-y-6">
          {/* Header */}
          <div>
            <Link
              href="/dashboard"
              className="no-print inline-block mb-3 font-mono text-xs text-white/40 hover:text-neon transition-colors"
            >
              ← Back to dashboard
            </Link>
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="font-mono text-xs text-neon/50" aria-hidden="true">$ ./report</p>
                <h1 className="text-2xl font-bold text-white break-all print:text-slate-800">{targetUrl}</h1>
                <p className="mt-1 text-sm text-white/40 print:text-slate-500">Security scan report · {checkedAt}</p>
              </div>
              <button
                onClick={() => window.print()}
                className="no-print shrink-0 rounded-md border border-cyberborder px-4 py-2 text-sm font-medium text-white/60 hover:border-neon hover:text-neon transition-colors"
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
              <p className="text-sm text-white/70 leading-relaxed print:text-slate-600">
                {result.summary ?? "Scan complete. Review findings below."}
              </p>
              {findings.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-2 text-xs">
                  {critical.length > 0 && <span className="rounded-full bg-red-400/10 border border-red-400/20 px-2 py-0.5 text-red-400 font-medium">{critical.length} critical</span>}
                  {high.length > 0 && <span className="rounded-full bg-orange-400/10 border border-orange-400/20 px-2 py-0.5 text-orange-400 font-medium">{high.length} high</span>}
                  {medium.length > 0 && <span className="rounded-full bg-yellow-400/10 border border-yellow-400/20 px-2 py-0.5 text-yellow-400 font-medium">{medium.length} medium</span>}
                  {low.length > 0 && <span className="rounded-full bg-blue-400/10 border border-blue-400/20 px-2 py-0.5 text-blue-400 font-medium">{low.length} low</span>}
                  {info.length > 0 && <span className="rounded-full bg-white/5 border border-cyberborder px-2 py-0.5 text-white/60 font-medium">{info.length} info</span>}
                </div>
              )}
            </div>
          </div>

          {/* Check breakdown */}
          <div>
            <h2 className="mb-3 font-mono text-xs text-white/40 uppercase tracking-wide">// check breakdown</h2>
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
          {allOrdered.length > 0 ? (
            <div>
              <h2 className="mb-4 font-mono text-xs text-white/40 uppercase tracking-wide">// findings</h2>
              <div className="space-y-3">
                {allOrdered.map((f, i) => <FindingCard key={i} finding={f} />)}
              </div>
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
              <Link href="/services" className="underline hover:text-white">see how it works</Link>.
            </div>
          )}

          {/* Score badge embed */}
          <div className="no-print rounded-xl border border-cyberborder bg-cyberpanel p-5">
            <p className="font-mono text-xs text-white/40 uppercase tracking-wide mb-3">// embed your score badge</p>
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
