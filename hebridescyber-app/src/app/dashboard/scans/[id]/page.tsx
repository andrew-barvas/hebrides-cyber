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

const SEVERITY_META: Record<Severity, { label: string; bg: string; text: string; dot: string; printBg: string }> = {
  critical: { label: "Critical", bg: "bg-red-50",    text: "text-red-800",    dot: "bg-red-500",    printBg: "#fef2f2" },
  high:     { label: "High",     bg: "bg-orange-50", text: "text-orange-800", dot: "bg-orange-400", printBg: "#fff7ed" },
  medium:   { label: "Medium",   bg: "bg-yellow-50", text: "text-yellow-800", dot: "bg-yellow-400", printBg: "#fefce8" },
  low:      { label: "Low",      bg: "bg-blue-50",   text: "text-blue-800",   dot: "bg-blue-400",   printBg: "#eff6ff" },
  info:     { label: "Info",     bg: "bg-slate-50",  text: "text-slate-700",  dot: "bg-slate-400",  printBg: "#f8fafc" },
};

function ScoreGauge({ score }: { score: number }) {
  const colour = score >= 80 ? "text-green-600" : score >= 60 ? "text-yellow-600" : score >= 40 ? "text-orange-600" : "text-red-600";
  const ring   = score >= 80 ? "border-green-400" : score >= 60 ? "border-yellow-400" : score >= 40 ? "border-orange-400" : "border-red-400";
  const label  = score >= 80 ? "Good" : score >= 60 ? "Fair" : score >= 40 ? "Poor" : "Critical";
  return (
    <div className={`inline-flex flex-col items-center justify-center rounded-full border-4 ${ring} h-28 w-28 flex-shrink-0`}>
      <span className={`text-4xl font-bold ${colour}`}>{score}</span>
      <span className="text-xs text-slate-400">/100 · {label}</span>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const meta = SEVERITY_META[finding.severity] ?? SEVERITY_META.info;
  return (
    <div className={`rounded-lg border border-slate-200 ${meta.bg} p-4`}>
      <div className="mb-1 flex items-center gap-2">
        <span className={`inline-block h-2 w-2 rounded-full flex-shrink-0 ${meta.dot}`} />
        <span className={`text-xs font-semibold uppercase tracking-wide ${meta.text}`}>{meta.label}</span>
      </div>
      <p className="font-medium text-slate-800 text-sm">{finding.title}</p>
      {finding.detail && <p className="mt-1 text-xs text-slate-600 leading-relaxed">{finding.detail}</p>}
    </div>
  );
}

function CheckRow({ label, pass, detail }: { label: string; pass: boolean | undefined; detail: string }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-slate-200 bg-white p-3">
      <span className={`mt-0.5 flex-shrink-0 text-sm font-bold ${pass ? "text-green-600" : "text-red-500"}`}>
        {pass ? "✓" : "✗"}
      </span>
      <div>
        <p className="text-sm font-medium text-slate-700">{label}</p>
        <p className="text-xs text-slate-400">{detail}</p>
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

  if (loading) return <div className="px-6 py-16 text-center text-sm text-slate-400">Loading scan report…</div>;
  if (error)   return <div className="px-6 py-16 text-center text-sm text-red-600">{error}</div>;
  if (!result) {
    return (
      <div className="px-6 py-16 text-center text-sm text-slate-500">
        No results yet — the scan may still be running.{" "}
        <Link href="/dashboard" className="underline">← Dashboard</Link>
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
      {/* Print-only styles — keeps the PDF clean and readable */}
      <style>{`
        @media print {
          body { font-family: system-ui, sans-serif; color: #1e293b; background: #fff; }
          .no-print { display: none !important; }
          .page-break-before { page-break-before: always; }
          a { color: inherit; text-decoration: none; }
          .print-border { border: 1px solid #e2e8f0; border-radius: 8px; }
        }
        @page { margin: 1.5cm; }
      `}</style>

      <div className="mx-auto max-w-3xl px-6 py-12 space-y-8 print:py-0 print:space-y-6">
        {/* Header — visible on screen and in print */}
        <div>
          <Link href="/dashboard" className="no-print text-xs text-slate-400 hover:text-atlantic">← Back to dashboard</Link>
          <div className="mt-2 flex items-center justify-between gap-4">
            <div>
              <h1 className="text-2xl font-bold text-atlantic break-all">{targetUrl}</h1>
              <p className="mt-1 text-sm text-slate-400">Security scan report · {checkedAt}</p>
            </div>
            <button
              onClick={() => window.print()}
              className="no-print flex-shrink-0 rounded-md border border-slate-200 px-4 py-2 text-sm font-medium text-slate-600 hover:border-atlantic hover:text-atlantic"
            >
              ↓ Download PDF
            </button>
          </div>
        </div>

        {/* Score + summary */}
        <div className="flex flex-col items-start gap-6 rounded-xl border border-slate-200 bg-white p-6 shadow-sm sm:flex-row sm:items-center">
          {result.score !== null && <ScoreGauge score={result.score} />}
          <div>
            <p className="text-sm font-semibold text-atlantic mb-1">Executive summary</p>
            <p className="text-sm text-slate-600 leading-relaxed">
              {result.summary ?? "Scan complete. Review findings below."}
            </p>
            {findings.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-2 text-xs">
                {critical.length > 0 && <span className="rounded-full bg-red-100 px-2 py-0.5 text-red-700 font-medium">{critical.length} critical</span>}
                {high.length > 0 && <span className="rounded-full bg-orange-100 px-2 py-0.5 text-orange-700 font-medium">{high.length} high</span>}
                {medium.length > 0 && <span className="rounded-full bg-yellow-100 px-2 py-0.5 text-yellow-700 font-medium">{medium.length} medium</span>}
                {low.length > 0 && <span className="rounded-full bg-blue-100 px-2 py-0.5 text-blue-700 font-medium">{low.length} low</span>}
                {info.length > 0 && <span className="rounded-full bg-slate-100 px-2 py-0.5 text-slate-600 font-medium">{info.length} info</span>}
              </div>
            )}
          </div>
        </div>

        {/* Check breakdown */}
        <div>
          <h2 className="mb-3 text-sm font-semibold text-atlantic">Check breakdown</h2>
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
            <h2 className="mb-4 text-lg font-semibold text-atlantic">Findings</h2>
            <div className="space-y-3">
              {allOrdered.map((f, i) => <FindingCard key={i} finding={f} />)}
            </div>
          </div>
        ) : (
          <div className="rounded-lg border border-green-200 bg-green-50 p-5 text-sm text-green-800">
            No significant findings detected. TLS, headers, DNS authentication, and common exposure paths all checked out.
          </div>
        )}

        {/* Remediation note */}
        {(critical.length + high.length) > 0 && (
          <div className="rounded-lg border border-orange-200 bg-orange-50 p-4 text-sm text-orange-800 no-print">
            <strong>{critical.length + high.length} critical/high finding{(critical.length + high.length) !== 1 ? "s" : ""} found.</strong>{" "}
            Hebrides Cyber can open remediation PRs directly in your repository — contact us or{" "}
            <Link href="/services" className="underline">see how it works</Link>.
          </div>
        )}

        {/* Footer for print */}
        <div className="hidden print:block mt-8 pt-4 border-t border-slate-200 text-xs text-slate-400 text-center">
          <p>Generated by Hebrides Cyber Security Score · hebridescyber.com · {checkedAt}</p>
          <p className="mt-1">This report should be treated as confidential. Findings represent a point-in-time snapshot and should be verified before remediation.</p>
        </div>

        {/* Embed badge — screen only */}
        <div className="no-print rounded-lg border border-slate-200 bg-slate-50 p-4">
          <p className="text-sm font-medium text-atlantic mb-2">Embed your score badge</p>
          <code className="block break-all rounded bg-white border border-slate-200 p-2 text-xs text-slate-600">
            {`<img src="https://hebridescyber.com/api/badge/${result.scan_id}.svg" alt="Security Score ${result.score ?? '?'}/100" />`}
          </code>
        </div>
      </div>
    </>
  );
}
