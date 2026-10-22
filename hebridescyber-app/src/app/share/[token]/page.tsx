"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ScoreGauge, FindingCard, ExecutiveSummary, type ViewFinding, type Severity } from "@/components/ScanReportView";

type ApiFinding = {
  check_id: string | null;
  severity: Severity;
  title: string;
  detail: string;
  remediation: string | null;
  status: "new" | "unchanged" | null;
  cve_ids?: string[];
  fix_difficulty?: string;
  estimated_fix_minutes?: number;
};

type ApiReport = {
  scan_id: string;
  target_url: string;
  status: string;
  created_at: string;
  completed_at?: string;
  score: number | null;
  summary?: string | null;
  counts?: Record<string, number>;
  findings: ApiFinding[];
  fixed_findings?: Array<{ check_id: string | null; severity: Severity; title: string }>;
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function SharedReportPage() {
  const params = useParams<{ token: string }>();
  const [report, setReport] = useState<ApiReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!params?.token) return;
    (async () => {
      const res = await fetch(`/api/reports/${params.token}`);
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "This share link is invalid or has expired.");
      setReport(body);
    })()
      .catch((err) => setError((err as Error).message))
      .finally(() => setLoading(false));
  }, [params?.token]);

  if (loading) {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center">
        <p className="font-mono text-sm text-cybermuted">// loading shared report…</p>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center text-center px-6">
        <div>
          <p className="text-sm text-red-400">{error ?? "This share link is invalid or has expired."}</p>
          <Link href="/" className="mt-4 inline-block text-sm text-neon underline">← hebridescyber.co.uk</Link>
        </div>
      </div>
    );
  }

  const findings: (ViewFinding & { checkId?: string })[] = [
    ...report.findings.map((f) => ({
      severity: f.severity,
      title: f.title,
      detail: f.detail,
      remediation: f.remediation ?? undefined,
      checkId: f.check_id ?? undefined,
      status: f.status ?? undefined,
      cveIds: f.cve_ids,
      fixDifficulty: f.fix_difficulty as ViewFinding["fixDifficulty"],
      estimatedFixMinutes: f.estimated_fix_minutes,
    })),
    ...(report.fixed_findings ?? []).map((f) => ({
      severity: f.severity,
      title: f.title,
      detail: "",
      checkId: f.check_id ?? undefined,
      status: "fixed" as const,
    })),
  ].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

  const checkedAt = report.completed_at
    ? new Date(report.completed_at).toLocaleString()
    : new Date(report.created_at).toLocaleString();

  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      <div className="bg-grid pointer-events-none fixed inset-0 opacity-20" />

      <div className="relative mx-auto max-w-3xl px-6 py-12 space-y-8">
        <div className="rounded-lg border border-neon/20 bg-neon/5 px-4 py-2 text-xs text-neon">
          Shared read-only report · not editable, no login required to view
        </div>

        <div>
          <p className="font-mono text-xs text-neon/50" aria-hidden="true">$ ./report --shared</p>
          <h1 className="text-2xl font-bold text-cybertext break-all">{report.target_url}</h1>
          <p className="mt-1 text-sm text-cybermuted">Security scan report · {checkedAt}</p>
        </div>

        <div className="flex flex-col items-start gap-6 rounded-xl border border-cyberborder bg-cyberpanel p-6 sm:flex-row sm:items-center">
          {report.score !== null && <ScoreGauge score={report.score} />}
          <div>
            <p className="text-sm font-semibold text-neon mb-1">Summary</p>
            <p className="text-sm text-cybertext/70 leading-relaxed">
              {report.summary ?? "Scan complete. Review findings below."}
            </p>
          </div>
        </div>

        {report.score !== null && <ExecutiveSummary findings={findings} score={report.score} />}

        {findings.length > 0 ? (
          <div>
            <h2 className="mb-4 font-mono text-xs text-cybermuted uppercase tracking-wide">// findings</h2>
            <div className="space-y-3">
              {findings.map((f, i) => <FindingCard key={f.checkId ?? i} finding={f} />)}
            </div>
          </div>
        ) : (
          <div className="rounded-lg border border-neon/20 bg-neon/5 p-5 text-sm text-neon">
            No significant findings detected.
          </div>
        )}

        <div className="pt-4 border-t border-cyberborder text-xs text-cybermuted text-center">
          <p>
            Powered by <Link href="/" className="text-neon hover:underline">Hebrides Cyber</Link> · Findings
            represent a point-in-time snapshot and should be verified before remediation.
          </p>
        </div>
      </div>
    </div>
  );
}
