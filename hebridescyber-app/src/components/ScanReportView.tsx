"use client";

// Presentational pieces shared by the authenticated scan report page
// (src/app/dashboard/scans/[id]/page.tsx) and the public share page
// (src/app/share/[token]/page.tsx). Extracted rather than duplicated once a
// second consumer needed the exact same finding-card/remediation-markdown
// rendering — see docs/PLATFORM-ROADMAP.md's shareable-report-links entry.
//
// Deliberately NOT exported here: the "check breakdown" section (TLS/headers/
// DNS/exposure pass-fail rows). That data lives in the raw scan_results.results
// jsonb, which the public share API (src/lib/scanReport.ts's ScanReport) never
// includes — only score/summary/counts/findings. The public view is a reduced
// view by design, not a 1:1 mirror of the owner's dashboard.
import { useState } from "react";
import type { DiffStatus, FindingsDiff } from "@/lib/findingsDiff";
import { COMPLIANCE_FRAMEWORK_LABELS, type ComplianceRef } from "@/lib/scanners/compliance";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ViewFinding = {
  severity: Severity;
  title: string;
  detail: string;
  remediation?: string;
  checkId?: string;
  status?: DiffStatus;
  cveIds?: string[];
  complianceRefs?: ComplianceRef[];
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function sortFindingsBySeverity<T extends { severity: Severity }>(list: T[]): T[] {
  return [...list].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

export type FindingsFilter = "all" | "new" | "fixed";

/**
 * Severity-orders `findings`, tags each with its New/Fixed/Unchanged status
 * against `diff` (matching by checkId — see diffFindings), and returns the
 * subset matching `filter`. Shared by the scan report page and the dashboard
 * overview so both render the exact same New/Fixed semantics rather than two
 * copies that could drift.
 */
export function buildFindingsView(
  findings: ViewFinding[],
  diff: FindingsDiff | null,
  filter: FindingsFilter
): ViewFinding[] {
  const allOrdered = sortFindingsBySeverity(findings);

  const statusByCheckId = new Map<string, DiffStatus>();
  if (diff) {
    diff.added.forEach((f) => f.checkId && statusByCheckId.set(f.checkId, "new"));
    diff.unchanged.forEach((f) => f.checkId && statusByCheckId.set(f.checkId, "unchanged"));
  }
  const taggedOrdered: ViewFinding[] = allOrdered.map((f) => ({
    ...f,
    status: f.checkId ? statusByCheckId.get(f.checkId) : undefined,
  }));

  if (filter === "new") return taggedOrdered.filter((f) => f.status === "new");
  if (filter === "fixed") return diff ? sortFindingsBySeverity(diff.fixed) : [];
  return taggedOrdered;
}

export const SEVERITY_META: Record<Severity, { label: string; bg: string; text: string; dot: string; border: string }> = {
  critical: { label: "Critical", bg: "bg-red-400/10",    text: "text-red-400",    dot: "bg-red-400",    border: "border-red-400/20" },
  high:     { label: "High",     bg: "bg-orange-400/10", text: "text-orange-400", dot: "bg-orange-400", border: "border-orange-400/20" },
  medium:   { label: "Medium",   bg: "bg-yellow-400/10", text: "text-yellow-400", dot: "bg-yellow-400", border: "border-yellow-400/20" },
  low:      { label: "Low",      bg: "bg-blue-400/10",   text: "text-blue-400",   dot: "bg-blue-400",   border: "border-blue-400/20" },
  info:     { label: "Info",     bg: "bg-cybertext/5",       text: "text-cybertext/60",   dot: "bg-cybertext/40",   border: "border-cyberborder" },
};

export function ScoreGauge({ score }: { score: number }) {
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

/**
 * On-demand "AI-tailored fix" — a separate, explicit fetch from the static
 * remediation already rendered above it, since the static text is free
 * (baked into src/lib/scanners/remediationText.ts) while this calls Azure
 * OpenAI per click. Only rendered when the caller supplies scanId+token
 * (the authenticated dashboard), never on the public share page — see
 * src/pages/api/scans/[id]/ai-fix.ts, which requires the scan owner's
 * credentials anyway, so this is belt-and-suspenders rather than the only
 * guard.
 */
function AiTailoredFix({ scanId, token, checkId }: { scanId: string; token: string; checkId: string }) {
  const [status, setStatus] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [guidance, setGuidance] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function request() {
    setStatus("loading");
    setError(null);
    try {
      const res = await fetch(`/api/scans/${scanId}/ai-fix`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ checkId }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not generate AI-tailored fix");
      setGuidance(body.guidance);
      setStatus("done");
    } catch (err) {
      setError((err as Error).message);
      setStatus("error");
    }
  }

  if (status === "idle") {
    return (
      <button
        onClick={request}
        className="mt-3 text-xs font-semibold text-neon hover:text-neon/80 print:hidden"
      >
        ✨ Get an AI-tailored fix for your stack
      </button>
    );
  }

  return (
    <div className="mt-3 border-l-2 border-neon/30 pl-3 print:hidden">
      <p className="mb-2 text-xs font-semibold text-neon">✨ AI-tailored fix</p>
      {status === "loading" && <p className="text-xs text-cybertext/40">Generating…</p>}
      {status === "error" && (
        <div>
          <p className="text-xs text-red-400">{error}</p>
          <button onClick={request} className="mt-1 text-xs font-medium text-neon hover:underline">
            Try again
          </button>
        </div>
      )}
      {status === "done" && guidance && <RemediationBody markdown={guidance} />}
    </div>
  );
}

export function FindingCard({
  finding,
  scanId,
  token,
}: {
  finding: ViewFinding;
  /** Owner-only — omit on the public share page. Enables the AI-tailored-fix button. */
  scanId?: string;
  token?: string;
}) {
  const meta = SEVERITY_META[finding.severity] ?? SEVERITY_META.info;

  // A resolved finding is good news — de-emphasised rather than alarming, so
  // it doesn't compete visually with the still-open findings above it.
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

      {finding.cveIds && finding.cveIds.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {finding.cveIds.map((cve) => (
            <a
              key={cve}
              href={`https://nvd.nist.gov/vuln/detail/${cve}`}
              target="_blank"
              rel="noopener noreferrer"
              className="rounded border border-cyberborder px-1.5 py-0.5 font-mono text-[10px] text-cybertext/60 hover:border-neon hover:text-neon transition-colors print:text-slate-500"
            >
              {cve} ↗
            </a>
          ))}
        </div>
      )}

      {finding.complianceRefs && finding.complianceRefs.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {finding.complianceRefs.map((ref) => (
            <span
              key={`${ref.framework}:${ref.control}`}
              title={ref.control}
              className="rounded-full border border-cyberborder bg-cyberbg/60 px-1.5 py-0.5 text-[10px] text-cybertext/50 print:text-slate-500"
            >
              {COMPLIANCE_FRAMEWORK_LABELS[ref.framework]}
            </span>
          ))}
        </div>
      )}

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
          {scanId && token && finding.checkId && (
            <AiTailoredFix scanId={scanId} token={token} checkId={finding.checkId} />
          )}
        </details>
      )}
    </div>
  );
}

// Cyber Essentials' own 5 control themes (NCSC scheme) — not this codebase's
// invention, so listed verbatim rather than derived from anything else.
const CYBER_ESSENTIALS_CONTROLS = [
  "Firewalls and internet gateways",
  "Secure configuration",
  "Security update management",
  "User access control",
  "Malware protection",
];

/**
 * Cyber Essentials-specific breakdown — singled out from the general
 * complianceRefs badges on each finding because it's the one framework with
 * genuine UK small-business relevance for this product. Deliberately worded
 * as an "automated indicator," never a certification claim: real Cyber
 * Essentials certification is a formal self-assessment (or Plus, an
 * external audit) against NCSC's own questionnaire, which this scan does
 * not perform and cannot substitute for.
 *
 * Returns null when no open finding maps to any framework yet (e.g. a scan
 * stored before complianceRefs existed) — a report with the section but
 * zero real data behind it would be misleading, not just incomplete.
 */
export function ComplianceSummary({ findings }: { findings: ViewFinding[] }) {
  // A fixed finding shouldn't count against a control area that's since
  // been addressed — only open findings inform this breakdown.
  const open = findings.filter((f) => f.status !== "fixed");
  const anyMapped = open.some((f) => (f.complianceRefs?.length ?? 0) > 0);
  if (!anyMapped) return null;

  const controlHasFinding = new Map<string, boolean>(CYBER_ESSENTIALS_CONTROLS.map((c) => [c, false]));
  for (const f of open) {
    for (const ref of f.complianceRefs ?? []) {
      if (ref.framework === "cyber-essentials") controlHasFinding.set(ref.control, true);
    }
  }

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <p className="mb-1 text-sm font-semibold text-cybertext">Cyber Essentials control areas</p>
      <p className="mb-4 text-xs text-cybertext/50">
        An automated indicator based on this scan&rsquo;s findings — not a Cyber Essentials certification. Real
        certification is a formal self-assessment (or, for Plus, an external audit) against NCSC&rsquo;s own
        questionnaire.
      </p>
      <div className="grid gap-2 sm:grid-cols-2">
        {CYBER_ESSENTIALS_CONTROLS.map((control) => {
          const hasFinding = controlHasFinding.get(control);
          return (
            <div key={control} className="flex items-center gap-2 rounded-lg border border-cyberborder bg-cyberbg/50 p-3">
              <span className={`text-sm font-bold ${hasFinding ? "text-red-400" : "text-neon"}`}>{hasFinding ? "✗" : "✓"}</span>
              <span className="text-xs text-cybertext/70">{control}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function CheckRow({ label, pass, detail }: { label: string; pass: boolean | undefined; detail: string }) {
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
