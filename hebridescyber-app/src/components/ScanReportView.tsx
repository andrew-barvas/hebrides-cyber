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
import type { DiffStatus } from "@/lib/findingsDiff";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ViewFinding = {
  severity: Severity;
  title: string;
  detail: string;
  remediation?: string;
  checkId?: string;
  status?: DiffStatus;
};

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

export function FindingCard({ finding }: { finding: ViewFinding }) {
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
