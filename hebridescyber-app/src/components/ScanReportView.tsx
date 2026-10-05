"use client";

// Presentational pieces shared by the authenticated scan report page
// (src/app/dashboard/scans/[id]/page.tsx) and the public share page
// (src/app/share/[token]/page.tsx). Extracted rather than duplicated once a
// second consumer needed the exact same finding-card/remediation-markdown
// rendering — see docs/decisions/ENGINEERING-LOG-2026-08.md's shareable-report-links entry.
//
// Deliberately NOT exported here: the "check breakdown" section (TLS/headers/
// DNS/exposure pass-fail rows). That data lives in the raw scan_results.results
// jsonb, which the public share API (src/lib/scanReport.ts's ScanReport) never
// includes — only score/summary/counts/findings. The public view is a reduced
// view by design, not a 1:1 mirror of the owner's dashboard.
import { useState } from "react";
import type { DiffStatus, FindingsDiff } from "@/lib/findingsDiff";
import { COMPLIANCE_FRAMEWORK_LABELS, ALL_CONTROLS_BY_FRAMEWORK, type ComplianceRef, type ComplianceFramework } from "@/lib/scanners/compliance";
import { isExtendedToolFinding } from "@/lib/extendedToolCheckIds";
import { computeCriticalPaths } from "@/lib/attackPathAnalysis";
import type { FixDifficulty } from "@/lib/scanners/fixDifficulty";
import { TRIAGE_STATE_LABELS } from "@/lib/findingTriage";
import { corroboratingTools } from "@/lib/findingConsolidation";
import { TriageMenu, UndoTriageButton, describeTriage, type ViewTriage } from "./FindingTriage";

export type { ViewTriage } from "./FindingTriage";
import type { ScriptFoundBy, ScriptIntegrity, ScriptInventoryResult } from "@/lib/scanners/scriptInventory";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert } from "@/components/ui/alert";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ViewFinding = {
  severity: Severity;
  title: string;
  detail: string;
  remediation?: string;
  checkId?: string;
  status?: DiffStatus;
  cveIds?: string[];
  /** Other tools that reported the same issue — see src/lib/findingConsolidation.ts. */
  corroboratedBy?: Array<{ tool: string; checkId: string; title: string }>;
  complianceRefs?: ComplianceRef[];
  fixDifficulty?: FixDifficulty;
  estimatedFixMinutes?: number;
  cvssScore?: number;
  cvssVector?: string;
  /** CISA KEV + FIRST EPSS, for CVE-backed findings — see scanners/threatIntel.ts. */
  threatIntel?: {
    knownExploited: boolean;
    kevCveIds?: string[];
    ransomware?: boolean;
    epss?: number;
    epssPercentile?: number;
  };
  /** The owner's active triage (accepted / false positive / snoozed) — see
   *  src/lib/findingTriage.ts. Only ever set on the owner's dashboard. */
  triage?: ViewTriage;
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const FIX_DIFFICULTY_META: Record<FixDifficulty, { label: string; time: string; text: string; bg: string; border: string }> = {
  trivial: { label: "Trivial", time: "~15 min", text: "text-neon", bg: "bg-neon/10", border: "border-neon/30" },
  easy: { label: "Easy", time: "~1 hr", text: "text-blue-400", bg: "bg-blue-400/10", border: "border-blue-400/30" },
  moderate: { label: "Moderate", time: "~4 hrs", text: "text-yellow-400", bg: "bg-yellow-400/10", border: "border-yellow-400/30" },
  hard: { label: "Hard", time: "~2 days", text: "text-red-400", bg: "bg-red-400/10", border: "border-red-400/30" },
};

/** Within a severity: known-exploited first, then by EPSS likelihood. A
 *  library flaw in CISA's KEV catalog is a more urgent fix than an equally
 *  severe one nobody is using — the order is the prioritisation. */
function exploitRank(f: { threatIntel?: ViewFinding["threatIntel"] }): number {
  return (f.threatIntel?.knownExploited ? 2 : 0) + (f.threatIntel?.epss ?? 0);
}

export function sortFindingsBySeverity<T extends { severity: Severity; threatIntel?: ViewFinding["threatIntel"] }>(list: T[]): T[] {
  return [...list].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || exploitRank(b) - exploitRank(a)
  );
}

export function formatEpss(epss: number): string {
  const pct = epss * 100;
  return pct >= 10 ? `${Math.round(pct)}%` : pct >= 1 ? `${pct.toFixed(1)}%` : "<1%";
}

export type FindingsFilter = "all" | "new" | "fixed";

/**
 * Severity-orders `findings`, tags each with its New/Fixed/Unchanged status
 * against `diff` (matching by checkId — see diffFindings), and returns the
 * subset matching `filter`. Shared by the scan report page and the dashboard
 * overview so both render the exact same New/Fixed semantics rather than two
 * copies that could drift. With `triage` (active triage by checkId), each
 * still-present finding also carries its triage.
 */
export function buildFindingsView(
  findings: ViewFinding[],
  diff: FindingsDiff | null,
  filter: FindingsFilter,
  triage?: ReadonlyMap<string, ViewTriage>
): ViewFinding[] {
  const allOrdered = sortFindingsBySeverity(findings);

  const statusByCheckId = new Map<string, DiffStatus>();
  if (diff) {
    diff.added.forEach((f) => f.checkId && statusByCheckId.set(f.checkId, "new"));
    diff.unchanged.forEach((f) => f.checkId && statusByCheckId.set(f.checkId, "unchanged"));
  }
  const taggedOrdered: ViewFinding[] = allOrdered.map((f) => {
    const t = f.checkId ? triage?.get(f.checkId) : undefined;
    return { ...f, status: f.checkId ? statusByCheckId.get(f.checkId) : undefined, ...(t ? { triage: t } : {}) };
  });

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
                // GFM-style pipe table: every line starts with "|", and the
                // second line is a header/body separator ("|---|---|",
                // optionally with ":" alignment markers). Used by
                // remediationText.ts's SPF_ISSUES/DKIM_NOT_DETECTED
                // provider-reference tables — without this, a table falls
                // through to the plain-paragraph branch below and renders
                // as one garbled run-on line of pipe characters.
                const isTable =
                  lines.length >= 2 &&
                  lines.every((l) => l.trim().startsWith("|")) &&
                  /^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?$/.test(lines[1].trim());

                if (isTable) {
                  const cellsOf = (line: string) =>
                    line
                      .trim()
                      .replace(/^\|/, "")
                      .replace(/\|$/, "")
                      .split("|")
                      .map((cell) => cell.trim());
                  const [headerRow, , ...bodyRows] = lines.map(cellsOf);

                  return (
                    <div key={j} className="overflow-x-auto">
                      <table className="w-full border-collapse text-xs">
                        <thead>
                          <tr className="border-b border-cyberborder text-left">
                            {headerRow.map((cell, ci) => (
                              <th key={ci} className="py-1 pr-4 font-semibold text-cybertext/80 print:text-slate-900">
                                {renderInline(cell)}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {bodyRows.map((row, ri) => (
                            <tr key={ri} className="border-b border-cyberborder/40 last:border-0">
                              {row.map((cell, ci) => (
                                <td key={ci} className="py-1 pr-4 text-cybertext/70 print:text-slate-700">
                                  {renderInline(cell)}
                                </td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  );
                }

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

/**
 * "Create ticket" — only rendered when the caller has already confirmed a
 * ticket integration exists (hasTicketIntegration), so this component itself
 * never needs to know whether it's Jira or Linear underneath — see
 * src/pages/api/scans/[id]/create-ticket.ts, which picks that up server-side
 * from the owner's saved integration. Dashboard-only, same reasoning as
 * AiTailoredFix.
 */
function CreateTicketButton({ scanId, token, checkId }: { scanId: string; token: string; checkId: string }) {
  const [status, setStatus] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [ticketUrl, setTicketUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function request() {
    setStatus("loading");
    setError(null);
    try {
      const res = await fetch(`/api/scans/${scanId}/create-ticket`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ checkId }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not create ticket");
      setTicketUrl(body.url);
      setStatus("done");
    } catch (err) {
      setError((err as Error).message);
      setStatus("error");
    }
  }

  if (status === "idle") {
    return (
      <button onClick={request} className="mt-3 ml-4 text-xs font-semibold text-neon hover:text-neon/80 print:hidden">
        🎫 Create ticket
      </button>
    );
  }
  if (status === "loading") {
    return <p className="mt-3 ml-4 text-xs text-cybertext/40 print:hidden">Creating ticket…</p>;
  }
  if (status === "error") {
    return (
      <div className="mt-3 ml-4 print:hidden">
        <p className="text-xs text-red-400">{error}</p>
        <button onClick={request} className="mt-1 text-xs font-medium text-neon hover:underline">
          Try again
        </button>
      </div>
    );
  }
  return (
    <a
      href={ticketUrl ?? "#"}
      target="_blank"
      rel="noopener noreferrer"
      className="mt-3 ml-4 inline-block text-xs font-semibold text-neon hover:underline print:hidden"
    >
      🎫 Ticket created — view it ↗
    </a>
  );
}

/**
 * "Recheck now" — E-30 (docs/ENHANCEMENTS.md), harvested from Closed Door
 * Security's PTaaS retest loop. Triggers a real on-demand rescan (the same
 * fast, base-suite-only path any "Scan now" click already runs — see
 * src/pages/api/scans/[id]/retest-finding.ts's header) and reports whether
 * THIS finding specifically came back fixed, without making the customer
 * navigate away and compare two full reports themselves.
 *
 * Not rendered at all for an extended-tool finding (nuclei/sqlmap/xsser/
 * commix/etc. — see src/lib/extendedToolCheckIds.ts) — the on-demand path
 * never runs those tools, so "retesting" one of their findings this way
 * would silently claim "fixed" without ever re-checking it. The parent
 * guard below enforces this; the API route enforces it again server-side.
 */
function RetestFindingButton({ scanId, token, checkId }: { scanId: string; token: string; checkId: string }) {
  const [state, setState] = useState<"idle" | "checking" | "fixed" | "still-present" | "error">("idle");
  const [message, setMessage] = useState<string | null>(null);
  const [newScanId, setNewScanId] = useState<string | null>(null);

  async function retest() {
    setState("checking");
    setMessage("Re-checking…");
    try {
      const startRes = await fetch(`/api/scans/${scanId}/retest-finding`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ checkId }),
      });
      const startBody = await startRes.json();
      if (!startRes.ok) throw new Error(startBody.error ?? "Could not start recheck");

      const targetScanId = startBody.scanId as string;
      setNewScanId(targetScanId);

      // Same interval/timeout budget as startScan() in src/app/dashboard/page.tsx.
      const POLL_INTERVAL_MS = 4_000;
      const MAX_POLLS = 45;

      async function poll(): Promise<{ status: string; findings?: Array<{ check_id: string | null }>; fixed_findings?: Array<{ check_id: string | null }> }> {
        const res = await fetch(`/api/v1/scans/${targetScanId}`, { headers: { Authorization: `Bearer ${token}` } });
        if (!res.ok) throw new Error(`Recheck status check failed (${res.status})`);
        return res.json();
      }

      let report = await poll();
      let polls = 0;
      while ((report.status === "pending" || report.status === "running") && polls < MAX_POLLS) {
        await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
        report = await poll();
        polls++;
      }

      if (report.status === "pending" || report.status === "running") {
        setMessage("Still running — check back in a minute.");
        setState("idle");
        return;
      }
      if (report.status === "failed") throw new Error("Recheck scan failed — try again.");

      const stillPresent = (report.findings ?? []).some((f) => f.check_id === checkId);
      setState(stillPresent ? "still-present" : "fixed");
    } catch (err) {
      setMessage((err as Error).message);
      setState("error");
    }
  }

  if (state === "idle") {
    return (
      <button onClick={retest} className="mt-3 ml-4 text-xs font-semibold text-neon hover:text-neon/80 print:hidden">
        🔁 Recheck now
      </button>
    );
  }
  if (state === "checking") {
    return <p className="mt-3 ml-4 text-xs text-cybertext/40 print:hidden">{message}</p>;
  }
  if (state === "error") {
    return (
      <div className="mt-3 ml-4 print:hidden">
        <p className="text-xs text-red-400">{message}</p>
        <button onClick={retest} className="mt-1 text-xs font-medium text-neon hover:underline">
          Try again
        </button>
      </div>
    );
  }
  if (state === "fixed") {
    return (
      <p className="mt-3 ml-4 text-xs font-semibold text-neon print:hidden">
        ✓ Fixed — confirmed just now.{" "}
        {newScanId && (
          <a href={`/dashboard/scans/${newScanId}`} className="underline hover:no-underline">
            View full scan →
          </a>
        )}
      </p>
    );
  }
  // still-present
  return (
    <p className="mt-3 ml-4 text-xs text-cybertext/60 print:hidden">
      Still present as of just now.{" "}
      {newScanId && (
        <a href={`/dashboard/scans/${newScanId}`} className="text-neon underline hover:no-underline">
          View full scan →
        </a>
      )}
    </p>
  );
}

export function FindingCard({
  finding,
  scanId,
  token,
  hasTicketIntegration,
  onTriaged,
}: {
  finding: ViewFinding;
  /** Owner-only — omit on the public share page. Enables the AI-tailored-fix button. */
  scanId?: string;
  token?: string;
  /** Owner-only, and only true once GET-confirmed a Jira/Linear integration exists. Enables the "Create ticket" button. */
  hasTicketIntegration?: boolean;
  /** Owner-only, and only once finding triage is confirmed available. Enables "Mark as…". */
  onTriaged?: (checkId: string, triage: ViewTriage | null) => void;
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
        {finding.cvssScore != null && (
          <span
            className={`rounded-full border px-1.5 py-0.5 text-[10px] font-semibold ${
              finding.cvssScore >= 9 ? "border-red-400/30 bg-red-400/10 text-red-400" :
              finding.cvssScore >= 7 ? "border-orange-400/30 bg-orange-400/10 text-orange-400" :
              finding.cvssScore >= 4 ? "border-yellow-400/30 bg-yellow-400/10 text-yellow-400" :
              "border-blue-400/30 bg-blue-400/10 text-blue-400"
            }`}
            title={finding.cvssVector ?? `CVSS ${finding.cvssScore}`}
          >
            CVSS {finding.cvssScore.toFixed(1)}
          </span>
        )}
        {finding.threatIntel?.knownExploited && (
          <span
            className="rounded-full border border-red-400/40 bg-red-400/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-red-400"
            title={`Listed in CISA's Known Exploited Vulnerabilities catalog: ${(finding.threatIntel.kevCveIds ?? []).join(", ")}${finding.threatIntel.ransomware ? " — known to be used in ransomware campaigns" : ""}`}
          >
            Actively exploited{finding.threatIntel.ransomware ? " · ransomware" : ""}
          </span>
        )}
        {finding.threatIntel?.epss !== undefined && (
          <span
            className="rounded-full border border-cyberborder px-1.5 py-0.5 text-[10px] font-semibold text-cybertext/70"
            title={`FIRST EPSS: ${formatEpss(finding.threatIntel.epss)} probability of exploitation activity in the next 30 days${finding.threatIntel.epssPercentile !== undefined ? ` (higher than ${Math.floor(finding.threatIntel.epssPercentile * 100)}% of scored CVEs)` : ""}`}
          >
            EPSS {formatEpss(finding.threatIntel.epss)}
          </span>
        )}
        {finding.status === "new" && (
          <span className="rounded-full border border-neon/30 bg-neon/10 px-1.5 py-0.5 text-[10px] font-semibold text-neon">NEW</span>
        )}
        {finding.fixDifficulty && (() => {
          const dm = FIX_DIFFICULTY_META[finding.fixDifficulty];
          return (
            <span className={`ml-auto rounded-full border ${dm.border} ${dm.bg} px-1.5 py-0.5 text-[10px] font-semibold ${dm.text} print:text-slate-500`}>
              {dm.label} fix {dm.time}
            </span>
          );
        })()}
      </div>
      <p className="font-medium text-cybertext text-sm">{finding.title}</p>
      {finding.detail && <p className="mt-1 text-xs text-cybertext/60 leading-relaxed">{finding.detail}</p>}

      {finding.corroboratedBy && finding.corroboratedBy.length > 0 && (
        <p
          data-testid="corroborated-by"
          className="mt-1.5 text-[11px] text-cybermuted print:text-slate-500"
          title={finding.corroboratedBy.map((c) => `${c.tool}: ${c.title}`).join("\n")}
        >
          Also reported by {corroboratingTools(finding.corroboratedBy).join(", ")}
        </p>
      )}

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
          {/* One badge per framework: a finding mapped to two CIS controls
              used to show "CIS Controls v8" twice. Its controls go in the tooltip. */}
          {groupRefsByFramework(finding.complianceRefs).map(([framework, controls]) => (
            <span
              key={framework}
              title={controls.join("\n")}
              className="rounded-full border border-cyberborder bg-cyberbg/60 px-1.5 py-0.5 text-[10px] text-cybertext/50 print:text-slate-500"
            >
              {COMPLIANCE_FRAMEWORK_LABELS[framework]}
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
          {scanId && token && finding.checkId && hasTicketIntegration && (
            <CreateTicketButton scanId={scanId} token={token} checkId={finding.checkId} />
          )}
          {scanId && token && finding.checkId && !isExtendedToolFinding(finding.checkId) && (
            <RetestFindingButton scanId={scanId} token={token} checkId={finding.checkId} />
          )}
        </details>
      )}

      {scanId && token && finding.checkId && onTriaged && !finding.triage && (
        <TriageMenu
          scanId={scanId}
          token={token}
          checkId={finding.checkId}
          onTriaged={(triage) => onTriaged(finding.checkId as string, triage)}
        />
      )}
    </div>
  );
}

/**
 * The report's collapsed "Triaged" group: findings the owner has accepted,
 * marked false positive or snoozed, each with its reason, who and when, and
 * expiry — and Undo, which puts it straight back in the open list.
 */
export function TriagedFindings({
  findings,
  scanId,
  token,
  onTriaged,
}: {
  findings: ViewFinding[];
  scanId?: string;
  token?: string;
  onTriaged?: (checkId: string, triage: ViewTriage | null) => void;
}) {
  const triaged = findings.filter((f): f is ViewFinding & { triage: ViewTriage } => Boolean(f.triage));
  if (triaged.length === 0) return null;

  return (
    <details className="group mt-4 rounded-lg border border-cyberborder bg-cyberpanel">
      <summary className="cursor-pointer list-none px-4 py-3 text-sm font-medium text-cybertext">
        <span className="mr-1 inline-block transition-transform group-open:rotate-90" aria-hidden="true">
          ▸
        </span>
        Triaged ({triaged.length})
        <span className="ml-2 text-xs font-normal text-cybermuted">accepted, false positive or snoozed — not counted as open</span>
      </summary>
      <ul className="space-y-3 border-t border-cyberborder p-4">
        {triaged.map((f, i) => {
          const meta = SEVERITY_META[f.severity] ?? SEVERITY_META.info;
          return (
            <li key={f.checkId ?? i} className="rounded-lg border border-cyberborder bg-cyberbg/40 p-3">
              <div className="mb-1 flex flex-wrap items-center gap-2">
                <span className={`inline-block h-2 w-2 flex-shrink-0 rounded-full ${meta.dot}`} aria-hidden="true" />
                <span className={`text-xs font-semibold uppercase tracking-wide ${meta.text}`}>{meta.label}</span>
                <span className="rounded-full border border-cyberborder px-1.5 py-0.5 text-[10px] font-semibold text-cybertext">
                  {TRIAGE_STATE_LABELS[f.triage.state]}
                </span>
              </div>
              <p className="text-sm font-medium text-cybertext">{f.title}</p>
              <p className="mt-1 whitespace-pre-line text-xs text-cybertext/80">{f.triage.reason}</p>
              <p className="mt-1 text-xs text-cybermuted">{describeTriage(f.triage)}</p>
              {scanId && token && f.checkId && onTriaged && (
                <div className="mt-2">
                  <UndoTriageButton scanId={scanId} token={token} checkId={f.checkId} onUndone={() => onTriaged(f.checkId as string, null)} />
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </details>
  );
}

// Tab order — Cyber Essentials first, since it's the one framework with
// genuine UK small-business relevance for this product's positioning; the
// rest follow COMPLIANCE_FRAMEWORK_LABELS' own declaration order.
const FRAMEWORK_TAB_ORDER = Object.keys(COMPLIANCE_FRAMEWORK_LABELS) as ComplianceFramework[];

/** A finding's refs grouped by framework, in first-seen order, each with its distinct controls. */
export function groupRefsByFramework(refs: ComplianceRef[]): Array<[ComplianceFramework, string[]]> {
  const groups = new Map<ComplianceFramework, string[]>();
  for (const ref of refs) {
    const controls = groups.get(ref.framework) ?? [];
    if (!controls.includes(ref.control)) controls.push(ref.control);
    groups.set(ref.framework, controls);
  }
  return [...groups.entries()];
}

// Cyber Essentials gets its own longer disclaimer (real Cyber Essentials
// certification is a formal self-assessment, or for Plus an external
// audit, against NCSC's own questionnaire — this scan does neither); the
// other frameworks share a shorter, equally honest generic version.
const FRAMEWORK_DISCLAIMER: Partial<Record<ComplianceFramework, string>> = {
  "cyber-essentials":
    "An automated indicator based on this scan’s findings — not a Cyber Essentials certification. Real certification is a formal self-assessment (or, for Plus, an external audit) against NCSC’s own questionnaire.",
};
const DEFAULT_DISCLAIMER = "An automated indicator based on this scan’s findings — not a formal compliance certification or attestation against this framework.";

/**
 * Per-framework control-area breakdown — which of a framework's controls
 * (ALL_CONTROLS_BY_FRAMEWORK, compliance.ts) have at least one open finding
 * mapped to them. Framework-generic: any framework compliance.ts knows
 * about can be selected via the tabs below, not just Cyber Essentials.
 *
 * Returns null when no open finding maps to any framework yet (e.g. a scan
 * stored before complianceRefs existed) — a report with the section but
 * zero real data behind it would be misleading, not just incomplete.
 */
export function ComplianceSummary({ findings }: { findings: ViewFinding[] }) {
  const [activeFramework, setActiveFramework] = useState<ComplianceFramework>("cyber-essentials");

  // A fixed finding shouldn't count against a control area that's since
  // been addressed — only open findings inform this breakdown.
  const open = findings.filter((f) => f.status !== "fixed");
  const anyMapped = open.some((f) => (f.complianceRefs?.length ?? 0) > 0);
  if (!anyMapped) return null;

  const controls = [...ALL_CONTROLS_BY_FRAMEWORK[activeFramework]].sort();
  const controlHasFinding = new Map<string, boolean>(controls.map((c) => [c, false]));
  for (const f of open) {
    for (const ref of f.complianceRefs ?? []) {
      if (ref.framework === activeFramework) controlHasFinding.set(ref.control, true);
    }
  }

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <p className="mb-3 text-sm font-semibold text-cybertext">Compliance control areas</p>
      <div className="no-print mb-3 flex flex-wrap gap-1.5">
        {FRAMEWORK_TAB_ORDER.map((fw) => (
          <button
            key={fw}
            onClick={() => setActiveFramework(fw)}
            className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
              activeFramework === fw
                ? "border-neon/40 bg-neon/10 text-neon"
                : "border-cyberborder text-cybertext/50 hover:border-cybertext/30 hover:text-cybertext/70"
            }`}
          >
            {COMPLIANCE_FRAMEWORK_LABELS[fw]}
          </button>
        ))}
      </div>
      <p className="mb-4 text-xs text-cybertext/50">{FRAMEWORK_DISCLAIMER[activeFramework] ?? DEFAULT_DISCLAIMER}</p>
      {controls.length === 0 ? (
        <p className="text-xs text-cybertext/40">No controls mapped to {COMPLIANCE_FRAMEWORK_LABELS[activeFramework]} for this scan&rsquo;s findings yet.</p>
      ) : (
        <div className="grid gap-2 sm:grid-cols-2">
          {controls.map((control) => {
            const hasFinding = controlHasFinding.get(control);
            return (
              <div key={control} className="flex items-center gap-2 rounded-lg border border-cyberborder bg-cyberbg/50 p-3">
                <span className={`text-sm font-bold ${hasFinding ? "text-red-400" : "text-neon"}`}>{hasFinding ? "✗" : "✓"}</span>
                <span className="text-xs text-cybertext/70">{control}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/**
 * Critical Path Analysis — chains related findings into a "worse together
 * than alone" attack narrative. Calls the pure computeCriticalPaths()
 * directly on this page's already-loaded findings, rather than routing
 * through scanReport.ts's buildScanReport() (which also computes the same
 * chains, for the public API/webhook consumers) — the dashboard page
 * doesn't call buildScanReport() today, and refactoring it to do so isn't
 * needed just to reuse a pure function. Excludes fixed findings for the
 * same reason ComplianceSummary does: a chain built from a since-resolved
 * finding would be misleading, not just stale.
 */
export function CriticalPaths({ findings }: { findings: ViewFinding[] }) {
  const open = findings.filter((f) => f.status !== "fixed");
  const paths = computeCriticalPaths(open);
  if (paths.length === 0) return null;

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <p className="mb-1 text-sm font-semibold text-cybertext">Attack chains</p>
      <p className="mb-4 text-xs text-cybertext/50">
        Combinations of this scan&rsquo;s findings that are worse together than either is alone — not a new scan, just a different read of what&rsquo;s already been found.
      </p>
      <div className="space-y-3">
        {paths.map((path) => {
          const meta = SEVERITY_META[path.severity];
          return (
            <div key={path.title} className={`rounded-lg border ${meta.border} ${meta.bg} p-3`}>
              <div className="mb-1 flex items-center gap-2">
                <span className={`rounded-full border ${meta.border} px-1.5 py-0.5 text-[10px] font-medium ${meta.text}`}>{meta.label}</span>
                <p className="text-sm font-medium text-cybertext">{path.title}</p>
              </div>
              <p className="text-xs text-cybertext/60">{path.narrative}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function ExecutiveSummary({ findings, score }: { findings: ViewFinding[]; score: number }) {
  // Triaged findings (accepted / false positive / snoozed) aren't open work,
  // so they're counted separately rather than in any of the tiles.
  const open = findings.filter((f) => f.status !== "fixed" && !f.triage);
  const triagedCount = findings.filter((f) => f.status !== "fixed" && f.triage).length;
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let totalFixMinutes = 0;
  for (const f of open) {
    severityCounts[f.severity] = (severityCounts[f.severity] ?? 0) + 1;
    if (f.estimatedFixMinutes) totalFixMinutes += f.estimatedFixMinutes;
  }

  const topFindings = open
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .slice(0, 3);

  const formatTime = (mins: number) => {
    if (mins < 60) return `${mins} min`;
    const hrs = Math.round(mins / 60);
    if (hrs < 8) return `${hrs} hr${hrs > 1 ? "s" : ""}`;
    const days = Math.round(hrs / 8);
    return `${days} day${days > 1 ? "s" : ""}`;
  };

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5 print:border-slate-300 print:bg-white">
      <p className="mb-4 text-sm font-semibold text-cybertext">Executive summary</p>

      <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-lg border border-cyberborder bg-cyberbg/50 p-3 text-center">
          <p className="text-2xl font-bold text-cybertext">{score}</p>
          <p className="text-[10px] uppercase tracking-wide text-cybertext/50">Score</p>
        </div>
        <div className="rounded-lg border border-cyberborder bg-cyberbg/50 p-3 text-center">
          <p className="text-2xl font-bold text-red-400">{severityCounts.critical + severityCounts.high}</p>
          <p className="text-[10px] uppercase tracking-wide text-cybertext/50">Critical + High</p>
        </div>
        <div className="rounded-lg border border-cyberborder bg-cyberbg/50 p-3 text-center">
          <p className="text-2xl font-bold text-cybertext">{open.length}</p>
          <p className="text-[10px] uppercase tracking-wide text-cybertext/50">Open findings</p>
          {triagedCount > 0 && <p className="mt-0.5 text-[10px] text-cybermuted">+{triagedCount} triaged</p>}
        </div>
        <div className="rounded-lg border border-cyberborder bg-cyberbg/50 p-3 text-center">
          <p className="text-2xl font-bold text-cybertext">{totalFixMinutes > 0 ? formatTime(totalFixMinutes) : "—"}</p>
          <p className="text-[10px] uppercase tracking-wide text-cybertext/50">Est. remediation</p>
        </div>
      </div>

      <div className="mb-4 flex gap-1">
        {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
          const count = severityCounts[sev];
          if (!count) return null;
          const meta = SEVERITY_META[sev];
          return (
            <div
              key={sev}
              className={`h-2 rounded-full ${meta.dot}`}
              style={{ flex: count }}
              title={`${meta.label}: ${count}`}
            />
          );
        })}
      </div>

      {triagedCount > 0 && (
        <p className="mb-4 text-xs text-cybermuted">
          {triagedCount} triaged finding{triagedCount === 1 ? "" : "s"} (accepted, false positive or snoozed){" "}
          {triagedCount === 1 ? "isn’t" : "aren’t"} counted above. The score is as of the scan: findings marked false
          positive stop counting from the next scan.
        </p>
      )}

      {topFindings.length > 0 && (
        <div>
          <p className="mb-2 text-xs font-semibold text-cybertext/60 uppercase tracking-wide">Top priorities</p>
          <ol className="space-y-1.5">
            {topFindings.map((f, i) => {
              const meta = SEVERITY_META[f.severity];
              return (
                <li key={f.checkId ?? i} className="flex items-start gap-2 text-xs">
                  <span className={`mt-0.5 inline-block h-2 w-2 flex-shrink-0 rounded-full ${meta.dot}`} />
                  <span className="text-cybertext/80">{f.title}</span>
                  {f.fixDifficulty && (
                    <span className={`ml-auto flex-shrink-0 ${FIX_DIFFICULTY_META[f.fixDifficulty].text} text-[10px]`}>
                      {FIX_DIFFICULTY_META[f.fixDifficulty].time}
                    </span>
                  )}
                </li>
              );
            })}
          </ol>
        </div>
      )}
    </div>
  );
}

const FOUND_BY_LABEL: Record<ScriptFoundBy, string> = {
  both: "HTML + runtime",
  html: "HTML",
  runtime: "Runtime",
};

const INTEGRITY_META: Record<ScriptIntegrity, { label: string; text: string }> = {
  all: { label: "All tags", text: "text-neon" },
  some: { label: "Some tags", text: "text-warning" },
  none: { label: "None", text: "text-danger" },
  unknown: { label: "Unknown", text: "text-cybermuted" },
};

/**
 * Every third-party origin the scanned page loads JavaScript from
 * (scriptInventory.ts) — the PCI DSS 6.4.3 inventory. Owner view only: the
 * inventory lives in the raw results, which the public share page never
 * receives. Authorising an origin happens on its finding, not here.
 */
export function ScriptInventorySection({ inventory }: { inventory: ScriptInventoryResult | undefined }) {
  if (!inventory) return null; // scan stored before the inventory existed

  return (
    <Card className="print:border-slate-300 print:bg-white">
      <CardHeader className="mb-2">
        <CardTitle>third-party scripts</CardTitle>
      </CardHeader>
      {inventory.status === "error" ? (
        <Alert variant="warning" title="Script inventory unavailable this scan">
          <p className="text-xs">{inventory.note}</p>
        </Alert>
      ) : (
        <div className="space-y-4">
          <CardDescription className="text-xs">
            Every outside source this page loads JavaScript from — the script inventory PCI DSS 6.4.3 asks for. Each one has an
            &ldquo;unreviewed&rdquo; finding below until you authorise it by marking that finding as accepted with a justification.
          </CardDescription>
          {inventory.paymentPage.detected && (
            <Alert variant="warning" title="This looks like a payment page">
              <p className="text-xs">Evidence: {inventory.paymentPage.signals.join("; ")}.</p>
            </Alert>
          )}
          {inventory.note && (
            <Alert variant="info">
              <p className="text-xs">{inventory.note}</p>
            </Alert>
          )}
          {inventory.origins.length === 0 ? (
            <p className="text-sm text-cybermuted">
              {inventory.status === "partial"
                ? "No third-party scripts in the page's HTML."
                : "This page loads no scripts from third-party sources."}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-cyberborder text-cybermuted print:text-slate-600">
                    <th scope="col" className="py-2 pr-4 font-semibold">Origin</th>
                    <th scope="col" className="py-2 pr-4 font-semibold">Found by</th>
                    <th scope="col" className="py-2 pr-4 font-semibold">Integrity</th>
                    <th scope="col" className="py-2 font-semibold">Sample script</th>
                  </tr>
                </thead>
                <tbody>
                  {inventory.origins.map((entry) => {
                    const integrity = INTEGRITY_META[entry.integrity];
                    return (
                      <tr key={entry.origin} className="border-b border-cyberborder/40 align-top last:border-0">
                        <td className="py-2 pr-4">
                          <span className="break-all font-mono text-cybertext print:text-slate-800">{entry.origin}</span>
                          {entry.paymentProvider && (
                            <span className="mt-1 block text-[10px] uppercase tracking-wide text-warning">
                              {entry.paymentProvider} payment script
                            </span>
                          )}
                        </td>
                        <td className="whitespace-nowrap py-2 pr-4 text-cybertext/70 print:text-slate-700">{FOUND_BY_LABEL[entry.foundBy]}</td>
                        <td className={`whitespace-nowrap py-2 pr-4 font-medium ${integrity.text}`}>{integrity.label}</td>
                        <td className="py-2 text-cybertext/70 print:text-slate-700">
                          <span className="break-all font-mono">{entry.sampleUrls[0]}</span>
                          {entry.scriptCount > 1 && (
                            <span className="mt-1 block text-cybermuted">+{entry.scriptCount - 1} more from this origin</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          {inventory.truncated && (
            <p className="text-xs text-cybermuted">
              Showing {inventory.origins.length} of {inventory.totalOrigins} origins.
            </p>
          )}
        </div>
      )}
    </Card>
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
