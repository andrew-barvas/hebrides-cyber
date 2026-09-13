"use client";

// E-28 (docs/ENHANCEMENTS.md): ScoreTrend.tsx charts one number over time;
// this answers the more useful repeat-customer question — which kinds of
// findings are trending up/down, and is Cyber Essentials/OWASP/CIS coverage
// actually improving. Two views sharing one data source (the current scan's
// findings for the category breakdown, findComplianceHistoryClient's
// per-scan coverage for the trend) rather than two separate fetches.

import { COMPLIANCE_FRAMEWORK_LABELS, type ComplianceFramework } from "@/lib/scanners/compliance";
import type { CompliancePoint } from "@/lib/clientScanHistory";

// Derived from COMPLIANCE_FRAMEWORK_LABELS' own keys rather than a
// hand-listed literal, so a newly added framework (compliance.ts) shows up
// here automatically instead of being silently omitted.
const FRAMEWORKS = Object.keys(COMPLIANCE_FRAMEWORK_LABELS) as ComplianceFramework[];

// Structural, not the full Finding/ViewFinding type — this component is fed
// dashboard/page.tsx's overviewFindings (ViewFinding[]), which carries at
// least this much.
type FindingLike = { severity: string; checkId?: string };

// Module checkId prefixes (the part before the first ".") are already a
// stable taxonomy — see compliance.ts's own header comment on the format —
// reused here rather than inventing a second category scheme. Known
// prefixes get a human label; anything new falls back to a humanised
// version of the raw key so a newly-added scanner module never needs this
// file touched to show up correctly.
const CATEGORY_LABELS: Record<string, string> = {
  tls: "TLS",
  "deep-tls": "TLS (deep)",
  headers: "Headers",
  dns: "DNS / email",
  exposure: "Exposed files",
  "directory-listing": "Directory listing",
  "cloud-misconfig": "Cloud config",
  "wayback-discovery": "Wayback discovery",
  fingerprint: "Outdated software",
  playwright: "Browser checks",
  ports: "Open ports",
  recon: "Recon",
  webapp: "Web app",
  "safe-browsing": "Safe Browsing",
  wpvdb: "WordPress plugins",
  subdomains: "Subdomains",
  hibp: "Breached credentials",
  sqlmap: "SQL injection",
  xsser: "XSS",
  commix: "Command injection",
  nmap: "Network scan",
  secretScan: "Exposed secrets",
  "dependency-manifest": "Dependencies",
  "docker-base-image": "Container base image",
  "auth-check": "Authenticated checks",
};

// Exported for src/app/dashboard/scans/history/page.tsx's per-category
// sparkline breakdown and src/lib/clientScanHistory.ts's history builder —
// same taxonomy, not a second copy of it.
export function categoryOf(checkId: string | undefined): string {
  if (!checkId) return "other";
  return checkId.split(":")[0].split(".")[0];
}

export function categoryLabel(category: string): string {
  return CATEGORY_LABELS[category] ?? category.replace(/-/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

function CategoryBreakdown({ findings }: { findings: FindingLike[] }) {
  const counts = new Map<string, number>();
  for (const f of findings) {
    if (f.severity === "info") continue;
    const cat = categoryOf(f.checkId);
    counts.set(cat, (counts.get(cat) ?? 0) + 1);
  }

  const rows = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  if (rows.length === 0) {
    return <p className="text-xs text-cybertext/40">No open findings in the latest scan — nothing to break down.</p>;
  }

  const max = rows[0][1];

  return (
    <div className="flex flex-col gap-1.5">
      {rows.map(([category, count]) => (
        <div key={category} className="flex items-center gap-2 text-xs">
          <span className="w-32 shrink-0 truncate text-cybertext/70">{categoryLabel(category)}</span>
          <div className="h-2 flex-1 rounded-full bg-cyberbg">
            <div className="h-2 rounded-full bg-neon/70" style={{ width: `${(count / max) * 100}%` }} />
          </div>
          <span className="w-5 shrink-0 text-right font-mono text-cybertext/50">{count}</span>
        </div>
      ))}
    </div>
  );
}

function CoverageTrend({ history }: { history: CompliancePoint[] }) {
  if (history.length < 2) {
    return (
      <p className="text-xs text-cybertext/40">
        Not enough scan history yet for a coverage trend — run at least one more scan of this target.
      </p>
    );
  }

  const first = history[0];
  const last = history[history.length - 1];

  return (
    <div className="flex flex-col gap-3">
      {FRAMEWORKS.map((framework) => {
        const firstPct = Math.round(first.coverage[framework] * 100);
        const lastPct = Math.round(last.coverage[framework] * 100);
        const delta = lastPct - firstPct;
        return (
          <div key={framework} className="flex items-center gap-2 text-xs">
            <span className="w-32 shrink-0 text-cybertext/70">{COMPLIANCE_FRAMEWORK_LABELS[framework]}</span>
            <div className="h-2 flex-1 rounded-full bg-cyberbg">
              <div
                className={`h-2 rounded-full ${lastPct >= 80 ? "bg-neon" : lastPct >= 50 ? "bg-amber-400" : "bg-red-400"}`}
                style={{ width: `${lastPct}%` }}
              />
            </div>
            <span className="w-10 shrink-0 text-right font-mono text-cybertext/50">{lastPct}%</span>
            {delta !== 0 && (
              <span className={`w-10 shrink-0 text-right ${delta > 0 ? "text-neon" : "text-red-400"}`}>
                {delta > 0 ? "▲" : "▼"}
                {Math.abs(delta)}
              </span>
            )}
          </div>
        );
      })}
      <p className="text-[10px] text-cybertext/40">
        Coverage = % of controls this app checks for with zero open findings, from {new Date(first.date).toLocaleDateString("en-GB")}{" "}
        to {new Date(last.date).toLocaleDateString("en-GB")}.
      </p>
    </div>
  );
}

export default function ComplianceTrend({ findings, history }: { findings: FindingLike[]; history: CompliancePoint[] }) {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
      <div>
        <p className="mb-2 text-xs font-semibold text-cybertext/50 uppercase tracking-wide">Open findings by category</p>
        <CategoryBreakdown findings={findings} />
      </div>
      <div>
        <p className="mb-2 text-xs font-semibold text-cybertext/50 uppercase tracking-wide">Compliance coverage trend</p>
        <CoverageTrend history={history} />
      </div>
    </div>
  );
}
