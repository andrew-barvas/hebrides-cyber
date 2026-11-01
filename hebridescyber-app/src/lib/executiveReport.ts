// Client-ready executive report (HTML, rendered to PDF by api/generate-report.ts).
//
// Replaces the old minimal template, which listed findings unsorted and ended
// with a dump of the raw results JSON. Pure: everything it needs is passed in,
// so it is tested without a browser; the route only fetches data and prints.
//
// Rules this encodes:
// - One-page-at-a-glance first (score, severity counts, top priorities), detail after.
// - What the customer decided is respected: false positives are left out, and
//   accepted/snoozed findings are listed separately, never counted as open.
// - Honest about limits: checks that errored, were partial or not configured are
//   listed, because a missing finding from them is not a clean result.
// - White label: with branding set, "Hebrides Cyber" does not appear anywhere
//   (the compliance disclaimer is rewritten, and the footer carries the
//   agency's name). Without branding the default identity is shown.
// - Defensive context: each finding names the CWE weakness and the MITRE
//   ATT&CK technique an adversary could use against it (attackMap.ts), as
//   IDs and links only, with MITRE's attribution. Scans stored before that
//   field existed are mapped here from their checkId.
// - Escaping: every value is HTML-escaped including quotes, and a logo is only
//   used if it is an https URL (the report is rendered by a headless browser).
import type { Finding } from "./scanners";
import { computeCriticalPaths, computeChokepoints } from "./attackPathAnalysis";
import { COMPLIANCE_REPORT_DISCLAIMER, generateComplianceReport, withComplianceRefs } from "./complianceReport";
import { partitionByTriage, TRIAGE_STATE_LABELS, type TriageIndex } from "./findingTriage";
import { hostOf } from "./findingLifecycle";
import { confirmedProof } from "./proofEvidence";
import { ATTACK_ATTRIBUTION, getAttackRefs, getCweIds } from "./scanners/attackMap";
import { evidenceSummary, readEvidence } from "./findingEvidence";

export type ReportBranding = { logoUrl?: string; name?: string };

/**
 * Text colours for every PDF template (executive, portfolio, scheduled). Small
 * print text has to read on paper and to text-extraction tools: body ~17.7:1 on
 * white, secondary ~9:1 (the old #64727f grey was ~4.9:1 and hard to read).
 */
export const REPORT_TEXT = "#111827";
export const REPORT_MUTED = "#3f4a56";

export type ExecutiveReportInput = {
  targetUrl: string;
  /** When the scan ran (ISO). */
  scannedAt: string | null;
  score: number | null;
  summary: string | null;
  findings: Finding[];
  /** The stored `results` object, read only for per-check statuses. */
  results: Record<string, unknown> | null;
  triage: TriageIndex;
  branding?: ReportBranding;
  now?: Date;
};

const SEVERITY_ORDER: Finding["severity"][] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLOUR: Record<Finding["severity"], string> = {
  critical: "#7f1d1d",
  high: "#b91c1c",
  medium: "#b45309",
  low: "#1d4ed8",
  info: "#475569",
};
const EFFORT_LABEL: Record<NonNullable<Finding["fixDifficulty"]>, string> = { trivial: "minutes", easy: "under an hour", moderate: "a few hours", hard: "days" };
const NOT_RUN = new Set(["error", "not_configured", "partial"]);
const TOP_N = 5;
const DETAIL_CHARS = 280;
const FIX_CHARS = 420;

export function escapeHtml(input: string): string {
  return input.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/** A logo is rendered by a headless browser, so only plain https URLs are allowed. */
export function safeLogoUrl(raw: string | undefined): string | null {
  if (!raw) return null;
  try {
    const u = new URL(raw);
    return u.protocol === "https:" ? u.href : null;
  } catch {
    return null;
  }
}

/** Markdown-ish remediation text as plain, short prose. */
export function plainText(text: string, max: number): string {
  const flat = text
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/[*_`#>]/g, "")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/\s+/g, " ")
    .trim();
  return flat.length > max ? `${flat.slice(0, max - 1).trimEnd()}…` : flat;
}

export function ratingFor(score: number | null): { label: string; colour: string } {
  if (score === null) return { label: "Not scored", colour: "#475569" };
  if (score >= 90) return { label: "Strong", colour: "#15803d" };
  if (score >= 75) return { label: "Good", colour: "#4d7c0f" };
  if (score >= 50) return { label: "Needs attention", colour: "#b45309" };
  return { label: "At risk", colour: "#b91c1c" };
}

const severityRank = (s: Finding["severity"]) => SEVERITY_ORDER.indexOf(s);

/** CWE ids and ATT&CK techniques for a finding, falling back to the checkId for scans stored before the fields existed. */
export function findingRefs(f: Finding): { cwe: string[]; attack: NonNullable<Finding["attackRefs"]> } {
  return { cwe: f.cwe ?? getCweIds(f.checkId), attack: f.attackRefs ?? getAttackRefs(f.checkId) };
}

/** Most urgent first: severity, then confirmed-exploitable, then known-exploited, then likelihood of exploitation, then easiest fix. */
export function prioritise(findings: Finding[]): Finding[] {
  const effort = ["trivial", "easy", "moderate", "hard"];
  return [...findings].sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      Number(Boolean(confirmedProof(b))) - Number(Boolean(confirmedProof(a))) ||
      Number(b.threatIntel?.knownExploited ?? false) - Number(a.threatIntel?.knownExploited ?? false) ||
      (b.threatIntel?.epss ?? 0) - (a.threatIntel?.epss ?? 0) ||
      (a.fixDifficulty ? effort.indexOf(a.fixDifficulty) : 9) - (b.fixDifficulty ? effort.indexOf(b.fixDifficulty) : 9)
  );
}

/** Checks that did not complete: their silence is not a clean result. */
export function incompleteChecks(results: Record<string, unknown> | null): { name: string; status: keyof typeof STATUS_WORDS }[] {
  const out: { name: string; status: keyof typeof STATUS_WORDS }[] = [];
  for (const [name, value] of Object.entries(results ?? {})) {
    if (name === "extended" || !value || typeof value !== "object") continue;
    const status = (value as { status?: unknown }).status;
    if (typeof status === "string" && NOT_RUN.has(status)) out.push({ name, status: status as keyof typeof STATUS_WORDS });
  }
  return out;
}

const STATUS_WORDS: Record<"error" | "partial" | "not_configured", string> = { error: "could not complete", partial: "completed only in part", not_configured: "was not available" };

function severityCounts(findings: Finding[]): Record<Finding["severity"], number> {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function renderExecutiveReportHtml(input: ExecutiveReportInput): string {
  const now = input.now ?? new Date();
  const host = hostOf(input.targetUrl) ?? input.targetUrl;
  const branding = input.branding;
  const brandName = branding?.name?.trim() || (branding ? "Security Report" : "Hebrides Cyber");
  const logo = safeLogoUrl(branding?.logoUrl);

  const { open, triaged } = partitionByTriage(input.findings, host, input.triage);
  // A false positive is "not a real issue": leave it out of a client report entirely.
  const accepted = triaged.filter((f) => input.triage.get(host, f.checkId)?.state !== "false_positive");
  const ordered = prioritise(open);
  const counts = severityCounts(open);
  const rating = ratingFor(input.score);
  const top = ordered.filter((f) => f.severity !== "info").slice(0, TOP_N);
  const compliance = generateComplianceReport(input.targetUrl, withComplianceRefs(open));
  const incomplete = incompleteChecks(input.results);
  const attackPaths = computeCriticalPaths(open);
  const chokepoints = computeChokepoints(attackPaths).filter((c) => c.pathCount > 1);
  const titleByCheckId = new Map(open.filter((f) => f.checkId).map((f) => [f.checkId as string, f.title]));

  const disclaimer = branding ? COMPLIANCE_REPORT_DISCLAIMER.replace("Hebrides Cyber's external scan", "the external scan") : COMPLIANCE_REPORT_DISCLAIMER;

  const e = escapeHtml;
  const badge = (s: Finding["severity"]) => `<span class="sev" style="background:${SEVERITY_COLOUR[s]}">${e(s)}</span>`;
  const effort = (f: Finding) => (f.fixDifficulty ? e(EFFORT_LABEL[f.fixDifficulty]) : "—");
  const refIds = (f: Finding) => {
    const { cwe, attack } = findingRefs(f);
    return [...cwe, ...attack.map((a) => a.id)].map(e).join(", ") || "—";
  };
  const techniqueLine = (f: Finding) => {
    const { cwe, attack } = findingRefs(f);
    if (!attack.length && !cwe.length) return "";
    const parts = [...attack.map((a) => `<a href="${e(a.url)}">${e(a.id)}</a> ${e(a.name)}`), ...cwe.map(e)];
    return `<p class="muted refs"><b>Why it matters:</b> ${parts.join(" · ")}</p>`;
  };
  const usesAttack = open.some((f) => findingRefs(f).attack.length > 0);

  const countChips = SEVERITY_ORDER.map((s) => `<div class="chip"><b style="color:${SEVERITY_COLOUR[s]}">${counts[s]}</b><span>${e(s)}</span></div>`).join("");

  const topHtml = top.length
    ? top
        .map(
          (f, i) => `<div class="priority">
            <div class="pn">${i + 1}</div>
            <div class="pb">
              <div>${badge(f.severity)} <b>${e(f.title)}</b>${confirmedProof(f) ? ' <span class="kev">confirmed exploitable</span>' : ""}${f.threatIntel?.knownExploited ? ' <span class="kev">actively exploited</span>' : ""}</div>
              <p>${e(plainText(f.detail, DETAIL_CHARS))}</p>
              ${techniqueLine(f)}
              ${readEvidence(f.evidence) ? `<p class="ev"><b>Evidence:</b> <code>${e(evidenceSummary(readEvidence(f.evidence)))}</code></p>` : ""}
              ${f.remediation ? `<p class="fix"><b>How to fix:</b> ${e(plainText(f.remediation, FIX_CHARS))} <i>(effort: ${effort(f)})</i></p>` : ""}
            </div>
          </div>`
        )
        .join("")
    : `<p>No open findings above informational level were recorded.</p>`;

  const rows = ordered
    .map((f) => `<tr><td>${badge(f.severity)}</td><td>${e(f.title)}</td><td>${e(plainText(f.detail, DETAIL_CHARS))}${readEvidence(f.evidence) ? `<br><code class="ev">${e(evidenceSummary(readEvidence(f.evidence)))}</code>` : ""}</td><td>${refIds(f)}</td><td>${effort(f)}</td></tr>`)
    .join("");

  const frameworkRows = compliance.frameworks
    .map((fw) => `<tr><td>${e(fw.label)}</td><td>${fw.passing} of ${fw.totalControls}</td><td>${fw.failing}</td></tr>`)
    .join("");

  const acceptedHtml = accepted.length
    ? `<h2>Accepted or snoozed risks</h2>
       <p class="muted">Reviewed and deliberately left open. They are not counted above.</p>
       <ul>${accepted.map((f) => `<li>${e(f.title)} <span class="muted">— ${e(TRIAGE_STATE_LABELS[input.triage.get(host, f.checkId)!.state])}</span></li>`).join("")}</ul>`
    : "";

  const chokepointsHtml = chokepoints.length
    ? `<div class="chokepoints"><b>Fix these first — each breaks more than one chain:</b>
       <ul>${chokepoints.map((c) => `<li>${e(titleByCheckId.get(c.checkId) ?? c.checkId)} <span class="muted">(breaks ${c.pathCount} chains)</span></li>`).join("")}</ul></div>`
    : "";
  const attackPathsHtml = attackPaths.length
    ? `<h2>Attack chains</h2>
       <p class="muted">Combinations of this scan's findings that are worse together than any is alone — a different read of what has already been found, not a new scan.</p>
       ${chokepointsHtml}
       ${attackPaths
         .map(
           (p) => `<div class="chain">
             <div>${badge(p.severity)} <b>${e(p.title)}</b></div>
             <div class="chainsteps">${p.steps
               .map((s, i) => `${i > 0 ? '<span class="arrow">&rarr;</span>' : ""}<span class="node node-${s.role}">${e(s.label)}</span>`)
               .join("")}</div>
             <p class="muted">${e(plainText(p.narrative, DETAIL_CHARS))}</p>
           </div>`
         )
         .join("")}`
    : "";

  const incompleteHtml = incomplete.length
    ? `<h2>Checks that did not finish</h2>
       <p class="muted">No findings from these checks does not mean no problems: ${incomplete.length === 1 ? "it was" : "they were"} not able to look in full.</p>
       <ul>${incomplete.map((c) => `<li>${e(c.name)} — ${e(STATUS_WORDS[c.status])}</li>`).join("")}</ul>`
    : `<p class="muted">Every automated check in this scan completed.</p>`;

  const generated = now.toISOString().slice(0, 10);
  const scanned = input.scannedAt ? input.scannedAt.slice(0, 10) : generated;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><title>${e(brandName)} — ${e(host)}</title>
<style>
  @page { size: A4; margin: 18mm 16mm; }
  body { font-family: Arial, Helvetica, sans-serif; color: ${REPORT_TEXT}; font-size: 12px; line-height: 1.45; }
  h1 { font-size: 22px; margin: 0; color: #0b3d5b; } h2 { font-size: 15px; margin: 22px 0 8px; color: #0b3d5b; border-bottom: 1px solid #d5dde5; padding-bottom: 4px; }
  .head { display: flex; align-items: center; gap: 12px; border-bottom: 3px solid #0b3d5b; padding-bottom: 12px; }
  .head img { height: 40px; max-width: 160px; object-fit: contain; }
  .muted { color: ${REPORT_MUTED}; } .meta { margin: 10px 0 0; }
  .overview { display: flex; gap: 18px; align-items: stretch; margin-top: 14px; }
  .score { min-width: 130px; text-align: center; border: 2px solid ${rating.colour}; border-radius: 8px; padding: 12px; }
  .score b { font-size: 38px; color: ${rating.colour}; display: block; line-height: 1; } .score span { font-weight: bold; color: ${rating.colour}; }
  .chips { display: flex; gap: 8px; flex: 1; } .chip { flex: 1; border: 1px solid #d5dde5; border-radius: 8px; text-align: center; padding: 12px 4px; }
  .chip b { display: block; font-size: 24px; } .chip span { text-transform: uppercase; font-size: 10px; color: ${REPORT_MUTED}; }
  .sev { display: inline-block; color: #fff; text-transform: uppercase; font-size: 9px; font-weight: bold; padding: 2px 6px; border-radius: 4px; }
  .kev { color: #7f1d1d; font-weight: bold; font-size: 10px; }
  .priority { display: flex; gap: 10px; margin: 10px 0; page-break-inside: avoid; } .pn { font-size: 18px; font-weight: bold; color: #0b3d5b; width: 20px; }
  .pb p { margin: 3px 0; } .refs { font-size: 10px; } .refs a { color: #0b3d5b; } .fix { background: #f1f5f8; padding: 6px 8px; border-radius: 4px; }
  .ev, .ev code, code.ev { font-size: 10px; color: ${REPORT_MUTED}; word-break: break-all; }
  table { width: 100%; border-collapse: collapse; } th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #e3e9ee; vertical-align: top; font-size: 11px; }
  th { background: #f1f5f8; } tr { page-break-inside: avoid; }
  .chain { margin: 10px 0; page-break-inside: avoid; } .chain > div:first-child { margin-bottom: 4px; }
  .chainsteps { display: flex; flex-wrap: wrap; align-items: center; gap: 4px; margin: 4px 0; }
  .node { border: 1px solid #c3ccd6; border-radius: 6px; padding: 3px 8px; font-size: 10px; background: #f8fafc; }
  .node-entry { border-color: #0b7a5b; } .node-pivot { border-color: #b45309; } .node-impact { border-color: #b91c1c; }
  .arrow { color: ${REPORT_MUTED}; font-size: 12px; } .chokepoints { background: #f1f7f4; border: 1px solid #0b7a5b33; border-radius: 6px; padding: 6px 10px; margin: 8px 0; }
  .foot { margin-top: 26px; padding-top: 8px; border-top: 1px solid #d5dde5; font-size: 10px; color: ${REPORT_MUTED}; }
</style></head><body>
  <div class="head">${logo ? `<img src="${e(logo)}" alt="${e(brandName)}" />` : ""}<div><h1>${e(brandName)}</h1><div class="muted">Security assessment report</div></div></div>
  <p class="meta"><b>Site:</b> ${e(input.targetUrl)} &nbsp; <b>Scanned:</b> ${e(scanned)} &nbsp; <b>Report date:</b> ${e(generated)}</p>

  <div class="overview">
    <div class="score"><b>${input.score === null ? "—" : input.score}</b><span>${e(rating.label)}</span><div class="muted">out of 100</div></div>
    <div class="chips">${countChips}</div>
  </div>

  <h2>Summary</h2>
  <p>${e(input.summary?.trim() || "No summary was recorded for this scan.")}</p>

  <h2>Top priorities</h2>
  ${topHtml}

  ${attackPathsHtml}

  <h2>Compliance snapshot</h2>
  <table><thead><tr><th>Framework</th><th>Controls with no issues found</th><th>With critical/high issues</th></tr></thead><tbody>${frameworkRows}</tbody></table>
  <p class="muted">${e(disclaimer)}</p>

  <h2>All open findings (${ordered.length})</h2>
  <table><thead><tr><th>Severity</th><th>Issue</th><th>Detail</th><th>CWE / ATT&amp;CK</th><th>Effort to fix</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="5">No open findings.</td></tr>'}</tbody></table>
  ${usesAttack ? `<p class="muted">ATT&amp;CK techniques show how an adversary could use an exposure, to help decide what to fix first. ${e(ATTACK_ATTRIBUTION)}</p>` : ""}

  ${acceptedHtml}
  ${incompleteHtml}

  <div class="foot">Prepared by ${e(brandName)}${branding ? "" : " · www.hebridescyber.co.uk"}. This report reflects an automated external scan on ${e(scanned)} and is not a penetration test, audit or certification.</div>
</body></html>`;
}
