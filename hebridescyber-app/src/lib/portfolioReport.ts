// Portfolio report: every site an account monitors in one client-ready PDF
// (HTML rendered by api/portfolio-report.ts). Built for agencies managing
// several client sites: the executive report covers one scan; this answers
// "which of my sites need attention, and what's wrong across all of them?".
//
// Same rules as executiveReport.ts, whose helpers it reuses:
// - the customer's triage is respected: false positives and accepted or
//   snoozed findings are not counted as open;
// - white label: with branding set, "Hebrides Cyber" appears nowhere;
// - every value is HTML-escaped, a logo is only used if it is an https URL;
// - honest about gaps: a site with no completed scan, or one not scanned for
//   a while, says so instead of looking clean.
// Pure: data in, HTML out, tested without a browser.
import type { Finding } from "./scanners";
import { escapeHtml, plainText, prioritise, ratingFor, safeLogoUrl, type ReportBranding } from "./executiveReport";
import { hostOf } from "./findingLifecycle";
import { partitionByTriage, type TriageIndex } from "./findingTriage";

export type PortfolioSiteInput = {
  targetUrl: string;
  /** Latest completed scan, or null when the site has none yet. */
  scan: { id: string; completedAt: string; score: number | null; findings: Finding[] } | null;
};

export type PortfolioInput = {
  sites: PortfolioSiteInput[];
  triage: TriageIndex;
  branding?: ReportBranding;
  now?: Date;
};

type Severity = Finding["severity"];
const COUNTED: Severity[] = ["critical", "high", "medium", "low"];
const SEVERITY_COLOUR: Record<Severity, string> = { critical: "#7f1d1d", high: "#b91c1c", medium: "#b45309", low: "#1d4ed8", info: "#475569" };
/** A site not scanned for this long is flagged: its findings may be out of date. */
export const STALE_AFTER_DAYS = 14;
const TOP_PER_SITE = 3;
const MAX_COMMON = 8;

export type PortfolioSite = {
  host: string;
  targetUrl: string;
  scanId: string | null;
  completedAt: string | null;
  score: number | null;
  counts: Record<Severity, number>;
  exploited: number;
  top: Finding[];
  stale: boolean;
};

export type CommonIssue = { checkId: string; title: string; severity: Severity; hosts: string[] };

export type PortfolioSummary = {
  sites: PortfolioSite[];
  scanned: number;
  averageScore: number | null;
  totals: Record<Severity, number>;
  exploited: number;
  common: CommonIssue[];
};

const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function emptyCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

/** Pure: per-site summaries (worst first, unscanned last) and issues shared by several sites. */
export function summarisePortfolio(input: PortfolioInput): PortfolioSummary {
  const now = (input.now ?? new Date()).getTime();
  const totals = emptyCounts();
  let exploited = 0;
  const byCheck = new Map<string, CommonIssue>();

  const sites: PortfolioSite[] = input.sites.map((site) => {
    const host = hostOf(site.targetUrl) ?? site.targetUrl;
    const counts = emptyCounts();
    if (!site.scan) {
      return { host, targetUrl: site.targetUrl, scanId: null, completedAt: null, score: null, counts, exploited: 0, top: [], stale: true };
    }
    const { open } = partitionByTriage(site.scan.findings, host, input.triage);
    let siteExploited = 0;
    for (const f of open) {
      counts[f.severity] += 1;
      totals[f.severity] += 1;
      if (f.threatIntel?.knownExploited) siteExploited += 1;
      if (f.severity === "info" || !f.checkId) continue;
      const entry = byCheck.get(f.checkId) ?? { checkId: f.checkId, title: f.title, severity: f.severity, hosts: [] };
      if (!entry.hosts.includes(host)) entry.hosts.push(host);
      if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[entry.severity]) entry.severity = f.severity;
      byCheck.set(f.checkId, entry);
    }
    exploited += siteExploited;
    return {
      host,
      targetUrl: site.targetUrl,
      scanId: site.scan.id,
      completedAt: site.scan.completedAt,
      score: site.scan.score,
      counts,
      exploited: siteExploited,
      top: prioritise(open).filter((f) => f.severity !== "info").slice(0, TOP_PER_SITE),
      stale: now - Date.parse(site.scan.completedAt) > STALE_AFTER_DAYS * 24 * 60 * 60 * 1000,
    };
  });

  sites.sort((a, b) => {
    if ((a.score === null) !== (b.score === null)) return a.score === null ? 1 : -1;
    if (a.score !== b.score) return (a.score ?? 0) - (b.score ?? 0);
    return b.counts.critical + b.counts.high - (a.counts.critical + a.counts.high) || a.host.localeCompare(b.host);
  });

  const scored = sites.filter((s) => s.score !== null);
  const common = [...byCheck.values()]
    .filter((c) => c.hosts.length > 1)
    .sort((a, b) => b.hosts.length - a.hosts.length || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.title.localeCompare(b.title))
    .slice(0, MAX_COMMON);

  return {
    sites,
    scanned: sites.filter((s) => s.scanId !== null).length,
    averageScore: scored.length ? Math.round(scored.reduce((sum, s) => sum + (s.score ?? 0), 0) / scored.length) : null,
    totals,
    exploited,
    common,
  };
}

export function renderPortfolioReportHtml(input: PortfolioInput): string {
  const now = input.now ?? new Date();
  const summary = summarisePortfolio(input);
  const branding = input.branding;
  const brandName = branding?.name?.trim() || (branding ? "Security Report" : "Hebrides Cyber");
  const logo = safeLogoUrl(branding?.logoUrl);
  const e = escapeHtml;
  const generated = now.toISOString().slice(0, 10);
  const average = ratingFor(summary.averageScore);

  const badge = (s: Severity) => `<span class="sev" style="background:${SEVERITY_COLOUR[s]}">${e(s)}</span>`;
  const chips = COUNTED.map((s) => `<div class="chip"><b style="color:${SEVERITY_COLOUR[s]}">${summary.totals[s]}</b><span>${e(s)}</span></div>`).join("");

  const siteRows = summary.sites
    .map((s) => {
      const rating = ratingFor(s.score);
      const when = s.completedAt ? `${e(s.completedAt.slice(0, 10))}${s.stale ? ' <span class="warn">not rescanned recently</span>' : ""}` : '<span class="warn">no completed scan yet</span>';
      return `<tr>
        <td><b>${e(s.host)}</b></td>
        <td style="color:${rating.colour}"><b>${s.score ?? "—"}</b>${s.score === null ? "" : ` <span class="muted">${e(rating.label)}</span>`}</td>
        ${COUNTED.map((sev) => `<td class="num">${s.scanId ? s.counts[sev] : "—"}</td>`).join("")}
        <td class="num">${s.scanId ? s.exploited : "—"}</td>
        <td>${when}</td>
      </tr>`;
    })
    .join("");

  const commonHtml = summary.common.length
    ? `<h2>Issues on more than one site</h2>
       <p class="muted">Fixing these once, in a shared template, hosting setting or plugin, may fix them everywhere.</p>
       <table><thead><tr><th>Issue</th><th>Severity</th><th>Sites</th></tr></thead><tbody>
       ${summary.common.map((c) => `<tr><td>${e(c.title)}</td><td>${badge(c.severity)}</td><td>${c.hosts.length} of ${summary.scanned}: ${e(c.hosts.join(", "))}</td></tr>`).join("")}
       </tbody></table>`
    : "";

  const perSite = summary.sites
    .filter((s) => s.top.length > 0)
    .map(
      (s) => `<div class="site"><h3>${e(s.host)}</h3><ol>${s.top
        .map((f) => `<li>${badge(f.severity)} <b>${e(f.title)}</b>${f.threatIntel?.knownExploited ? ' <span class="kev">actively exploited</span>' : ""}<br><span class="muted">${e(plainText(f.detail, 200))}</span></li>`)
        .join("")}</ol></div>`
    )
    .join("");

  const unscanned = summary.sites.filter((s) => !s.scanId).length;
  const caveat = unscanned
    ? `<p class="warn">${unscanned} site${unscanned === 1 ? " has" : "s have"} no completed scan yet, so ${unscanned === 1 ? "it isn't" : "they aren't"} reflected in the totals.</p>`
    : "";

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><title>${e(brandName)} — security portfolio</title>
<style>
  @page { size: A4; margin: 18mm 16mm; }
  body { font-family: Arial, Helvetica, sans-serif; color: #1f2933; font-size: 12px; line-height: 1.45; }
  h1 { font-size: 22px; margin: 0; color: #0b3d5b; } h2 { font-size: 15px; margin: 22px 0 8px; color: #0b3d5b; border-bottom: 1px solid #d5dde5; padding-bottom: 4px; }
  h3 { font-size: 13px; margin: 14px 0 4px; }
  .head { display: flex; align-items: center; gap: 12px; border-bottom: 3px solid #0b3d5b; padding-bottom: 12px; }
  .head img { height: 40px; max-width: 160px; object-fit: contain; }
  .muted { color: #64727f; } .warn { color: #b45309; font-weight: bold; }
  .overview { display: flex; gap: 18px; margin-top: 14px; }
  .score { min-width: 140px; text-align: center; border: 2px solid ${average.colour}; border-radius: 8px; padding: 12px; }
  .score b { font-size: 34px; color: ${average.colour}; display: block; line-height: 1; } .score span { font-size: 11px; color: #64727f; }
  .chips { display: flex; gap: 8px; flex: 1; } .chip { flex: 1; border: 1px solid #d5dde5; border-radius: 8px; text-align: center; padding: 12px 4px; }
  .chip b { display: block; font-size: 24px; } .chip span { text-transform: uppercase; font-size: 10px; color: #64727f; }
  table { width: 100%; border-collapse: collapse; } th, td { text-align: left; padding: 5px 6px; border-bottom: 1px solid #e4e9ee; vertical-align: top; }
  th { font-size: 10px; text-transform: uppercase; color: #64727f; } td.num { text-align: center; }
  .sev { display: inline-block; color: #fff; text-transform: uppercase; font-size: 9px; font-weight: bold; padding: 2px 6px; border-radius: 4px; }
  .kev { color: #7f1d1d; font-weight: bold; font-size: 10px; }
  .site { page-break-inside: avoid; } ol { margin: 4px 0 0 18px; padding: 0; } li { margin-bottom: 6px; }
  .foot { margin-top: 26px; border-top: 1px solid #d5dde5; padding-top: 8px; font-size: 10px; color: #64727f; }
</style></head>
<body>
  <div class="head">${logo ? `<img src="${e(logo)}" alt="" />` : ""}<div><h1>Security portfolio</h1><div class="muted">${e(brandName)} · ${summary.sites.length} site${summary.sites.length === 1 ? "" : "s"} · generated ${e(generated)}</div></div></div>

  <div class="overview">
    <div class="score"><b>${summary.averageScore ?? "—"}</b><span>average score across ${summary.scanned} scanned site${summary.scanned === 1 ? "" : "s"}</span></div>
    <div class="chips">${chips}</div>
  </div>
  <p>${summary.exploited ? `<span class="kev">${summary.exploited} open finding${summary.exploited === 1 ? " is" : "s are"} on CISA's list of vulnerabilities being actively exploited.</span> Fix those first.` : "No open finding is on CISA's list of actively exploited vulnerabilities."}</p>
  ${caveat}

  <h2>Sites, most in need of attention first</h2>
  <table><thead><tr><th>Site</th><th>Score</th>${COUNTED.map((s) => `<th>${e(s)}</th>`).join("")}<th>Exploited</th><th>Last scan</th></tr></thead><tbody>${siteRows}</tbody></table>

  ${commonHtml}

  ${perSite ? `<h2>Top priorities per site</h2>${perSite}` : ""}

  <div class="foot">Open findings exclude anything marked as a false positive, an accepted risk or snoozed. Automated external scans see what is reachable from the internet; they are an indicator, not a certification or a penetration test. ${e(brandName)}.</div>
</body></html>`;
}
