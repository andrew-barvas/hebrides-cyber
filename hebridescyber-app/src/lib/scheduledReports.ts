// Scheduled report delivery — generates and emails periodic scan summaries.
//
// Called by a scheduled script (src/scripts/send-scheduled-reports.ts)
// to find due reports, generate content, and deliver via email.
// Follows the same best-effort pattern as the newsletter/digest scripts.
//
// Every format carries the same per-site rows. CSV and JSON go inline in the
// email body; PDF is printed by the same htmlToPdf() as the executive report
// and attached. A report never goes out in a format other than the one its
// email names: if the PDF can't be rendered, the email says it fell back to CSV.

import type { SupabaseClient } from "@supabase/supabase-js";
import type { EmailAttachment } from "./email";
import { escapeHtml, ratingFor, REPORT_MUTED, REPORT_TEXT } from "./executiveReport";
import { STALE_AFTER_DAYS } from "./portfolioReport";

export type ReportFrequency = "daily" | "weekly" | "monthly";
export type ReportFormat = "pdf" | "csv" | "json";

export type ScheduledReport = {
  id: string;
  owner: string;
  target_url: string | null;
  frequency: ReportFrequency;
  format: ReportFormat;
  recipients: string[];
  enabled: boolean;
  last_sent: string | null;
  next_due: string | null;
};

function computeNextDue(frequency: ReportFrequency, from: Date): Date {
  const next = new Date(from);
  switch (frequency) {
    case "daily":
      next.setUTCDate(next.getUTCDate() + 1);
      break;
    case "weekly":
      next.setUTCDate(next.getUTCDate() + 7);
      break;
    case "monthly":
      next.setUTCMonth(next.getUTCMonth() + 1);
      break;
  }
  return next;
}

/**
 * Pure function: is a report due now?
 */
export function isReportDue(nextDue: string | null, now: Date): boolean {
  if (!nextDue) return true;
  return now >= new Date(nextDue);
}

/** How far ahead the workflow's pre-check looks, so a report falling due between it and the send step still gets a browser. */
export const PDF_CHECK_LOOKAHEAD_MS = 15 * 60 * 1000;

/**
 * Pure: will this run render a PDF? The workflow installs Chromium only when
 * it will, rather than on every hourly run.
 */
export function pdfReportDue(
  reports: Pick<ScheduledReport, "enabled" | "format" | "next_due">[],
  now: Date,
  lookaheadMs: number = PDF_CHECK_LOOKAHEAD_MS,
): boolean {
  const horizon = new Date(now.getTime() + lookaheadMs);
  return reports.some((r) => r.enabled && r.format === "pdf" && isReportDue(r.next_due, horizon));
}

export type FindingSummary = {
  targetUrl: string;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  score: number | null;
  lastScanDate: string | null;
};

/**
 * Gather findings summary for a report — either for one target or all targets.
 */
export async function gatherReportData(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  targetUrl: string | null,
): Promise<FindingSummary[]> {
  const summaries: FindingSummary[] = [];

  let targetsQuery = supabaseAdmin
    .from("monitored_targets")
    .select("target_url")
    .eq("owner", ownerId);

  if (targetUrl) {
    targetsQuery = targetsQuery.eq("target_url", targetUrl);
  }

  const { data: targets } = await targetsQuery;
  if (!targets || targets.length === 0) return summaries;

  for (const target of targets) {
    const { data: latestScan } = await supabaseAdmin
      .from("scans")
      .select("id, score, created_at")
      .eq("owner", ownerId)
      .eq("target_url", target.target_url)
      .eq("status", "completed")
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (!latestScan) {
      summaries.push({
        targetUrl: target.target_url,
        totalFindings: 0,
        critical: 0, high: 0, medium: 0, low: 0, info: 0,
        score: null,
        lastScanDate: null,
      });
      continue;
    }

    const { data: results } = await supabaseAdmin
      .from("scan_results")
      .select("results")
      .eq("scan_id", latestScan.id)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    const findings = (results?.results as { findings?: Array<{ severity: string }> })?.findings ?? [];
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      const sev = f.severity as keyof typeof counts;
      if (sev in counts) counts[sev]++;
    }

    summaries.push({
      targetUrl: target.target_url,
      totalFindings: findings.length,
      ...counts,
      score: latestScan.score ?? null,
      lastScanDate: latestScan.created_at,
    });
  }

  return summaries;
}

/**
 * Format a report as CSV text.
 */
export function formatReportCsv(summaries: FindingSummary[]): string {
  const header = "target_url,score,total_findings,critical,high,medium,low,info,last_scan_date";
  const rows = summaries.map((s) =>
    `${s.targetUrl},${s.score ?? ""},${s.totalFindings},${s.critical},${s.high},${s.medium},${s.low},${s.info},${s.lastScanDate ?? ""}`
  );
  return [header, ...rows].join("\r\n");
}

/**
 * Format a report as JSON.
 */
export function formatReportJson(summaries: FindingSummary[]): string {
  return JSON.stringify({ generated_at: new Date().toISOString(), targets: summaries }, null, 2);
}

type Severity = "critical" | "high" | "medium" | "low" | "info";
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLOUR: Record<Severity, string> = { critical: "#7f1d1d", high: "#b91c1c", medium: "#b45309", low: "#1d4ed8", info: "#475569" };

/** Pure: the headline figures shared by the email body and the PDF. */
export function summariseReport(summaries: FindingSummary[]): {
  totalFindings: number;
  avgScore: number | null;
  totals: Record<Severity, number>;
} {
  const totals = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const s of summaries) for (const sev of SEVERITIES) totals[sev] += s[sev];
  const scored = summaries.filter((s) => s.score !== null);
  return {
    totalFindings: summaries.reduce((sum, s) => sum + s.totalFindings, 0),
    avgScore: scored.length > 0 ? Math.round(scored.reduce((sum, s) => sum + (s.score ?? 0), 0) / scored.length) : null,
    totals,
  };
}

/**
 * The PDF version of a scheduled report, as HTML for htmlToPdf(): the same
 * rows as the CSV/JSON, styled like the executive report. Pure.
 *
 * Honest about gaps, like the portfolio report: a site with no completed scan
 * says so rather than reading as clean, an old scan is flagged, and the counts
 * are labelled as untriaged because gatherReportData() doesn't apply triage.
 */
export function renderScheduledReportHtml(
  summaries: FindingSummary[],
  opts: { targetLabel: string; frequency: ReportFrequency; now?: Date },
): string {
  const now = opts.now ?? new Date();
  const e = escapeHtml;
  const { avgScore, totals } = summariseReport(summaries);
  const rating = ratingFor(avgScore);
  const scanned = summaries.filter((s) => s.lastScanDate !== null).length;
  const staleBefore = now.getTime() - STALE_AFTER_DAYS * 24 * 60 * 60 * 1000;

  // Scanned sites first, lowest score first (unscored after scored); sites never scanned last.
  const ordered = [...summaries].sort(
    (a, b) => Number(a.lastScanDate === null) - Number(b.lastScanDate === null) || (a.score ?? 101) - (b.score ?? 101),
  );

  const rows = ordered
    .map((s) => {
      if (s.lastScanDate === null) {
        return `<tr><td>${e(s.targetUrl)}</td><td colspan="7" class="muted">Not scanned yet: no results to report.</td></tr>`;
      }
      const r = ratingFor(s.score);
      const stale = new Date(s.lastScanDate).getTime() < staleBefore;
      return `<tr><td>${e(s.targetUrl)}</td><td><b style="color:${r.colour}">${s.score ?? "—"}</b> <span class="muted">${e(r.label)}</span></td>${SEVERITIES.map((sev) => `<td class="n">${s[sev]}</td>`).join("")}<td>${e(s.lastScanDate.slice(0, 10))}${stale ? `<div class="stale">over ${STALE_AFTER_DAYS} days ago: may be out of date</div>` : ""}</td></tr>`;
    })
    .join("");

  const chips = SEVERITIES.map((sev) => `<div class="chip"><b style="color:${SEVERITY_COLOUR[sev]}">${totals[sev]}</b><span>${sev}</span></div>`).join("");
  const generated = now.toISOString().slice(0, 10);

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><title>Hebrides Cyber — scheduled security report</title>
<style>
  @page { size: A4; margin: 18mm 16mm; }
  body { font-family: Arial, Helvetica, sans-serif; color: ${REPORT_TEXT}; font-size: 12px; line-height: 1.45; }
  h1 { font-size: 22px; margin: 0; color: #0b3d5b; } h2 { font-size: 15px; margin: 22px 0 8px; color: #0b3d5b; border-bottom: 1px solid #d5dde5; padding-bottom: 4px; }
  .head { border-bottom: 3px solid #0b3d5b; padding-bottom: 12px; }
  .muted { color: ${REPORT_MUTED}; } .meta { margin: 10px 0 0; }
  .overview { display: flex; gap: 18px; align-items: stretch; margin-top: 14px; }
  .score { min-width: 130px; text-align: center; border: 2px solid ${rating.colour}; border-radius: 8px; padding: 12px; }
  .score b { font-size: 38px; color: ${rating.colour}; display: block; line-height: 1; } .score span { font-weight: bold; color: ${rating.colour}; }
  .chips { display: flex; gap: 8px; flex: 1; } .chip { flex: 1; border: 1px solid #d5dde5; border-radius: 8px; text-align: center; padding: 12px 4px; }
  .chip b { display: block; font-size: 24px; } .chip span { text-transform: uppercase; font-size: 10px; color: ${REPORT_MUTED}; }
  table { width: 100%; border-collapse: collapse; } th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #e3e9ee; vertical-align: top; font-size: 11px; }
  th { background: #f1f5f8; } tr { page-break-inside: avoid; } .n { text-align: right; }
  .stale { color: #b45309; font-size: 10px; }
  .foot { margin-top: 26px; padding-top: 8px; border-top: 1px solid #d5dde5; font-size: 10px; color: ${REPORT_MUTED}; }
</style></head><body>
  <div class="head"><h1>Hebrides Cyber</h1><div class="muted">Scheduled security report</div></div>
  <p class="meta"><b>Covers:</b> ${e(opts.targetLabel)} &nbsp; <b>Frequency:</b> ${e(opts.frequency)} &nbsp; <b>Report date:</b> ${e(generated)}</p>

  <div class="overview">
    <div class="score"><b>${avgScore ?? "—"}</b><span>${e(rating.label)}</span><div class="muted">average of ${scanned} scanned site${scanned === 1 ? "" : "s"}</div></div>
    <div class="chips">${chips}</div>
  </div>

  <h2>Sites (${summaries.length})</h2>
  <table><thead><tr><th>Site</th><th>Score</th><th class="n">Critical</th><th class="n">High</th><th class="n">Medium</th><th class="n">Low</th><th class="n">Info</th><th>Last scanned</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="8">No monitored sites.</td></tr>'}</tbody></table>

  <p class="foot">Counts are every finding in each site's latest completed scan, before triage: false positives and accepted risks are included. The dashboard shows the triaged view.</p>
</body></html>`;
}

/** What send-scheduled-reports.ts emails for one report. */
export type ReportEmail = {
  subject: string;
  html: string;
  attachments: EmailAttachment[];
  /** What was actually sent: CSV when a PDF was asked for but could not be rendered. */
  sentFormat: ReportFormat;
  /** Why the PDF could not be rendered, when it couldn't. */
  pdfError?: string;
};

const PRE_STYLE = "background:#111;color:#ccc;padding:12px;border-radius:4px;overflow-x:auto;font-size:12px";

/**
 * Builds one report's email. `renderPdf` is htmlToPdf() in production and a
 * stub in tests, so this runs without a browser.
 */
export async function buildReportEmail(
  report: Pick<ScheduledReport, "target_url" | "frequency" | "format">,
  summaries: FindingSummary[],
  opts: { siteUrl: string; renderPdf: (html: string) => Promise<Buffer>; now?: Date },
): Promise<ReportEmail> {
  const now = opts.now ?? new Date();
  const targetLabel = report.target_url ?? "all monitored sites";
  const { totalFindings, avgScore } = summariseReport(summaries);

  let sentFormat: ReportFormat = report.format;
  let pdfError: string | undefined;
  const attachments: EmailAttachment[] = [];
  if (report.format === "pdf") {
    try {
      const pdf = await opts.renderPdf(renderScheduledReportHtml(summaries, { targetLabel, frequency: report.frequency, now }));
      attachments.push({ filename: `hebridescyber-report-${now.toISOString().slice(0, 10)}.pdf`, content: pdf });
    } catch (err) {
      sentFormat = "csv";
      pdfError = err instanceof Error ? err.message : String(err);
    }
  }

  const formatLabel = pdfError ? "CSV (the PDF could not be generated)" : sentFormat === "pdf" ? "PDF (attached)" : sentFormat.toUpperCase();
  const reportData =
    sentFormat === "pdf"
      ? `<p>The full report is attached as a PDF.</p>`
      : `<pre style="${PRE_STYLE}">${escapeHtml(sentFormat === "csv" ? formatReportCsv(summaries) : formatReportJson(summaries))}</pre>`;
  const fallbackNote = pdfError
    ? `<p style="background:#3a2a0a;color:#fde68a;padding:8px 12px;border-radius:4px">This report is set to arrive as a PDF, but the PDF could not be generated this time, so the same figures are below as CSV instead. Your schedule hasn't changed.</p>`
    : "";

  const subject = `Scheduled Security Report — ${escapeHtml(targetLabel)}`;
  const html = [
    `<div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto">`,
    `<h2 style="color:#39FFC0">Scheduled Security Report</h2>`,
    `<p>Report for: <strong>${escapeHtml(targetLabel)}</strong></p>`,
    `<p>Frequency: ${report.frequency} | Format: ${formatLabel}</p>`,
    `<table style="width:100%;border-collapse:collapse;margin:16px 0">`,
    `<tr style="background:#0D1524;color:#fff"><th style="padding:8px;text-align:left">Metric</th><th style="padding:8px;text-align:right">Value</th></tr>`,
    `<tr><td style="padding:8px">Sites scanned</td><td style="padding:8px;text-align:right">${summaries.length}</td></tr>`,
    `<tr><td style="padding:8px">Total findings</td><td style="padding:8px;text-align:right">${totalFindings}</td></tr>`,
    avgScore !== null ? `<tr><td style="padding:8px">Average score</td><td style="padding:8px;text-align:right">${avgScore}/100</td></tr>` : "",
    `</table>`,
    fallbackNote,
    reportData,
    `<p><a href="${opts.siteUrl}/dashboard" style="color:#39FFC0">View dashboard →</a></p>`,
    `<p style="color:#888;font-size:12px;margin-top:24px">Manage your scheduled reports in Dashboard → Integrations.</p>`,
    `</div>`,
  ].join("\n");

  return { subject, html, attachments, sentFormat, pdfError };
}

/**
 * Mark a report as sent and compute the next due date.
 */
export async function markReportSent(
  supabaseAdmin: SupabaseClient,
  reportId: string,
  frequency: ReportFrequency,
): Promise<void> {
  const now = new Date();
  await supabaseAdmin
    .from("scheduled_reports")
    .update({
      last_sent: now.toISOString(),
      next_due: computeNextDue(frequency, now).toISOString(),
      updated_at: now.toISOString(),
    })
    .eq("id", reportId);
}
