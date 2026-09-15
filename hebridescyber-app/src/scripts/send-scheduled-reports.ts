// Sends due scheduled reports to their configured recipients.
// Run by .github/workflows/scheduled-reports.yml as a cron job.
// Same direct-Supabase pattern as send-monthly-digest.ts — no HTTP hop.
//
// Run locally with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... npx tsx src/scripts/send-scheduled-reports.ts

import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import {
  isReportDue,
  gatherReportData,
  formatReportCsv,
  formatReportJson,
  markReportSent,
  type ScheduledReport,
} from "../lib/scheduledReports";
import { sendEmail, escapeHtml } from "../lib/email";

async function main() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }

  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    realtime: { transport: ws as unknown as WebSocketLikeConstructor },
  });

  const { data: reports, error: fetchErr } = await supabaseAdmin
    .from("scheduled_reports")
    .select("*")
    .eq("enabled", true);

  if (fetchErr) {
    console.error("Failed to fetch scheduled reports:", fetchErr.message);
    process.exit(1);
  }

  const allReports = (reports ?? []) as ScheduledReport[];
  const now = new Date();
  const due = allReports.filter((r) => isReportDue(r.next_due, now));

  console.log(`Scheduled reports: ${allReports.length} total, ${due.length} due.`);

  let sent = 0;
  let skipped = 0;
  const errors: string[] = [];

  for (const report of due) {
    try {
      const summaries = await gatherReportData(supabaseAdmin, report.owner, report.target_url);

      if (summaries.length === 0) {
        skipped++;
        continue;
      }

      const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
      const targetLabel = report.target_url ?? "all monitored sites";
      const totalFindings = summaries.reduce((sum, s) => sum + s.totalFindings, 0);
      const scoredSummaries = summaries.filter((s) => s.score !== null);
      const avgScore = scoredSummaries.length > 0
        ? Math.round(scoredSummaries.reduce((sum, s) => sum + (s.score ?? 0), 0) / scoredSummaries.length)
        : null;

      const reportData = report.format === "csv"
        ? `<pre style="background:#111;color:#ccc;padding:12px;border-radius:4px;overflow-x:auto;font-size:12px">${escapeHtml(formatReportCsv(summaries))}</pre>`
        : `<pre style="background:#111;color:#ccc;padding:12px;border-radius:4px;overflow-x:auto;font-size:12px">${escapeHtml(formatReportJson(summaries))}</pre>`;

      const subject = `Scheduled Security Report — ${escapeHtml(targetLabel)}`;
      const html = [
        `<div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto">`,
        `<h2 style="color:#39FFC0">Scheduled Security Report</h2>`,
        `<p>Report for: <strong>${escapeHtml(targetLabel)}</strong></p>`,
        `<p>Frequency: ${report.frequency} | Format: ${report.format}</p>`,
        `<table style="width:100%;border-collapse:collapse;margin:16px 0">`,
        `<tr style="background:#0D1524;color:#fff"><th style="padding:8px;text-align:left">Metric</th><th style="padding:8px;text-align:right">Value</th></tr>`,
        `<tr><td style="padding:8px">Sites scanned</td><td style="padding:8px;text-align:right">${summaries.length}</td></tr>`,
        `<tr><td style="padding:8px">Total findings</td><td style="padding:8px;text-align:right">${totalFindings}</td></tr>`,
        avgScore !== null ? `<tr><td style="padding:8px">Average score</td><td style="padding:8px;text-align:right">${avgScore}/100</td></tr>` : "",
        `</table>`,
        reportData,
        `<p><a href="${siteUrl}/dashboard" style="color:#39FFC0">View dashboard →</a></p>`,
        `<p style="color:#888;font-size:12px;margin-top:24px">Manage your scheduled reports in Dashboard → Settings.</p>`,
        `</div>`,
      ].join("\n");

      for (const recipient of report.recipients) {
        await sendEmail({ to: recipient, subject, html });
      }

      await markReportSent(supabaseAdmin, report.id, report.frequency);
      sent++;
    } catch (err) {
      errors.push(`Report ${report.id}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  console.log(`Scheduled reports: sent ${sent}, skipped ${skipped}, ${errors.length} error(s).`);
  for (const err of errors) console.error(`  - ${err}`);

  if (errors.length > 0) process.exit(1);
}

main().catch((err) => {
  console.error("send-scheduled-reports failed:", err);
  process.exit(1);
});
