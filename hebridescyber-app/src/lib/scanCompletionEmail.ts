// E-50: scan-completion email notification — sends the scan owner a summary
// email whenever a scan finishes, regardless of whether new findings were
// found. Gated on `subscriptions.notify_email` (default true) and the
// notification rules from E-51 (score threshold, severity filter).
//
// Same never-throw contract as sendCriticalAlertEmail / sendSlackAlert —
// a failure here must never break the scan pipeline.
import type { SupabaseClient } from "@supabase/supabase-js";
import { sendEmail, escapeHtml } from "./email";
import type { ScanReport } from "./scanReport";
import { shouldNotify, type NotificationPrefs } from "./notificationRules";

export async function sendScanCompletionEmail(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  report: ScanReport
): Promise<void> {
  try {
    const { data: sub } = await supabaseAdmin
      .from("subscriptions")
      .select("status, notify_email, notify_score_threshold, notify_severity_min")
      .eq("owner", ownerId)
      .maybeSingle();

    if (!sub || sub.status !== "active") return;
    if (!sub.notify_email) return;

    const prefs: NotificationPrefs = {
      scoreThreshold: sub.notify_score_threshold,
      severityMin: sub.notify_severity_min,
    };

    if (!shouldNotify(report, prefs)) return;

    const { data: userRow } = await supabaseAdmin
      .from("users")
      .select("email")
      .eq("id", ownerId)
      .maybeSingle();

    const toEmail = userRow?.email;
    if (!toEmail) return;

    const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
    const host = hostnameOf(report.target_url);
    const dashboardLink = `${siteUrl}/dashboard/scans/${report.scan_id}`;

    const subject = `Scan complete: ${host} — ${report.score ?? "—"}/100`;

    const html = buildCompletionHtml({
      host,
      score: report.score,
      findingsCount: report.findings.length,
      newCount: report.new_finding_count ?? 0,
      fixedCount: report.fixed_finding_count ?? 0,
      criticalCount: report.findings.filter((f) => f.severity === "critical").length,
      highCount: report.findings.filter((f) => f.severity === "high").length,
      dashboardLink,
    });

    const result = await sendEmail({ to: toEmail, subject, html });
    if (!result.ok) {
      console.error(`[scanCompletionEmail] failed for scan ${report.scan_id}:`, result.error);
    }
  } catch (err) {
    console.error(`[scanCompletionEmail] threw for scan ${report.scan_id}:`, (err as Error).message);
  }
}

function hostnameOf(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

function buildCompletionHtml(opts: {
  host: string;
  score: number | null;
  findingsCount: number;
  newCount: number;
  fixedCount: number;
  criticalCount: number;
  highCount: number;
  dashboardLink: string;
}): string {
  const { host, score, findingsCount, newCount, fixedCount, criticalCount, highCount, dashboardLink } = opts;
  const scoreColor = score != null ? (score < 40 ? "#b91c1c" : score < 70 ? "#d97706" : "#059669") : "#6b7280";

  return `
    <div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:560px;margin:0 auto;color:#111827;">
      <h2 style="margin:0 0 8px;font-size:20px;">Scan complete: ${escapeHtml(host)}</h2>
      <div style="background:#f9fafb;border-radius:8px;padding:16px;margin-bottom:16px;">
        <div style="font-size:32px;font-weight:700;color:${scoreColor};margin-bottom:4px;">${score ?? "—"}/100</div>
      </div>
      <table style="width:100%;border-collapse:collapse;margin-bottom:20px;">
        <tr>
          <td style="padding:8px 0;font-size:14px;">Total findings</td>
          <td style="padding:8px 0;font-size:14px;font-weight:600;text-align:right;">${findingsCount}</td>
        </tr>
        <tr>
          <td style="padding:8px 0;font-size:14px;">New since last scan</td>
          <td style="padding:8px 0;font-size:14px;font-weight:600;text-align:right;">${newCount}</td>
        </tr>
        <tr>
          <td style="padding:8px 0;font-size:14px;">Fixed since last scan</td>
          <td style="padding:8px 0;font-size:14px;font-weight:600;text-align:right;color:#059669;">${fixedCount}</td>
        </tr>
        <tr>
          <td style="padding:8px 0;font-size:14px;">Critical / High</td>
          <td style="padding:8px 0;font-size:14px;font-weight:600;text-align:right;${criticalCount > 0 ? "color:#b91c1c;" : ""}">${criticalCount} / ${highCount}</td>
        </tr>
      </table>
      <p style="margin:0 0 24px;">
        <a href="${dashboardLink}" style="display:inline-block;background:#111827;color:#ffffff;padding:10px 20px;border-radius:6px;text-decoration:none;font-size:14px;">
          View full report
        </a>
      </p>
      <p style="margin:0;color:#9ca3af;font-size:12px;">
        You can disable scan completion emails in your dashboard notification settings.
      </p>
    </div>
  `;
}
