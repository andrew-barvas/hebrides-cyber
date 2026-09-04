// Critical-finding alert email — fires when a completed scan surfaces new
// critical/high severity findings, for ANY active plan (Basic included).
//
// The pricing page sells Basic as including "critical alerts", but until
// this file existed the only alerting path was Slack's sendChangeAlertIfDue
// (src/lib/scanExecution.ts), which is gated to plan === "pro" || "agency"
// because a Slack webhook is itself a paid-tier configuration item. Email
// has no such reason to be gated — every paying customer, Basic included,
// should hear about new critical findings by email even without Slack
// configured. This is what closes that gap.
//
// Deliberately its own module rather than added to scanExecution.ts: that
// file is being edited by its owner concurrently, so this only supplies the
// function to import and the exact call-site snippet to wire in.
import type { SupabaseClient } from "@supabase/supabase-js";
import { sendEmail, escapeHtml } from "./email";
import type { ScanReport } from "./scanReport";

const ALERTABLE_SEVERITIES = new Set(["critical", "high"]);

/**
 * Sends the scan owner a "new critical findings" email for this report, if
 * warranted. Never throws — same contract as sendChangeAlertIfDue, so a
 * failure here can never break the scan pipeline that calls it.
 *
 * Trigger condition: report.new_finding_count > 0 (a previous scan of this
 * target exists and something changed) AND at least one of the *new*
 * findings (status === "new", not just any finding in the report) is
 * critical or high severity. A report full of new "info" findings, or a
 * first-ever scan (new_finding_count === null, nothing to compare against),
 * does not fire.
 */
export async function sendCriticalAlertEmail(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  report: ScanReport
): Promise<void> {
  try {
    if (!report.new_finding_count) return; // null (no previous scan) or 0 — nothing changed

    const newAlertableFindings = report.findings.filter(
      (f) => f.status === "new" && ALERTABLE_SEVERITIES.has(f.severity)
    );
    if (newAlertableFindings.length === 0) return;

    // Any active plan qualifies — Basic included. This is intentionally NOT
    // gated to plan in ("pro", "agency") the way the Slack alert is.
    const { data: sub } = await supabaseAdmin
      .from("subscriptions")
      .select("status")
      .eq("owner", ownerId)
      .maybeSingle();
    if (!sub || sub.status !== "active") return;

    // public.users duplicates auth.users.email for exactly this kind of
    // lookup (see sql/migrations/001_init.sql) — cheaper than
    // supabaseAdmin.auth.admin.getUserById for a single column.
    const { data: userRow } = await supabaseAdmin
      .from("users")
      .select("email")
      .eq("id", ownerId)
      .maybeSingle();

    const toEmail = userRow?.email;
    if (!toEmail) {
      console.error(`[scanAlerts] no email on file for owner ${ownerId}, skipping critical alert for scan ${report.scan_id}`);
      return;
    }

    const criticalCount = newAlertableFindings.filter((f) => f.severity === "critical").length;
    const highCount = newAlertableFindings.filter((f) => f.severity === "high").length;
    const topFindings = [...newAlertableFindings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity)).slice(0, 3);

    const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
    const dashboardLink = `${siteUrl}/dashboard/scans/${report.scan_id}`;
    const host = hostnameOf(report.target_url);

    const subject =
      criticalCount > 0
        ? `New critical finding${criticalCount === 1 ? "" : "s"} on ${host}`
        : `New high-severity finding${highCount === 1 ? "" : "s"} on ${host}`;

    const html = buildAlertHtml({
      host,
      score: report.score,
      newCount: newAlertableFindings.length,
      criticalCount,
      highCount,
      topFindings,
      dashboardLink,
    });

    const result = await sendEmail({ to: toEmail, subject, html });
    if (!result.ok) {
      console.error(`[scanAlerts] critical alert email failed for scan ${report.scan_id}:`, result.error);
    }
  } catch (err) {
    console.error(`[scanAlerts] critical alert email threw for scan ${report.scan_id}:`, (err as Error).message);
  }
}

function severityRank(severity: string): number {
  return severity === "critical" ? 0 : severity === "high" ? 1 : 2;
}

function hostnameOf(targetUrl: string): string {
  try {
    return new URL(targetUrl).hostname;
  } catch {
    return targetUrl;
  }
}

function buildAlertHtml(opts: {
  host: string;
  score: number | null;
  newCount: number;
  criticalCount: number;
  highCount: number;
  topFindings: ScanReport["findings"];
  dashboardLink: string;
}): string {
  const { host, score, newCount, criticalCount, highCount, topFindings, dashboardLink } = opts;

  const findingRows = topFindings
    .map((f) => {
      const color = f.severity === "critical" ? "#b91c1c" : "#c2410c";
      return (
        `<tr>` +
        `<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;text-transform:uppercase;font-size:12px;font-weight:600;color:${color};white-space:nowrap;">${escapeHtml(f.severity)}</td>` +
        `<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;">${escapeHtml(f.title)}</td>` +
        `</tr>`
      );
    })
    .join("");

  return `
    <div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:560px;margin:0 auto;color:#111827;">
      <h2 style="margin:0 0 8px;font-size:20px;">New critical findings on ${escapeHtml(host)}</h2>
      <p style="margin:0 0 16px;color:#4b5563;font-size:14px;line-height:1.5;">
        Your latest Security Score scan found <strong>${newCount}</strong> new
        finding${newCount === 1 ? "" : "s"} rated critical or high severity
        (${criticalCount} critical, ${highCount} high) that weren't present
        in the previous scan.
      </p>
      <p style="margin:0 0 16px;font-size:14px;">
        <strong>Current Security Score:</strong> ${score ?? "—"}/100
      </p>
      <table style="width:100%;border-collapse:collapse;margin-bottom:20px;">
        <thead>
          <tr>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #111827;font-size:12px;">Severity</th>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #111827;font-size:12px;">Finding</th>
          </tr>
        </thead>
        <tbody>${findingRows}</tbody>
      </table>
      <p style="margin:0 0 24px;">
        <a href="${dashboardLink}" style="display:inline-block;background:#111827;color:#ffffff;padding:10px 20px;border-radius:6px;text-decoration:none;font-size:14px;">
          View full report
        </a>
      </p>
      <p style="margin:0;color:#9ca3af;font-size:12px;">
        You're receiving this because critical alerts are included with your
        Hebrides Cyber plan. Manage monitored targets from your dashboard.
      </p>
    </div>
  `;
}
