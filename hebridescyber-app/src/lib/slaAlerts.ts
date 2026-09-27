// Remediation SLA alerts: after a scan syncs a site's finding lifecycle,
// email the owner about findings that just became due soon or just breached
// their SLA — once per stage (finding_lifecycle.sla_warned_at /
// sla_breach_notified_at), so a daily scan doesn't repeat itself.
//
// Agency plan (admins exempt), matching where SLA monitoring is sold. Email
// only for now; Slack/Teams could follow via the existing channel webhooks.
// Never throws — same contract as every other post-scan hook in
// scanExecution.ts.
import type { SupabaseClient } from "@supabase/supabase-js";
import { escapeHtml, sendEmail } from "./email";
import { isMissingSchemaError } from "./dbErrors";
import { policyFromRow, selectSlaAlerts, type LifecycleRow, type SlaItem, type SlaPolicyRow } from "./slaMonitoring";

export async function hasSlaAccess(supabaseAdmin: SupabaseClient, ownerId: string): Promise<boolean> {
  const [{ data: sub }, { data: user }] = await Promise.all([
    supabaseAdmin.from("subscriptions").select("plan, status").eq("owner", ownerId).maybeSingle(),
    supabaseAdmin.from("users").select("is_admin").eq("id", ownerId).maybeSingle(),
  ]);
  return Boolean(user?.is_admin) || (sub?.plan === "agency" && sub?.status === "active");
}

function formatDays(daysRemaining: number): string {
  const days = Math.round(Math.abs(daysRemaining));
  if (daysRemaining < 0) return days === 0 ? "overdue today" : `${days} day${days === 1 ? "" : "s"} overdue`;
  return days === 0 ? "due today" : `due in ${days} day${days === 1 ? "" : "s"}`;
}

export function buildSlaAlertEmail(host: string, alerts: { dueSoon: SlaItem[]; breached: SlaItem[] }, dashboardLink: string) {
  const { dueSoon, breached } = alerts;
  const subject =
    breached.length > 0
      ? `${breached.length} finding${breached.length === 1 ? "" : "s"} past remediation SLA on ${host}`
      : `${dueSoon.length} finding${dueSoon.length === 1 ? "" : "s"} nearing remediation SLA on ${host}`;

  const rows = [...breached, ...dueSoon]
    .slice(0, 20)
    .map((item) => {
      const color = item.state === "breached" ? "#b91c1c" : "#b45309";
      return (
        `<tr>` +
        `<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;text-transform:uppercase;font-size:12px;font-weight:600;white-space:nowrap;">${escapeHtml(item.severity)}</td>` +
        `<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;">${escapeHtml(item.title)}</td>` +
        `<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:13px;color:${color};white-space:nowrap;">${formatDays(item.daysRemaining)}</td>` +
        `</tr>`
      );
    })
    .join("");
  const more = breached.length + dueSoon.length > 20 ? `<p style="font-size:13px;color:#4b5563;">…and ${breached.length + dueSoon.length - 20} more.</p>` : "";

  const html = `
    <div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:600px;margin:0 auto;color:#111827;">
      <h2 style="margin:0 0 8px;font-size:20px;">Remediation SLAs on ${escapeHtml(host)}</h2>
      <p style="margin:0 0 16px;color:#4b5563;font-size:14px;line-height:1.5;">
        ${breached.length > 0 ? `<strong>${breached.length}</strong> finding${breached.length === 1 ? " has" : "s have"} passed ${breached.length === 1 ? "its" : "their"} remediation target. ` : ""}
        ${dueSoon.length > 0 ? `<strong>${dueSoon.length}</strong> ${dueSoon.length === 1 ? "is" : "are"} close to ${dueSoon.length === 1 ? "its" : "their"} deadline.` : ""}
        Targets are counted from when each finding was first seen by a scan.
      </p>
      <table style="width:100%;border-collapse:collapse;margin-bottom:16px;">
        <thead>
          <tr>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #111827;font-size:12px;">Severity</th>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #111827;font-size:12px;">Finding</th>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #111827;font-size:12px;">SLA</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
      ${more}
      <p style="margin:0 0 24px;">
        <a href="${dashboardLink}" style="display:inline-block;background:#111827;color:#ffffff;padding:10px 20px;border-radius:6px;text-decoration:none;font-size:14px;">
          Open remediation SLAs
        </a>
      </p>
      <p style="margin:0;color:#9ca3af;font-size:12px;">
        You get one email per finding when it nears its deadline and one when it passes it.
        Change the targets or turn these off under Dashboard → SLAs.
      </p>
    </div>
  `;
  return { subject, html };
}

export async function sendSlaAlerts(supabaseAdmin: SupabaseClient, ownerId: string, host: string, now: Date = new Date()): Promise<void> {
  try {
    if (!(await hasSlaAccess(supabaseAdmin, ownerId))) return;

    const [{ data: policyRow, error: policyError }, { data: rows, error: rowsError }] = await Promise.all([
      supabaseAdmin
        .from("sla_policies")
        .select("critical_days, high_days, medium_days, low_days, warn_days, alerts_enabled")
        .eq("owner", ownerId)
        .maybeSingle(),
      supabaseAdmin
        .from("finding_lifecycle")
        .select("id, target_host, check_id, severity, title, first_seen_at, last_seen_at, resolved_at, sla_warned_at, sla_breach_notified_at")
        .eq("owner", ownerId)
        .eq("target_host", host)
        .is("resolved_at", null),
    ]);
    const loadError = policyError ?? rowsError;
    if (loadError) {
      if (!isMissingSchemaError(loadError)) console.error("[slaAlerts] load failed:", loadError.message);
      return;
    }

    const alerts = selectSlaAlerts((rows ?? []) as LifecycleRow[], policyFromRow(policyRow as SlaPolicyRow | null), now);
    if (alerts.dueSoon.length === 0 && alerts.breached.length === 0) return;

    const { data: user } = await supabaseAdmin.from("users").select("email").eq("id", ownerId).maybeSingle();
    if (!user?.email) return;

    const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
    const { subject, html } = buildSlaAlertEmail(host, alerts, `${siteUrl}/dashboard/sla`);
    const sent = await sendEmail({ to: user.email, subject, html });
    // Only mark what was actually delivered, so an email outage retries next scan.
    if (!sent.ok) {
      console.error(`[slaAlerts] email failed for ${host}:`, sent.error);
      return;
    }

    const stamp = now.toISOString();
    if (alerts.breached.length > 0) {
      await supabaseAdmin.from("finding_lifecycle").update({ sla_breach_notified_at: stamp }).in("id", alerts.breached.map((i) => i.id));
    }
    if (alerts.dueSoon.length > 0) {
      await supabaseAdmin.from("finding_lifecycle").update({ sla_warned_at: stamp }).in("id", alerts.dueSoon.map((i) => i.id));
    }
  } catch (err) {
    console.error("[slaAlerts] threw:", (err as Error).message);
  }
}
