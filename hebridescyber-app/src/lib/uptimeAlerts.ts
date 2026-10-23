// Down / recovered notifications for the bring-your-own uptime offering.
// One message per outage (uptimeService.ts's decideUptimeAlert decides when),
// sent to every channel the owner already configured: Slack and Teams
// webhooks on their subscription, and email. Never throws; a channel that
// fails is logged and the others still go out.
import type { SupabaseClient } from "@supabase/supabase-js";
import { escapeHtml, sendEmail } from "./email";
import { sendSlackNotice } from "./slack";
import { sendTeamsNotice } from "./msTeams";
import { hostnameFromUrl } from "./ownership";
import type { UptimeAlertKind } from "./uptimeService";

const SITE_URL = (process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk").replace(/\/$/, "");

export function buildUptimeMessage(kind: UptimeAlertKind, targetUrl: string): { subject: string; title: string; lines: string[] } {
  let host = targetUrl;
  try {
    host = hostnameFromUrl(targetUrl);
  } catch {
    // keep the raw value
  }
  if (kind === "down") {
    return {
      subject: `${host} is down`,
      title: `Site down: ${host}`,
      lines: [`Your UptimeRobot monitor reports ${host} as down.`, "You will get one more message when it recovers."],
    };
  }
  return {
    subject: `${host} is back up`,
    title: `Recovered: ${host}`,
    lines: [`Your UptimeRobot monitor reports ${host} as up again.`],
  };
}

export async function sendUptimeAlert(db: SupabaseClient, ownerId: string, kind: UptimeAlertKind, targetUrl: string): Promise<void> {
  try {
    const { subject, title, lines } = buildUptimeMessage(kind, targetUrl);
    const dashboard = `${SITE_URL}/dashboard/integrations`;
    const [{ data: sub }, { data: user }] = await Promise.all([
      db.from("subscriptions").select("slack_webhook_url, ms_teams_webhook_url").eq("owner", ownerId).maybeSingle(),
      db.from("users").select("email").eq("id", ownerId).maybeSingle(),
    ]);

    const sends: Array<Promise<unknown>> = [];
    if (sub?.slack_webhook_url) {
      sends.push(sendSlackNotice(sub.slack_webhook_url as string, title, lines, dashboard).catch((err) => console.error("[uptimeAlerts] Slack failed:", (err as Error).message)));
    }
    if (sub?.ms_teams_webhook_url) {
      sends.push(sendTeamsNotice(sub.ms_teams_webhook_url as string, title, lines, dashboard).catch((err) => console.error("[uptimeAlerts] Teams failed:", (err as Error).message)));
    }
    if (user?.email) {
      const html =
        `<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:560px;color:#111827;">` +
        `<h2 style="margin:0 0 8px;font-size:20px;">${escapeHtml(title)}</h2>` +
        lines.map((l) => `<p style="margin:0 0 8px;font-size:14px;color:#4b5563;">${escapeHtml(l)}</p>`).join("") +
        `<p style="margin:16px 0 0;"><a href="${dashboard}">Open your uptime dashboard</a></p>` +
        `<p style="margin:16px 0 0;font-size:12px;color:#9ca3af;">Sent because you connected your UptimeRobot account to Hebrides Cyber.</p></div>`;
      sends.push(sendEmail({ to: user.email as string, subject, html }).catch((err) => console.error("[uptimeAlerts] email failed:", (err as Error).message)));
    }
    await Promise.all(sends);
  } catch (err) {
    console.error("[uptimeAlerts] failed:", (err as Error).message);
  }
}
