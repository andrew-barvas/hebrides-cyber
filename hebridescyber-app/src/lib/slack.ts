// Slack alert integration.
// Posts to a user-configured incoming webhook URL — set per-subscription
// in the dashboard (subscriptions.slack_webhook_url) or globally via
// SLACK_WEBHOOK_URL env var for admin alerting.
import { isValidSlackWebhookUrl } from "./webhookUrlValidation";

export type SlackAlertPayload = {
  scanId: string;
  targetUrl: string;
  score: number;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  dashboardUrl: string;
  // Change-since-last-scan counts. Undefined when there's no previous scan to
  // compare against (findPreviousFindings returned null) — the caller only
  // invokes sendSlackAlert at all when newFindingsCount > 0, so this is
  // always a real number in practice, but stays optional in the type to
  // match ScanReport's own new_finding_count: number | null shape.
  newFindingsCount?: number;
  fixedFindingsCount?: number;
};

function severityEmoji(score: number): string {
  if (score < 40) return "🔴";
  if (score < 70) return "🟡";
  return "🟢";
}

export async function sendSlackAlert(
  webhookUrl: string,
  payload: SlackAlertPayload
): Promise<void> {
  // SSRF guard: webhookUrl is customer-supplied (subscriptions.slack_webhook_url)
  // and this fetch runs server-side, so refuse anything that isn't Slack's
  // real webhook host rather than trusting the "https://" check alone.
  if (!isValidSlackWebhookUrl(webhookUrl)) {
    throw new Error("Refusing to send Slack alert: URL is not a hooks.slack.com webhook");
  }

  const {
    scanId,
    targetUrl,
    score,
    findingsCount,
    criticalCount,
    highCount,
    dashboardUrl,
    newFindingsCount,
    fixedFindingsCount,
  } = payload;
  const emoji = severityEmoji(score);
  const hasChangeData = typeof newFindingsCount === "number";
  const changeLine = hasChangeData
    ? `${newFindingsCount} new finding${newFindingsCount === 1 ? "" : "s"} since last scan` +
      (fixedFindingsCount ? ` · ${fixedFindingsCount} fixed` : "")
    : `${findingsCount} findings (${criticalCount} critical, ${highCount} high)`;

  const text =
    `${emoji} *Security Score: ${score}/100* — \`${targetUrl}\`\n` +
    `${changeLine}\n` +
    `<${dashboardUrl}/dashboard/scans/${scanId}|View full report>`;

  const body = {
    text,
    blocks: [
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: hasChangeData
            ? `${emoji} *Hebrides Cyber — New findings detected*`
            : `${emoji} *Hebrides Cyber — Scan Complete*`,
        },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Target*\n\`${targetUrl}\`` },
          { type: "mrkdwn", text: `*Score*\n${score}/100` },
          ...(hasChangeData
            ? [
                { type: "mrkdwn", text: `*New findings*\n${newFindingsCount}` },
                { type: "mrkdwn", text: `*Fixed since last scan*\n${fixedFindingsCount ?? 0}` },
              ]
            : [
                { type: "mrkdwn", text: `*Critical*\n${criticalCount}` },
                { type: "mrkdwn", text: `*High*\n${highCount}` },
              ]),
        ],
      },
      {
        type: "actions",
        elements: [
          {
            type: "button",
            text: { type: "plain_text", text: "View Report" },
            url: `${dashboardUrl}/dashboard/scans/${scanId}`,
            style: criticalCount > 0 ? "danger" : "primary",
          },
        ],
      },
    ],
  };

  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
  });

  if (!res.ok) {
    console.error(`[slack] alert failed: ${res.status} ${await res.text()}`);
  }
}

// ---- Emerging-threat alert (src/lib/emergingThreatAlerts.ts) ---------------

/** One newly exploited CVE matched against one site. Shared with msTeams.ts. */
export type ThreatAlertItem = {
  host: string;
  cveId: string;
  vulnerabilityName: string | null;
  product: string;
  detectedVersion: string | null;
  tier: "affected" | "possibly_affected";
  reportUrl: string;
};

/** Items shown per message; the rest are counted, and all are in the email. */
export const THREAT_ALERT_ITEM_CAP = 10;

/** Slack mrkdwn treats &, < and > as control characters. CISA's text is external. */
function slackEscape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function threatItemSummary(item: ThreatAlertItem): string {
  const seen = item.detectedVersion ? `${item.product} ${item.detectedVersion}` : `${item.product} (version not visible)`;
  return item.tier === "affected" ? `${seen} is in the affected range` : `${seen} may be affected, check your version`;
}

/**
 * Unlike sendSlackAlert, throws on a non-2xx response: the caller only marks
 * an alert delivered after a send that actually succeeded.
 */
export async function sendSlackThreatAlert(webhookUrl: string, items: ThreatAlertItem[], dashboardUrl: string): Promise<void> {
  if (!isValidSlackWebhookUrl(webhookUrl)) {
    throw new Error("Refusing to send Slack alert: URL is not a hooks.slack.com webhook");
  }
  if (items.length === 0) return;

  const shown = items.slice(0, THREAT_ALERT_ITEM_CAP);
  const lines = shown.map((item) => {
    const name = item.vulnerabilityName ? ` (${slackEscape(item.vulnerabilityName)})` : "";
    return `• \`${slackEscape(item.host)}\`: *${item.cveId}*${name}. ${slackEscape(threatItemSummary(item))}. <${item.reportUrl}|Latest report>`;
  });
  if (items.length > shown.length) lines.push(`…and ${items.length - shown.length} more. See the email for the full list.`);
  const heading =
    items.length === 1
      ? "🚨 *Hebrides Cyber: a newly exploited vulnerability matches your site*"
      : `🚨 *Hebrides Cyber: ${items.length} newly exploited vulnerabilities match your sites*`;
  const intro = "CISA has added these to its Known Exploited Vulnerabilities catalog: attackers are using them now.";

  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      text: `${heading}\n${intro}\n${lines.join("\n")}`,
      blocks: [
        { type: "section", text: { type: "mrkdwn", text: `${heading}\n${intro}` } },
        { type: "section", text: { type: "mrkdwn", text: lines.join("\n") } },
        {
          type: "actions",
          elements: [{ type: "button", text: { type: "plain_text", text: "Open dashboard" }, url: `${dashboardUrl}/dashboard`, style: "danger" }],
        },
      ],
    }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Slack responded ${res.status}`);
}

/**
 * A titled list of lines with a dashboard button: for change notices
 * (attackSurfaceMonitor.ts). Every line is escaped here. Throws on a
 * non-2xx response, so the caller only records what was delivered.
 */
const SLACK_SECTION_LIMIT = 3000;

export async function sendSlackNotice(webhookUrl: string, title: string, lines: string[], dashboardUrl: string): Promise<void> {
  if (!isValidSlackWebhookUrl(webhookUrl)) {
    throw new Error("Refusing to send Slack alert: URL is not a hooks.slack.com webhook");
  }
  const body = lines.map((l) => `• ${slackEscape(l)}`).join("\n");
  // Slack rejects a section block over 3000 characters (20 long hostnames can get there).
  const blockBody = body.length > SLACK_SECTION_LIMIT ? `${body.slice(0, SLACK_SECTION_LIMIT - 1)}…` : body;
  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      text: `*${slackEscape(title)}*\n${body}`,
      blocks: [
        { type: "section", text: { type: "mrkdwn", text: `*${slackEscape(title)}*` } },
        { type: "section", text: { type: "mrkdwn", text: blockBody } },
        { type: "actions", elements: [{ type: "button", text: { type: "plain_text", text: "Open dashboard" }, url: dashboardUrl }] },
      ],
    }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Slack responded ${res.status}`);
}

// Admin global Slack alert (for internal monitoring — not customer-facing).
export async function sendAdminSlackAlert(text: string): Promise<void> {
  const url = process.env.SLACK_WEBHOOK_URL;
  if (!url) return;
  await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
    signal: AbortSignal.timeout(10_000),
  }).catch((err) => console.error("[slack admin]", err.message));
}
