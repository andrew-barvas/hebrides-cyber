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

  // Gated here, at the actual fetch call site, not just at the save path
  // (notification-webhooks.ts validates too, but that's defense in depth —
  // this is the check that actually matters, since it's the one place every
  // outbound request funnels through regardless of how the URL got saved.
  if (!isValidSlackWebhookUrl(webhookUrl)) {
    console.error(`[slack] refusing to send: "${webhookUrl}" is not a hooks.slack.com URL`);
    return;
  }

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
