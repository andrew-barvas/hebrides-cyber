// Slack alert integration.
// Posts to a user-configured incoming webhook URL — set per-subscription
// in the dashboard (subscriptions.slack_webhook_url) or globally via
// SLACK_WEBHOOK_URL env var for admin alerting.

export type SlackAlertPayload = {
  scanId: string;
  targetUrl: string;
  score: number;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  dashboardUrl: string;
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
  const { scanId, targetUrl, score, findingsCount, criticalCount, highCount, dashboardUrl } = payload;
  const emoji = severityEmoji(score);

  const text =
    `${emoji} *Security Score: ${score}/100* — \`${targetUrl}\`\n` +
    `${findingsCount} findings (${criticalCount} critical, ${highCount} high)\n` +
    `<${dashboardUrl}/dashboard/scans/${scanId}|View full report>`;

  const body = {
    text,
    blocks: [
      {
        type: "section",
        text: { type: "mrkdwn", text: `${emoji} *Hebrides Cyber — Scan Complete*` },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Target*\n\`${targetUrl}\`` },
          { type: "mrkdwn", text: `*Score*\n${score}/100` },
          { type: "mrkdwn", text: `*Critical*\n${criticalCount}` },
          { type: "mrkdwn", text: `*High*\n${highCount}` },
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
