// Microsoft Teams alert integration — parity with src/lib/slack.ts's
// sendSlackAlert, posted to a user-configured incoming webhook URL set per-
// subscription (subscriptions.ms_teams_webhook_url — see
// sql/migrations/012_ms_teams_webhook.sql for why it's not called
// teams_webhook_url).
//
// Uses the legacy "MessageCard" schema (@type: MessageCard), not the newer
// Adaptive Card format Teams Workflows-based webhooks expect. This is a
// deliberate choice, not an oversight: MessageCard is what a classic "Incoming
// Webhook" connector — still the simplest way for a small team to get a
// webhook URL into a channel — accepts, and it degrades gracefully (renders
// as a plain card) even in newer Workflow-based webhook endpoints. If Teams
// ever fully retires MessageCard rendering, this is the one thing to revisit.
import type { SlackAlertPayload } from "./slack";
import { isValidTeamsWebhookUrl } from "./webhookUrlValidation";

function severityColor(score: number): string {
  if (score < 40) return "D93F0B"; // red
  if (score < 70) return "F1C40F"; // amber
  return "2ECC71"; // green
}

export async function sendTeamsAlert(webhookUrl: string, payload: SlackAlertPayload): Promise<void> {
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

  const hasChangeData = typeof newFindingsCount === "number";
  const reportUrl = `${dashboardUrl}/dashboard/scans/${scanId}`;

  const facts = hasChangeData
    ? [
        { name: "New findings", value: String(newFindingsCount) },
        { name: "Fixed since last scan", value: String(fixedFindingsCount ?? 0) },
      ]
    : [
        { name: "Critical", value: String(criticalCount) },
        { name: "High", value: String(highCount) },
      ];

  // "summary" is the plain-text preview Teams shows in notification toasts —
  // the one place findingsCount matters here, since the card body itself
  // uses the more specific new/fixed or critical/high facts above.
  const summaryLine = hasChangeData
    ? `Hebrides Cyber — ${targetUrl} scored ${score}/100, ${newFindingsCount} new finding${newFindingsCount === 1 ? "" : "s"}`
    : `Hebrides Cyber — ${targetUrl} scored ${score}/100 (${findingsCount} finding${findingsCount === 1 ? "" : "s"})`;

  const body = {
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    themeColor: severityColor(score),
    summary: summaryLine,
    sections: [
      {
        activityTitle: hasChangeData ? "Hebrides Cyber — New findings detected" : "Hebrides Cyber — Scan complete",
        activitySubtitle: targetUrl,
        facts: [{ name: "Score", value: `${score}/100` }, ...facts],
        markdown: true,
      },
    ],
    potentialAction: [
      {
        "@type": "OpenUri",
        name: "View full report",
        targets: [{ os: "default", uri: reportUrl }],
      },
    ],
  };

  // Gated here, at the actual fetch call site — see slack.ts's identical
  // check for the full reasoning (save-path validation alone isn't enough).
  if (!isValidTeamsWebhookUrl(webhookUrl)) {
    console.error(`[ms-teams] refusing to send: "${webhookUrl}" is not a recognised Teams webhook host`);
    return;
  }

  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
  });

  if (!res.ok) {
    console.error(`[ms-teams] alert failed: ${res.status} ${await res.text()}`);
  }
}
