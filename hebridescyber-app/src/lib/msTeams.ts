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
import { THREAT_ALERT_ITEM_CAP, threatItemSummary, type SlackAlertPayload, type ThreatAlertItem } from "./slack";
import { isValidTeamsWebhookUrl } from "./webhookUrlValidation";

function severityColor(score: number): string {
  if (score < 40) return "D93F0B"; // red
  if (score < 70) return "F1C40F"; // amber
  return "2ECC71"; // green
}

export async function sendTeamsAlert(webhookUrl: string, payload: SlackAlertPayload): Promise<void> {
  // SSRF guard: webhookUrl is customer-supplied (subscriptions.ms_teams_webhook_url)
  // and this fetch runs server-side, so refuse anything that isn't a real
  // Teams webhook host rather than trusting the "https://" check alone.
  if (!isValidTeamsWebhookUrl(webhookUrl)) {
    throw new Error("Refusing to send Teams alert: URL is not a recognised Teams webhook host");
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

/**
 * Emerging-threat alert (src/lib/emergingThreatAlerts.ts), parity with
 * slack.ts's sendSlackThreatAlert. Throws on a non-2xx response so the caller
 * only marks an alert delivered after a send that actually succeeded.
 * markdown is off: the vulnerability names are CISA's text, not ours.
 */
export async function sendTeamsThreatAlert(webhookUrl: string, items: ThreatAlertItem[], dashboardUrl: string): Promise<void> {
  if (!isValidTeamsWebhookUrl(webhookUrl)) {
    throw new Error("Refusing to send Teams alert: URL is not a recognised Teams webhook host");
  }
  if (items.length === 0) return;

  const shown = items.slice(0, THREAT_ALERT_ITEM_CAP);
  const title =
    items.length === 1
      ? "Hebrides Cyber: a newly exploited vulnerability matches your site"
      : `Hebrides Cyber: ${items.length} newly exploited vulnerabilities match your sites`;
  const facts = shown.map((item) => ({
    name: `${item.cveId} on ${item.host}`,
    value: `${item.vulnerabilityName ? `${item.vulnerabilityName}. ` : ""}${threatItemSummary(item)}.`,
  }));
  if (items.length > shown.length) facts.push({ name: "More", value: `${items.length - shown.length} more in the email` });

  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      "@type": "MessageCard",
      "@context": "http://schema.org/extensions",
      themeColor: "D93F0B",
      summary: title,
      sections: [
        {
          activityTitle: title,
          activitySubtitle: "CISA has added these to its Known Exploited Vulnerabilities catalog: attackers are using them now.",
          facts,
          markdown: false,
        },
      ],
      potentialAction: [
        { "@type": "OpenUri", name: "Open dashboard", targets: [{ os: "default", uri: `${dashboardUrl}/dashboard` }] },
        ...(items.length === 1 ? [{ "@type": "OpenUri", name: "Latest report", targets: [{ os: "default", uri: items[0].reportUrl }] }] : []),
      ],
    }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Teams responded ${res.status}`);
}
