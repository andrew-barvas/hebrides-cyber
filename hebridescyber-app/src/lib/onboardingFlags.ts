// What the dashboard's onboarding checklist (OnboardingChecklist.tsx) counts
// as done. Pure, so each rule is tested on its own; the dashboard page only
// gathers the counts.
//
// - "Run your first scan" counts a scan only once it got past `pending`:
//   run-scan creates the row before ownership is checked, so a refused
//   attempt on an unverified domain leaves a pending row behind, and that
//   used to tick the step.
// - "Set up alerts" is done by any channel that will actually tell someone:
//   an active plan's critical-finding emails (scanAlerts.ts sends them on
//   every paid plan), an outbound webhook, Slack, Teams, or an on-call
//   integration (PagerDuty, Opsgenie).

export type OnboardingInput = {
  verifiedDomainCount: number;
  /** Scans past `pending`: queued, running, completed or failed. */
  startedScanCount: number;
  hasCompletedScan: boolean;
  /** The plan while its subscription is active, else "none". */
  activePlan: "none" | "basic" | "pro" | "agency";
  webhookCount: number;
  slackWebhookUrl: string | null;
  teamsWebhookUrl: string | null;
  onCallCount: number;
};

export type OnboardingFlags = {
  verifiedDomain: boolean;
  hasScanned: boolean;
  hasReport: boolean;
  hasAlertChannel: boolean;
  /** Which alert step to suggest: Slack/Teams on Pro and Agency, a webhook otherwise. */
  alertChannelIsSlackTeams: boolean;
};

export function deriveOnboardingFlags(input: OnboardingInput): OnboardingFlags {
  const paid = input.activePlan !== "none";
  return {
    verifiedDomain: input.verifiedDomainCount > 0,
    hasScanned: input.startedScanCount > 0,
    hasReport: input.hasCompletedScan,
    hasAlertChannel: paid || input.webhookCount > 0 || Boolean(input.slackWebhookUrl) || Boolean(input.teamsWebhookUrl) || input.onCallCount > 0,
    alertChannelIsSlackTeams: input.activePlan === "pro" || input.activePlan === "agency",
  };
}
