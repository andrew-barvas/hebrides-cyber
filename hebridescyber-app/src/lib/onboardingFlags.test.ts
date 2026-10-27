import { describe, it, expect } from "vitest";
import { deriveOnboardingFlags, type OnboardingInput } from "./onboardingFlags";

const nothing: OnboardingInput = {
  verifiedDomainCount: 0,
  startedScanCount: 0,
  hasCompletedScan: false,
  activePlan: "none",
  webhookCount: 0,
  slackWebhookUrl: null,
  teamsWebhookUrl: null,
  onCallCount: 0,
};

describe("deriveOnboardingFlags", () => {
  it("is all not-done for a new free account", () => {
    expect(deriveOnboardingFlags(nothing)).toEqual({
      verifiedDomain: false,
      hasScanned: false,
      hasReport: false,
      hasAlertChannel: false,
      alertChannelIsSlackTeams: false,
    });
  });

  it("counts a scan only once it got past pending, and a report only once one completed", () => {
    // A refused attempt on an unverified domain leaves only a pending row, which the caller doesn't count.
    expect(deriveOnboardingFlags({ ...nothing, startedScanCount: 0 }).hasScanned).toBe(false);
    expect(deriveOnboardingFlags({ ...nothing, startedScanCount: 1 })).toMatchObject({ hasScanned: true, hasReport: false });
    expect(deriveOnboardingFlags({ ...nothing, startedScanCount: 1, hasCompletedScan: true }).hasReport).toBe(true);
    expect(deriveOnboardingFlags({ ...nothing, verifiedDomainCount: 2 }).verifiedDomain).toBe(true);
  });

  it("treats any working alert channel as done: plan emails, webhook, Slack, Teams, on-call", () => {
    for (const extra of [
      { activePlan: "basic" as const },
      { webhookCount: 1 },
      { slackWebhookUrl: "https://hooks.slack.com/services/x" },
      { teamsWebhookUrl: "https://example.webhook.office.com/x" },
      { onCallCount: 1 },
    ]) {
      expect(deriveOnboardingFlags({ ...nothing, ...extra }).hasAlertChannel).toBe(true);
    }
    expect(deriveOnboardingFlags({ ...nothing, slackWebhookUrl: "" }).hasAlertChannel).toBe(false);
  });

  it("suggests Slack/Teams on Pro and up, a webhook otherwise", () => {
    expect(deriveOnboardingFlags({ ...nothing, activePlan: "pro" }).alertChannelIsSlackTeams).toBe(true);
    expect(deriveOnboardingFlags({ ...nothing, activePlan: "agency" }).alertChannelIsSlackTeams).toBe(true);
    expect(deriveOnboardingFlags({ ...nothing, activePlan: "tier_a" }).alertChannelIsSlackTeams).toBe(true);
    expect(deriveOnboardingFlags({ ...nothing, activePlan: "basic" }).alertChannelIsSlackTeams).toBe(false);
  });

  it("counts Tier A's plan emails as an alert channel", () => {
    expect(deriveOnboardingFlags({ ...nothing, activePlan: "tier_a" }).hasAlertChannel).toBe(true);
  });
});
