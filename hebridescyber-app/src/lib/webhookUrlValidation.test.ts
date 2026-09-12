import { describe, it, expect } from "vitest";
import { isValidSlackWebhookUrl, isValidTeamsWebhookUrl } from "./webhookUrlValidation";

describe("isValidSlackWebhookUrl", () => {
  it("accepts a real Slack incoming webhook URL", () => {
    expect(isValidSlackWebhookUrl("https://hooks.slack.com/services/T00/B00/xyz")).toBe(true);
  });

  it("rejects http (non-TLS)", () => {
    expect(isValidSlackWebhookUrl("http://hooks.slack.com/services/T00/B00/xyz")).toBe(false);
  });

  it("rejects a lookalike host that merely contains hooks.slack.com", () => {
    expect(isValidSlackWebhookUrl("https://hooks.slack.com.evil.com/services/x")).toBe(false);
    expect(isValidSlackWebhookUrl("https://evil.com/hooks.slack.com")).toBe(false);
  });

  it("rejects private/internal/metadata targets", () => {
    expect(isValidSlackWebhookUrl("https://169.254.169.254/latest/meta-data")).toBe(false);
    expect(isValidSlackWebhookUrl("https://localhost/services/x")).toBe(false);
    expect(isValidSlackWebhookUrl("https://10.0.0.5/services/x")).toBe(false);
    expect(isValidSlackWebhookUrl("https://[::1]/services/x")).toBe(false);
  });

  it("rejects malformed URLs", () => {
    expect(isValidSlackWebhookUrl("not a url")).toBe(false);
    expect(isValidSlackWebhookUrl("")).toBe(false);
  });
});

describe("isValidTeamsWebhookUrl", () => {
  it("accepts the legacy outlook.office.com and outlook.office365.com hosts", () => {
    expect(isValidTeamsWebhookUrl("https://outlook.office.com/webhook/abc")).toBe(true);
    expect(isValidTeamsWebhookUrl("https://outlook.office365.com/webhook/abc")).toBe(true);
  });

  it("accepts a tenant subdomain of webhook.office.com", () => {
    expect(isValidTeamsWebhookUrl("https://mytenant.webhook.office.com/webhookb2/abc")).toBe(true);
  });

  it("rejects http (non-TLS)", () => {
    expect(isValidTeamsWebhookUrl("http://outlook.office.com/webhook/abc")).toBe(false);
  });

  it("rejects a host where the real domain is only a suffix-adjacent lookalike", () => {
    expect(isValidTeamsWebhookUrl("https://webhook.office.com.evil.com/x")).toBe(false);
    expect(isValidTeamsWebhookUrl("https://evil.com/outlook.office.com")).toBe(false);
  });

  it("rejects private/internal/metadata targets", () => {
    expect(isValidTeamsWebhookUrl("https://169.254.169.254/latest/meta-data")).toBe(false);
    expect(isValidTeamsWebhookUrl("https://localhost/webhook/abc")).toBe(false);
    expect(isValidTeamsWebhookUrl("https://192.168.1.1/webhook/abc")).toBe(false);
  });

  it("rejects malformed URLs", () => {
    expect(isValidTeamsWebhookUrl("not a url")).toBe(false);
    expect(isValidTeamsWebhookUrl("")).toBe(false);
  });
});
