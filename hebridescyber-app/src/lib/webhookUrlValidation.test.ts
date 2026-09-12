import { describe, it, expect } from "vitest";
import { isValidSlackWebhookUrl, isValidTeamsWebhookUrl } from "./webhookUrlValidation";

describe("isValidSlackWebhookUrl", () => {
  it("accepts a real hooks.slack.com URL", () => {
    expect(isValidSlackWebhookUrl("https://hooks.slack.com/services/T00/B00/xxx")).toBe(true);
  });

  it("rejects http (non-tls)", () => {
    expect(isValidSlackWebhookUrl("http://hooks.slack.com/services/T00/B00/xxx")).toBe(false);
  });

  it("rejects an arbitrary attacker-controlled https host — the vulnerability this fixes", () => {
    expect(isValidSlackWebhookUrl("https://attacker.example.com/collect")).toBe(false);
  });

  // Regression guard: a naive `hostname.includes("hooks.slack.com")` or
  // `endsWith("slack.com")` check would be fooled by either of these.
  it("rejects a lookalike domain with the real host as a prefix", () => {
    expect(isValidSlackWebhookUrl("https://hooks.slack.com.evil.com/services/x")).toBe(false);
  });

  it("rejects a lookalike domain with the real host as a substring", () => {
    expect(isValidSlackWebhookUrl("https://evilhooks.slack.com.attacker.net/x")).toBe(false);
  });

  it("rejects a private/metadata IP disguised as https", () => {
    expect(isValidSlackWebhookUrl("https://169.254.169.254/latest/meta-data/")).toBe(false);
  });

  it("rejects a malformed URL rather than throwing", () => {
    expect(isValidSlackWebhookUrl("not a url")).toBe(false);
  });
});

describe("isValidTeamsWebhookUrl", () => {
  it("accepts the classic outlook.office.com connector host", () => {
    expect(isValidTeamsWebhookUrl("https://outlook.office.com/webhook/abc")).toBe(true);
  });

  it("accepts outlook.office365.com", () => {
    expect(isValidTeamsWebhookUrl("https://outlook.office365.com/webhook/abc")).toBe(true);
  });

  it("accepts a tenant subdomain of the Workflows webhook.office.com host", () => {
    expect(isValidTeamsWebhookUrl("https://mytenant.webhook.office.com/webhookb2/abc")).toBe(true);
  });

  it("rejects an arbitrary attacker-controlled https host", () => {
    expect(isValidTeamsWebhookUrl("https://attacker.example.com/collect")).toBe(false);
  });

  it("rejects a lookalike domain with the real host as a suffix trick", () => {
    expect(isValidTeamsWebhookUrl("https://webhook.office.com.evil.com/x")).toBe(false);
  });

  it("rejects http (non-tls)", () => {
    expect(isValidTeamsWebhookUrl("http://outlook.office.com/webhook/abc")).toBe(false);
  });
});
