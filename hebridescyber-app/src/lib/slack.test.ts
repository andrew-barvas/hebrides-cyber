import { describe, it, expect, vi, afterEach } from "vitest";
import { sendSlackAlert, type SlackAlertPayload } from "./slack";

function payload(overrides: Partial<SlackAlertPayload> = {}): SlackAlertPayload {
  return {
    scanId: "scan-1",
    targetUrl: "https://example.com",
    score: 82,
    findingsCount: 3,
    criticalCount: 0,
    highCount: 1,
    dashboardUrl: "https://app.hebridescyber.com",
    ...overrides,
  };
}

describe("sendSlackAlert", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("posts to a real hooks.slack.com URL", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, text: async () => "" });
    global.fetch = fetchMock;

    await sendSlackAlert("https://hooks.slack.com/services/T00/B00/xxx", payload());

    expect(fetchMock).toHaveBeenCalledWith("https://hooks.slack.com/services/T00/B00/xxx", expect.any(Object));
  });

  // Regression guard: this is the actual SSRF fix. Before it, this function
  // fetch()'d whatever URL was stored in subscriptions.slack_webhook_url
  // with no validation at all — a customer (or anyone who could write that
  // column) could point "Slack alerts" at any internal or attacker-
  // controlled endpoint and have it fire on every scan completion.
  it("never calls fetch for a non-Slack URL, even though it's https", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock;

    await sendSlackAlert("https://attacker.example.com/collect", payload());

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("never calls fetch for a private-IP/metadata-endpoint URL", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock;

    await sendSlackAlert("https://169.254.169.254/latest/meta-data/", payload());

    expect(fetchMock).not.toHaveBeenCalled();
  });
});
