import { describe, it, expect, vi, afterEach } from "vitest";
import { sendSlackAlert, type SlackAlertPayload } from "./slack";

const payload: SlackAlertPayload = {
  scanId: "scan-1",
  targetUrl: "https://example.com",
  score: 82,
  findingsCount: 3,
  criticalCount: 0,
  highCount: 1,
  dashboardUrl: "https://www.hebridescyber.co.uk",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("sendSlackAlert SSRF guard", () => {
  it("posts to a real hooks.slack.com webhook", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await sendSlackAlert("https://hooks.slack.com/services/T00/B00/xyz", payload);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe("https://hooks.slack.com/services/T00/B00/xyz");
  });

  it("rejects a non-Slack host without ever calling fetch", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(sendSlackAlert("https://169.254.169.254/latest/meta-data", payload)).rejects.toThrow(
      /not a hooks\.slack\.com webhook/
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects an internal/private target disguised as a normal URL", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(sendSlackAlert("https://internal.example.corp/webhook", payload)).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
