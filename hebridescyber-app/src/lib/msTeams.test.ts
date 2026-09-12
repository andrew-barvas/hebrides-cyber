import { describe, it, expect, vi, afterEach } from "vitest";
import { sendTeamsAlert } from "./msTeams";
import type { SlackAlertPayload } from "./slack";

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

describe("sendTeamsAlert SSRF guard", () => {
  it("posts to a real Teams tenant webhook", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await sendTeamsAlert("https://mytenant.webhook.office.com/webhookb2/abc", payload);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe("https://mytenant.webhook.office.com/webhookb2/abc");
  });

  it("rejects a non-Teams host without ever calling fetch", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(sendTeamsAlert("https://169.254.169.254/latest/meta-data", payload)).rejects.toThrow(
      /not a recognised Teams webhook host/
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects an internal/private target disguised as a normal URL", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(sendTeamsAlert("https://internal.example.corp/webhook", payload)).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
