import { describe, it, expect, vi, afterEach } from "vitest";
import { sendTeamsAlert, sendTeamsNotice } from "./msTeams";
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

describe("sendTeamsNotice", () => {
  const URL_OK = "https://mytenant.webhook.office.com/webhookb2/abc";

  it("posts a card with the lines as plain text and a dashboard link", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await sendTeamsNotice(URL_OK, "2 new hostnames found for shop.example", ["New hostnames: a.shop.example, b.shop.example", "Why"], "https://app.example/dashboard/assets");

    const card = JSON.parse(fetchMock.mock.calls[0][1].body as string);
    expect(card.summary).toBe("2 new hostnames found for shop.example");
    expect(card.sections[0]).toEqual({ activityTitle: "2 new hostnames found for shop.example", text: "New hostnames: a.shop.example, b.shop.example\n\nWhy", markdown: false });
    expect(card.potentialAction[0].targets[0].uri).toBe("https://app.example/dashboard/assets");
  });

  it("throws on a non-2xx answer and refuses a non-Teams host", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 400 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(sendTeamsNotice(URL_OK, "t", ["x"], "https://app.example")).rejects.toThrow("Teams responded 400");
    await expect(sendTeamsNotice("https://internal.example.corp/hook", "t", ["x"], "https://app.example")).rejects.toThrow(/not a recognised Teams webhook host/);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
