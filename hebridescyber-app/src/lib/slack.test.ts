import { describe, it, expect, vi, afterEach } from "vitest";
import { sendSlackAlert, sendSlackNotice, type SlackAlertPayload } from "./slack";

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

describe("sendSlackNotice", () => {
  const URL_OK = "https://hooks.slack.com/services/T00/B00/xyz";

  it("posts the title, escaped lines and a dashboard button", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await sendSlackNotice(URL_OK, "DNS records changed for shop.example", ["SPF record added: <!channel> & co"], "https://app.example/dashboard/assets");

    const body = JSON.parse(fetchMock.mock.calls[0][1].body as string);
    expect(body.text).toBe("*DNS records changed for shop.example*\n• SPF record added: &lt;!channel&gt; &amp; co");
    expect(body.blocks[1].text.text).toBe("• SPF record added: &lt;!channel&gt; &amp; co");
    expect(body.blocks[2].elements[0].url).toBe("https://app.example/dashboard/assets");
  });

  it("keeps the section block under Slack's 3000-character limit", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await sendSlackNotice(URL_OK, "t", [`New hostnames: ${"a".repeat(4000)}`], "https://app.example");

    const body = JSON.parse(fetchMock.mock.calls[0][1].body as string);
    expect(body.blocks[1].text.text).toHaveLength(3000);
    expect(body.blocks[1].text.text.endsWith("…")).toBe(true);
    expect(body.text.length).toBeGreaterThan(4000);
  });

  it("throws on a non-2xx answer and refuses a non-Slack host", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 403 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(sendSlackNotice(URL_OK, "t", ["x"], "https://app.example")).rejects.toThrow("Slack responded 403");
    await expect(sendSlackNotice("https://169.254.169.254/x", "t", ["x"], "https://app.example")).rejects.toThrow(/not a hooks\.slack\.com webhook/);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
