import { describe, it, expect, vi, afterEach } from "vitest";
import { sendSlackThreatAlert, type ThreatAlertItem } from "./slack";
import { sendTeamsThreatAlert } from "./msTeams";

const item = (n: number, over: Partial<ThreatAlertItem> = {}): ThreatAlertItem => ({
  host: "shop.example",
  cveId: `CVE-2026-${1000 + n}`,
  vulnerabilityName: "Path <Traversal> & more",
  product: "Apache HTTP Server",
  detectedVersion: "2.4.49",
  tier: "affected",
  reportUrl: "https://www.hebridescyber.co.uk/dashboard/scans/s1",
  ...over,
});

afterEach(() => vi.unstubAllGlobals());

describe("sendSlackThreatAlert", () => {
  it("posts escaped, specific lines and caps the list", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const items = Array.from({ length: 12 }, (_, i) => item(i, i === 1 ? { tier: "possibly_affected", detectedVersion: null } : {}));
    await sendSlackThreatAlert("https://hooks.slack.com/services/T00/B00/xyz", items, "https://www.hebridescyber.co.uk");
    const body = JSON.parse(fetchMock.mock.calls[0][1].body as string) as { text: string };
    expect(body.text).toContain("12 newly exploited vulnerabilities");
    expect(body.text).toContain("Path &lt;Traversal&gt; &amp; more");
    expect(body.text).toContain("Apache HTTP Server 2.4.49 is in the affected range");
    expect(body.text).toContain("Apache HTTP Server (version not visible) may be affected, check your version");
    expect(body.text).toContain("…and 2 more");
    expect(fetchMock.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal);
  });

  it("throws on a failed send so the caller doesn't mark it delivered", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 404 })));
    await expect(sendSlackThreatAlert("https://hooks.slack.com/services/T00/B00/xyz", [item(1)], "https://x")).rejects.toThrow("Slack responded 404");
  });

  it("refuses a non-Slack URL without fetching", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(sendSlackThreatAlert("https://169.254.169.254/x", [item(1)], "https://x")).rejects.toThrow(/hooks\.slack\.com/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("sendTeamsThreatAlert", () => {
  const TEAMS = "https://example.webhook.office.com/webhookb2/abc";

  it("posts a MessageCard with one fact per alert", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await sendTeamsThreatAlert(TEAMS, [item(1)], "https://www.hebridescyber.co.uk");
    const body = JSON.parse(fetchMock.mock.calls[0][1].body as string);
    expect(body.sections[0].facts).toEqual([{ name: "CVE-2026-1001 on shop.example", value: "Path <Traversal> & more. Apache HTTP Server 2.4.49 is in the affected range." }]);
    expect(body.sections[0].markdown).toBe(false);
    expect(body.potentialAction[1].targets[0].uri).toBe("https://www.hebridescyber.co.uk/dashboard/scans/s1");
  });

  it("throws on a failed send", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 500 })));
    await expect(sendTeamsThreatAlert(TEAMS, [item(1)], "https://x")).rejects.toThrow("Teams responded 500");
  });
});
