import { describe, it, expect, vi, afterEach } from "vitest";
import { sendTeamsAlert } from "./msTeams";
import type { SlackAlertPayload } from "./slack";

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

describe("sendTeamsAlert", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("posts to a real outlook.office.com URL", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, text: async () => "" });
    global.fetch = fetchMock;

    await sendTeamsAlert("https://outlook.office.com/webhook/abc", payload());

    expect(fetchMock).toHaveBeenCalledWith("https://outlook.office.com/webhook/abc", expect.any(Object));
  });

  // Regression guard — same SSRF vulnerability class as slack.test.ts's
  // equivalent case, fixed the same way (webhookUrlValidation.ts).
  it("never calls fetch for a non-Teams URL, even though it's https", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock;

    await sendTeamsAlert("https://attacker.example.com/collect", payload());

    expect(fetchMock).not.toHaveBeenCalled();
  });
});
