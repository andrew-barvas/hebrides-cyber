import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { decideTicketAction, ticketHostOf, buildProviderClient, type TicketLink } from "./ticketLinks";
import { sealSecrets } from "./credentialEncryption";

function link(overrides: Partial<TicketLink> = {}): TicketLink {
  return {
    id: "link-1",
    provider: "jira",
    target_host: "example.com",
    check_id: "headers.missing-csp",
    issue_key: "SEC-1",
    issue_url: "https://team.atlassian.net/browse/SEC-1",
    first_seen_at: "2026-01-01T00:00:00Z",
    last_seen_at: "2026-01-01T00:00:00Z",
    closed_at: null,
    ...overrides,
  };
}

describe("ticketHostOf", () => {
  it("lowercases the hostname and drops protocol, port, path and query", () => {
    expect(ticketHostOf("https://Example.COM:8443/some/path?x=1")).toBe("example.com");
  });

  it("treats http and https forms of the same host as one host", () => {
    expect(ticketHostOf("http://example.com")).toBe(ticketHostOf("https://example.com/"));
  });

  it("falls back to the lowercased raw string when the target isn't a valid URL", () => {
    expect(ticketHostOf("NOT A URL")).toBe("not a url");
  });
});

describe("decideTicketAction", () => {
  it("creates when no ledger row exists", () => {
    expect(decideTicketAction(null, null)).toEqual({ action: "create", reason: "no-link" });
  });

  it("creates a fresh ticket when a previously-closed finding is detected again", () => {
    // The old issue stays closed as an accurate record of the earlier fix —
    // reopening it would erase the fact that it had ever been resolved.
    const result = decideTicketAction(link({ closed_at: "2026-02-01T00:00:00Z" }), null);
    expect(result).toEqual({ action: "create", reason: "regressed" });
  });

  it("takes the regression path without needing the tracker's opinion", () => {
    // A closed row is decided locally, so the caller can skip the API call —
    // passing a state through must not change the outcome.
    expect(decideTicketAction(link({ closed_at: "2026-02-01T00:00:00Z" }), { status: "open" })).toMatchObject({
      action: "create",
      reason: "regressed",
    });
  });

  it("creates when the linked issue was deleted in the tracker", () => {
    // A stale row must never suppress ticketing for a live finding.
    expect(decideTicketAction(link(), { status: "missing" })).toEqual({ action: "create", reason: "deleted-in-tracker" });
  });

  it("reuses an open issue instead of duplicating it", () => {
    expect(decideTicketAction(link(), { status: "open" })).toEqual({
      action: "existing",
      issueKey: "SEC-1",
      issueUrl: "https://team.atlassian.net/browse/SEC-1",
      alreadyResolved: false,
    });
  });

  it("reuses — and flags — an issue a human already resolved while the finding persists", () => {
    // Opening a second ticket would override a human's explicit close; a
    // comment on the one they triaged is the right nudge.
    expect(decideTicketAction(link(), { status: "done" })).toEqual({
      action: "existing",
      issueKey: "SEC-1",
      issueUrl: "https://team.atlassian.net/browse/SEC-1",
      alreadyResolved: true,
    });
  });

  it("blocks — creating neither nor suppressing — when the tracker can't be reached", () => {
    // The critical safety branch: guessing "missing" duplicates a ticket
    // someone may be working, guessing "open" hides a real finding.
    expect(decideTicketAction(link(), { status: "unknown", error: "HTTP 503" })).toEqual({
      action: "blocked",
      error: "HTTP 503",
    });
  });

  it("blocks when an open link was never checked against the tracker", () => {
    expect(decideTicketAction(link(), null)).toMatchObject({ action: "blocked" });
  });
});

describe("buildProviderClient", () => {
  it("builds a Jira client from a complete row", () => {
    const client = buildProviderClient({
      provider: "jira",
      jira_base_url: "https://team.atlassian.net",
      jira_email: "a@example.com",
      jira_api_token: "tok",
      jira_project_key: "SEC",
    });
    expect(client?.provider).toBe("jira");
  });

  it("builds a Linear client from a complete row", () => {
    const client = buildProviderClient({ provider: "linear", linear_api_key: "lin_key", linear_team_id: "team-1" });
    expect(client?.provider).toBe("linear");
  });

  it.each([
    ["missing project key", { provider: "jira" as const, jira_base_url: "https://x.atlassian.net", jira_email: "a@b.c", jira_api_token: "t", jira_project_key: null }],
    ["missing api token", { provider: "jira" as const, jira_base_url: "https://x.atlassian.net", jira_email: "a@b.c", jira_api_token: null, jira_project_key: "SEC" }],
    ["missing team id", { provider: "linear" as const, linear_api_key: "k", linear_team_id: null }],
    ["missing api key", { provider: "linear" as const, linear_api_key: null, linear_team_id: "t" }],
  ])("returns null for a half-written integration (%s)", (_label, row) => {
    // Must be null rather than a throwing client: this is resolved inside a
    // scan's post-completion phase, where an exception would surface as a
    // failure of a scan that already succeeded.
    expect(buildProviderClient(row)).toBeNull();
  });
});

describe("buildProviderClient — secrets stored encrypted", () => {
  const original = process.env.CREDENTIALS_ENC_KEY;
  const TEST_KEY = Buffer.alloc(32, 7).toString("base64");
  const githubRow = { provider: "github" as const, github_owner: "acme", github_repo: "web", github_token: "github_pat_PLAIN" };

  beforeEach(() => {
    process.env.CREDENTIALS_ENC_KEY = TEST_KEY;
  });
  afterEach(() => {
    vi.restoreAllMocks();
    if (original === undefined) delete process.env.CREDENTIALS_ENC_KEY;
    else process.env.CREDENTIALS_ENC_KEY = original;
  });

  async function headersSentBy(row: Parameters<typeof buildProviderClient>[0]): Promise<string> {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ state: "open" }), { status: 200 }));
    await buildProviderClient(row)!.getIssue("1");
    return JSON.stringify(fetchSpy.mock.calls[0][1]?.headers);
  }

  it("sends the decrypted token to the tracker, never the ciphertext", async () => {
    const sealed = sealSecrets(githubRow, ["github_token"]);
    expect(sealed.github_token).not.toBe("github_pat_PLAIN");
    const headers = await headersSentBy(sealed);
    expect(headers).toContain("github_pat_PLAIN");
    expect(headers).not.toContain("enc:v1:");
  });

  it("still uses a legacy plaintext token that hasn't been re-saved yet", async () => {
    expect(await headersSentBy(githubRow)).toContain("github_pat_PLAIN");
  });

  it("returns null, not a client holding ciphertext, when the key is missing or rotated", () => {
    const sealed = sealSecrets(githubRow, ["github_token"]);
    delete process.env.CREDENTIALS_ENC_KEY;
    expect(buildProviderClient(sealed)).toBeNull();
    process.env.CREDENTIALS_ENC_KEY = Buffer.alloc(32, 9).toString("base64");
    expect(buildProviderClient(sealed)).toBeNull();
  });
});
