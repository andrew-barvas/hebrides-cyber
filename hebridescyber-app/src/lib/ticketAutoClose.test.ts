import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { ScanReport } from "./scanReport";

const { closeIssueMock, addCommentMock, buildProviderClientMock, findOpenTicketLinksMock, markTicketLinkClosedMock } = vi.hoisted(() => ({
  closeIssueMock: vi.fn(),
  addCommentMock: vi.fn(),
  buildProviderClientMock: vi.fn(),
  findOpenTicketLinksMock: vi.fn(),
  markTicketLinkClosedMock: vi.fn(),
}));

vi.mock("./ticketLinks", async (importOriginal) => {
  // ticketHostOf is real (pure, already covered by its own tests); only the
  // I/O-bound helpers are replaced.
  const actual = await importOriginal<typeof import("./ticketLinks")>();
  return {
    ...actual,
    buildProviderClient: buildProviderClientMock,
    findOpenTicketLinks: findOpenTicketLinksMock,
    markTicketLinkClosed: markTicketLinkClosedMock,
  };
});

import { autoCloseFixedFindingTickets } from "./ticketAutoClose";

let integrationRow: Record<string, unknown> | null = null;

function makeSupabase(): SupabaseClient {
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    order: () => builder,
    limit: () => builder,
    maybeSingle: () => Promise.resolve({ data: integrationRow }),
  };
  return { from: () => builder } as unknown as SupabaseClient;
}

function report(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    scan_id: "scan-1",
    target_url: "https://example.com",
    status: "completed",
    created_at: "2026-03-01T00:00:00Z",
    score: 80,
    findings: [],
    fixed_findings: [{ check_id: "headers.missing-csp", severity: "medium", title: "No CSP" }],
    critical_paths: [],
    ...overrides,
  };
}

function ledgerLink(checkId: string, issueKey = "SEC-1") {
  return {
    id: `link-${checkId}`,
    provider: "jira" as const,
    target_host: "example.com",
    check_id: checkId,
    issue_key: issueKey,
    issue_url: `https://team.atlassian.net/browse/${issueKey}`,
    first_seen_at: "2026-01-01T00:00:00Z",
    last_seen_at: "2026-02-01T00:00:00Z",
    closed_at: null,
  };
}

describe("autoCloseFixedFindingTickets", () => {
  beforeEach(() => {
    integrationRow = { provider: "jira", auto_close_enabled: true, jira_base_url: "https://team.atlassian.net", jira_email: "a@b.c", jira_api_token: "t", jira_project_key: "SEC" };
    closeIssueMock.mockReset().mockResolvedValue({ ok: true, detail: "Done" });
    addCommentMock.mockReset().mockResolvedValue({ ok: true });
    markTicketLinkClosedMock.mockReset().mockResolvedValue(undefined);
    findOpenTicketLinksMock.mockReset().mockResolvedValue([ledgerLink("headers.missing-csp")]);
    buildProviderClientMock.mockReset().mockReturnValue({
      provider: "jira",
      createIssue: vi.fn(),
      getIssue: vi.fn(),
      addComment: addCommentMock,
      closeIssue: closeIssueMock,
    });
  });

  it("closes the ticket, comments, and marks the ledger row closed", async () => {
    const summary = await autoCloseFixedFindingTickets(makeSupabase(), "owner-1", report());

    expect(summary).toEqual({ closed: 1, failed: 0, stillOpen: 0 });
    expect(closeIssueMock).toHaveBeenCalledWith("SEC-1");
    expect(addCommentMock).toHaveBeenCalledWith("SEC-1", expect.stringContaining("Automatically verified as fixed"));
    expect(markTicketLinkClosedMock).toHaveBeenCalledWith(expect.anything(), "link-headers.missing-csp");
  });

  // The opt-in guarantee. An account that connected Jira before this feature
  // existed must never find its board moving on its own.
  it("does nothing at all when auto-close is not enabled", async () => {
    integrationRow = { ...integrationRow, auto_close_enabled: false };

    const summary = await autoCloseFixedFindingTickets(makeSupabase(), "owner-1", report());

    expect(summary).toEqual({ closed: 0, failed: 0, stillOpen: 0 });
    expect(closeIssueMock).not.toHaveBeenCalled();
  });

  it("does nothing when there is no ticket integration at all", async () => {
    integrationRow = null;
    const summary = await autoCloseFixedFindingTickets(makeSupabase(), "owner-1", report());
    expect(summary.closed).toBe(0);
    expect(closeIssueMock).not.toHaveBeenCalled();
  });

  it("does nothing when the scan had no previous scan to diff against", async () => {
    // fixed_findings absent means nothing is *known* to be fixed — a scan
    // that found nothing is not evidence that anything was resolved.
    const summary = await autoCloseFixedFindingTickets(makeSupabase(), "owner-1", report({ fixed_findings: undefined }));
    expect(summary).toEqual({ closed: 0, failed: 0, stillOpen: 0 });
    expect(findOpenTicketLinksMock).not.toHaveBeenCalled();
  });

  it("leaves tickets open when their finding is still present", async () => {
    findOpenTicketLinksMock.mockResolvedValue([ledgerLink("tls.weak-protocol", "SEC-9")]);

    const summary = await autoCloseFixedFindingTickets(makeSupabase(), "owner-1", report());

    expect(summary).toEqual({ closed: 0, failed: 0, stillOpen: 1 });
    expect(closeIssueMock).not.toHaveBeenCalled();
  });

  // Close-first ordering: a workflow with no available done transition would
  // otherwise collect an identical comment on every nightly scan forever,
  // since nothing records that we already said it.
  it("does not comment or mark closed when the tracker close fails", async () => {
    closeIssueMock.mockResolvedValue({ ok: false, error: "No transition to a done status is available" });

    const summary = await autoCloseFixedFindingTickets(makeSupabase(), "owner-1", report());

    expect(summary).toEqual({ closed: 0, failed: 1, stillOpen: 0 });
    expect(addCommentMock).not.toHaveBeenCalled();
    expect(markTicketLinkClosedMock).not.toHaveBeenCalled();
  });

  it("processes each fixed finding independently — one failure doesn't stop the rest", async () => {
    findOpenTicketLinksMock.mockResolvedValue([ledgerLink("a.check", "SEC-1"), ledgerLink("b.check", "SEC-2")]);
    closeIssueMock
      .mockResolvedValueOnce({ ok: false, error: "workflow blocked" })
      .mockResolvedValueOnce({ ok: true, detail: "Done" });

    const summary = await autoCloseFixedFindingTickets(
      makeSupabase(),
      "owner-1",
      report({
        fixed_findings: [
          { check_id: "a.check", severity: "high", title: "A" },
          { check_id: "b.check", severity: "low", title: "B" },
        ],
      })
    );

    expect(summary).toEqual({ closed: 1, failed: 1, stillOpen: 0 });
    expect(markTicketLinkClosedMock).toHaveBeenCalledTimes(1);
  });

  it("ignores fixed findings that carry no check_id", async () => {
    // Pre-checkId scans deserialise without one and can't be matched to a
    // ledger row — skipping is correct, guessing would close the wrong ticket.
    findOpenTicketLinksMock.mockResolvedValue([ledgerLink("headers.missing-csp")]);

    const summary = await autoCloseFixedFindingTickets(
      makeSupabase(),
      "owner-1",
      report({ fixed_findings: [{ check_id: null, severity: "medium", title: "Legacy finding" }] })
    );

    expect(summary).toEqual({ closed: 0, failed: 0, stillOpen: 0 });
    expect(closeIssueMock).not.toHaveBeenCalled();
  });

  it("skips a half-written integration rather than throwing", async () => {
    buildProviderClientMock.mockReturnValue(null);
    const summary = await autoCloseFixedFindingTickets(makeSupabase(), "owner-1", report());
    expect(summary).toEqual({ closed: 0, failed: 0, stillOpen: 0 });
  });

  // Runs inside executeScan's post-completion phase — a throw here must never
  // affect a scan that has already succeeded and been recorded as completed.
  it("swallows an unexpected error and returns a no-op summary", async () => {
    findOpenTicketLinksMock.mockRejectedValue(new Error("supabase exploded"));
    const summary = await autoCloseFixedFindingTickets(makeSupabase(), "owner-1", report());
    expect(summary).toEqual({ closed: 0, failed: 0, stillOpen: 0 });
  });
});
