import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const {
  authenticateApiRequestMock,
  buildProviderClientMock,
  findTicketLinkMock,
  recordTicketLinkMock,
  touchTicketLinkMock,
  createIssueMock,
  getIssueMock,
  addCommentMock,
} = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  buildProviderClientMock: vi.fn(),
  findTicketLinkMock: vi.fn(),
  recordTicketLinkMock: vi.fn(),
  touchTicketLinkMock: vi.fn(),
  createIssueMock: vi.fn(),
  getIssueMock: vi.fn(),
  addCommentMock: vi.fn(),
}));

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    order: () => builder,
    limit: () => builder,
    maybeSingle: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

vi.mock("@/lib/ticketLinks", async (importOriginal) => {
  // decideTicketAction and ticketHostOf stay REAL — the whole point of this
  // suite is that the endpoint wires the real decision table to the real
  // side effects, so stubbing the decision would test nothing.
  const actual = await importOriginal<typeof import("@/lib/ticketLinks")>();
  return {
    ...actual,
    buildProviderClient: buildProviderClientMock,
    findTicketLink: findTicketLinkMock,
    recordTicketLink: recordTicketLinkMock,
    touchTicketLink: touchTicketLinkMock,
  };
});

import handler from "@/pages/api/scans/[id]/create-ticket";

const FINDING = { checkId: "headers.missing-csp", severity: "medium", title: "No CSP", detail: "d", remediation: "r" };

function seedHappyPath() {
  queues = {
    scans: [{ data: { id: "scan-1", owner: "owner-1", target_url: "https://Example.com/path" } }],
    scan_results: [{ data: { results: { findings: [FINDING] } } }],
    ticket_integrations: [{ data: { provider: "jira", jira_base_url: "https://t.atlassian.net", jira_email: "a@b.c", jira_api_token: "t", jira_project_key: "SEC" } }],
  };
}

function mockReqRes(body: Record<string, unknown> = { checkId: "headers.missing-csp" }) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "POST", query: { id: "scan-1" }, body });
}

describe("POST /api/scans/[id]/create-ticket", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
    findTicketLinkMock.mockReset().mockResolvedValue(null);
    recordTicketLinkMock.mockReset().mockResolvedValue(undefined);
    touchTicketLinkMock.mockReset().mockResolvedValue(undefined);
    createIssueMock.mockReset().mockResolvedValue({ ok: true, url: "https://t.atlassian.net/browse/SEC-1", issueKey: "SEC-1" });
    getIssueMock.mockReset();
    addCommentMock.mockReset().mockResolvedValue({ ok: true });
    buildProviderClientMock.mockReset().mockReturnValue({
      provider: "jira",
      createIssue: createIssueMock,
      getIssue: getIssueMock,
      addComment: addCommentMock,
      closeIssue: vi.fn(),
    });
    seedHappyPath();
  });

  it("returns 405 for non-POST", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 401 when unauthenticated", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 400 without a checkId", async () => {
    const { req, res } = mockReqRes({});
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("returns 403 when the caller does not own the scan", async () => {
    queues.scans = [{ data: { id: "scan-1", owner: "someone-else", target_url: "https://example.com" } }];
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 404 when the checkId matches no finding on the scan", async () => {
    const { req, res } = mockReqRes({ checkId: "does.not-exist" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);
  });

  it("returns 501 when no integration is connected", async () => {
    queues.ticket_integrations = [{ data: null }];
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(501);
  });

  it("creates a new issue and records it in the ledger under the normalised host", async () => {
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toMatchObject({ ok: true, url: "https://t.atlassian.net/browse/SEC-1", deduplicated: false });
    // "https://Example.com/path" must be recorded as "example.com", or the
    // next scan of the same site wouldn't match this ledger row.
    expect(recordTicketLinkMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ targetHost: "example.com", checkId: "headers.missing-csp", issueKey: "SEC-1" })
    );
  });

  // The core of step 05: clicking twice must not open two identical tickets.
  it("comments on the existing issue instead of duplicating it", async () => {
    findTicketLinkMock.mockResolvedValue({
      id: "link-1",
      provider: "jira",
      target_host: "example.com",
      check_id: "headers.missing-csp",
      issue_key: "SEC-1",
      issue_url: "https://t.atlassian.net/browse/SEC-1",
      first_seen_at: "2026-01-01T00:00:00Z",
      last_seen_at: "2026-01-01T00:00:00Z",
      closed_at: null,
    });
    getIssueMock.mockResolvedValue({ status: "open" });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toMatchObject({ deduplicated: true, alreadyResolved: false, url: "https://t.atlassian.net/browse/SEC-1" });
    expect(createIssueMock).not.toHaveBeenCalled();
    expect(addCommentMock).toHaveBeenCalledWith("SEC-1", expect.stringContaining("re-detected"));
    expect(touchTicketLinkMock).toHaveBeenCalledWith(expect.anything(), "link-1");
  });

  it("flags a still-present finding whose ticket a human already resolved", async () => {
    findTicketLinkMock.mockResolvedValue({
      id: "link-1", provider: "jira", target_host: "example.com", check_id: "headers.missing-csp",
      issue_key: "SEC-1", issue_url: "https://t.atlassian.net/browse/SEC-1",
      first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-01T00:00:00Z", closed_at: null,
    });
    getIssueMock.mockResolvedValue({ status: "done" });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getJSONData()).toMatchObject({ deduplicated: true, alreadyResolved: true });
    expect(createIssueMock).not.toHaveBeenCalled();
    expect(addCommentMock).toHaveBeenCalledWith("SEC-1", expect.stringContaining("marked resolved"));
  });

  it("creates a fresh ticket when the linked issue was deleted in the tracker", async () => {
    findTicketLinkMock.mockResolvedValue({
      id: "link-1", provider: "jira", target_host: "example.com", check_id: "headers.missing-csp",
      issue_key: "SEC-GONE", issue_url: "https://t.atlassian.net/browse/SEC-GONE",
      first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-01T00:00:00Z", closed_at: null,
    });
    getIssueMock.mockResolvedValue({ status: "missing" });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getJSONData()).toMatchObject({ deduplicated: false, reason: "deleted-in-tracker" });
    expect(createIssueMock).toHaveBeenCalled();
  });

  it("creates a fresh ticket for a regression, without asking the tracker", async () => {
    findTicketLinkMock.mockResolvedValue({
      id: "link-1", provider: "jira", target_host: "example.com", check_id: "headers.missing-csp",
      issue_key: "SEC-1", issue_url: "https://t.atlassian.net/browse/SEC-1",
      first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-01T00:00:00Z",
      closed_at: "2026-02-01T00:00:00Z",
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getJSONData()).toMatchObject({ deduplicated: false, reason: "regressed" });
    expect(getIssueMock).not.toHaveBeenCalled();
    expect(createIssueMock).toHaveBeenCalled();
  });

  // Fail safe: an unreachable tracker must neither duplicate nor suppress.
  it("returns 502 and creates nothing when the tracker's state can't be determined", async () => {
    findTicketLinkMock.mockResolvedValue({
      id: "link-1", provider: "jira", target_host: "example.com", check_id: "headers.missing-csp",
      issue_key: "SEC-1", issue_url: "https://t.atlassian.net/browse/SEC-1",
      first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-01T00:00:00Z", closed_at: null,
    });
    getIssueMock.mockResolvedValue({ status: "unknown", error: "HTTP 503" });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getStatusCode()).toBe(502);
    expect(createIssueMock).not.toHaveBeenCalled();
    expect(recordTicketLinkMock).not.toHaveBeenCalled();
  });

  it("reports a failed comment rather than claiming the ticket was updated", async () => {
    findTicketLinkMock.mockResolvedValue({
      id: "link-1", provider: "jira", target_host: "example.com", check_id: "headers.missing-csp",
      issue_key: "SEC-1", issue_url: "https://t.atlassian.net/browse/SEC-1",
      first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-01T00:00:00Z", closed_at: null,
    });
    getIssueMock.mockResolvedValue({ status: "open" });
    addCommentMock.mockResolvedValue({ ok: false, error: "Jira comment failed (403)" });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getJSONData()).toMatchObject({ commentAdded: false, commentError: "Jira comment failed (403)" });
  });

  it("does not record a ledger row when issue creation fails", async () => {
    createIssueMock.mockResolvedValue({ ok: false, error: "Jira issue creation failed (400)" });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getStatusCode()).toBe(502);
    expect(recordTicketLinkMock).not.toHaveBeenCalled();
  });
});
