import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, checkRateLimitMock, insertMock, sendEmailMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  checkRateLimitMock: vi.fn(),
  insertMock: vi.fn(),
  sendEmailMock: vi.fn(),
}));

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    insert: insertMock,
    maybeSingle: next,
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

vi.mock("@/lib/rateLimit", () => ({
  checkRateLimit: checkRateLimitMock,
}));

vi.mock("@/lib/email", () => ({
  sendEmail: sendEmailMock,
  escapeHtml: (s: string) => s,
}));

import handler from "@/pages/api/account/request-audit";

const OWNER_ID = "33333333-3333-3333-3333-333333333333";

function mockReqRes(method: RequestMethod, body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method, body });
}

describe("POST /api/account/request-audit", () => {
  beforeEach(() => {
    queues = { users: [{ data: { email: "owner@example.com", company_name: "Acme Ltd" }, error: null }] };
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
    checkRateLimitMock.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
    insertMock.mockReset().mockResolvedValue({ error: null });
    sendEmailMock.mockReset().mockResolvedValue({ ok: true });
  });

  it("rejects non-POST methods with 405", async () => {
    const { req, res } = mockReqRes("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("rejects an unauthenticated caller with 401", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    const { req, res } = mockReqRes("POST", { tier: "small" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("rejects an API-key caller with 403 — requests must come from a logged-in session", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: OWNER_ID, via: "key" });
    const { req, res } = mockReqRes("POST", { tier: "small" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("rate-limits by owner id before touching the database", async () => {
    checkRateLimitMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 90 });
    const { req, res } = mockReqRes("POST", { tier: "small" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(429);
    expect(res._getHeaders()["retry-after"]).toBe("90");
    expect(checkRateLimitMock).toHaveBeenCalledWith(OWNER_ID, "request-audit");
    expect(insertMock).not.toHaveBeenCalled();
  });

  it("rejects an invalid tier", async () => {
    const { req, res } = mockReqRes("POST", { tier: "enterprise" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
    expect(insertMock).not.toHaveBeenCalled();
  });

  it("rejects an invalid optional targetUrl", async () => {
    const { req, res } = mockReqRes("POST", { tier: "small", targetUrl: "not a url" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("saves the request against the account's own email/company and sends a notification", async () => {
    const { req, res } = mockReqRes("POST", { tier: "standard", targetUrl: "https://example.com", notes: "Please quote." });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(insertMock).toHaveBeenCalledWith(
      expect.objectContaining({
        email: "owner@example.com",
        company: "Acme Ltd",
        url: "https://example.com",
        budget_range: "300_800",
        message: expect.stringContaining("Standard Web App Audit"),
      })
    );
    expect(sendEmailMock).toHaveBeenCalled();
  });

  it("maps each tier to its matching budget bucket", async () => {
    const cases: Array<[string, string]> = [
      ["small", "under_300"],
      ["standard", "300_800"],
      ["full", "800_1800"],
    ];
    for (const [tier, budgetRange] of cases) {
      insertMock.mockClear();
      queues.users = [{ data: { email: "owner@example.com", company_name: "Acme Ltd" }, error: null }];
      const { req, res } = mockReqRes("POST", { tier });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(200);
      expect(insertMock).toHaveBeenCalledWith(expect.objectContaining({ budget_range: budgetRange }));
    }
  });

  it("returns 404 if the caller has no users row", async () => {
    queues.users = [{ data: null, error: null }];
    const { req, res } = mockReqRes("POST", { tier: "small" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);
    expect(insertMock).not.toHaveBeenCalled();
  });

  it("returns 500 if the database insert fails, without sending an email", async () => {
    insertMock.mockResolvedValue({ error: { message: "db down" } });
    const { req, res } = mockReqRes("POST", { tier: "small" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(500);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("still returns 200 if the notification email fails to send (non-fatal)", async () => {
    sendEmailMock.mockResolvedValue({ ok: false, error: "resend down" });
    const { req, res } = mockReqRes("POST", { tier: "small" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
  });
});
