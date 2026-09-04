import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
}));

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    delete: () => builder,
    upsert: () => next(),
    maybeSingle: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

import handler from "@/pages/api/account/target-auth";

const TARGET_ID = "11111111-1111-1111-1111-111111111111";
const OWNER_ID = "22222222-2222-2222-2222-222222222222";

function mockReqRes(method: RequestMethod, body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method, body });
}

describe("POST/DELETE /api/account/target-auth — E-02 plan gate", () => {
  beforeEach(() => {
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
  });

  it("rejects a POST (new credential) from a non-Agency plan with 403, before writing anything", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID }, error: null }];
    queues.subscriptions = [{ data: { plan: "pro" }, error: null }];

    const { req, res } = mockReqRes("POST", { monitoredTargetId: TARGET_ID, authType: "cookie", cookieValue: "abc" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
    expect(JSON.parse(res._getData()).error).toMatch(/Agency/);
  });

  it("allows a POST from an Agency plan", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID }, error: null }];
    queues.subscriptions = [{ data: { plan: "agency" }, error: null }];
    queues.target_auth_credentials = [{ data: null, error: null }];

    const { req, res } = mockReqRes("POST", { monitoredTargetId: TARGET_ID, authType: "cookie", cookieValue: "abc" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
  });

  it("allows DELETE regardless of plan, so a downgraded account can still remove its credential", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID }, error: null }];
    queues.target_auth_credentials = [{ data: null, error: null }];

    const { req, res } = mockReqRes("DELETE", { monitoredTargetId: TARGET_ID });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    // The plan gate only runs on POST — no subscriptions queue entry was
    // even needed for this DELETE to succeed.
  });

  it("still 403s a non-owner regardless of plan (ownership check runs before the gate)", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: "someone-else" }, error: null }];

    const { req, res } = mockReqRes("POST", { monitoredTargetId: TARGET_ID, authType: "cookie", cookieValue: "abc" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
    expect(JSON.parse(res._getData()).error).toBe("Forbidden");
  });
});
