import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, logAuditEventMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  logAuditEventMock: vi.fn(),
}));

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    ilike: () => builder,
    insert: () => next(),
    maybeSingle: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));

import handler from "@/pages/api/team/members";

const TEAM_ID = "33333333-3333-3333-3333-333333333333";
const OWNER_ID = "22222222-2222-2222-2222-222222222222";
const INVITEE_ID = "44444444-4444-4444-4444-444444444444";

function mockReqRes(method: RequestMethod, body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method, body });
}

describe("POST /api/team/members (invite) — E-02 plan gate", () => {
  beforeEach(() => {
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
    logAuditEventMock.mockReset().mockResolvedValue(undefined);
  });

  it("rejects an invite when the team owner has since downgraded off Agency, even though the caller IS the owner", async () => {
    queues.teams = [{ data: { id: TEAM_ID, owner_id: OWNER_ID }, error: null }];
    queues.subscriptions = [{ data: { plan: "pro", status: "active" }, error: null }];

    const { req, res } = mockReqRes("POST", { team_id: TEAM_ID, email: "new@example.com" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
    expect(JSON.parse(res._getData()).error).toMatch(/Agency/);
  });

  it("rejects an invite when the owner's Agency subscription is cancelled (plan unchanged, status not active)", async () => {
    queues.teams = [{ data: { id: TEAM_ID, owner_id: OWNER_ID }, error: null }];
    queues.subscriptions = [{ data: { plan: "agency", status: "cancelled" }, error: null }];

    const { req, res } = mockReqRes("POST", { team_id: TEAM_ID, email: "new@example.com" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
  });

  it("allows an invite when the team owner is on Agency", async () => {
    queues.teams = [{ data: { id: TEAM_ID, owner_id: OWNER_ID }, error: null }];
    queues.subscriptions = [{ data: { plan: "agency", status: "active" }, error: null }];
    queues.users = [
      { data: { is_admin: false }, error: null }, // planGate's admin check
      { data: { id: INVITEE_ID, email: "new@example.com" }, error: null },
    ];
    queues.team_members = [
      { data: null, error: null }, // existing-membership check
      { data: [], error: null }, // current member count
      { data: null, error: null }, // the insert itself
    ];

    const { req, res } = mockReqRes("POST", { team_id: TEAM_ID, email: "new@example.com" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(201);
  });
});
