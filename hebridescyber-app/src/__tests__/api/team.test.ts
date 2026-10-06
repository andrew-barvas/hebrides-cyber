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
    order: () => builder,
    in: () => builder,
    insert: () => builder,
    single: next,
    maybeSingle: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

import handler from "@/pages/api/team";

const OWNER_ID = "22222222-2222-2222-2222-222222222222";

function mockReqRes(method: RequestMethod, body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method, body });
}

describe("POST /api/team (createTeam) — E-02 plan gate", () => {
  beforeEach(() => {
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
  });

  it("rejects team creation from a non-Agency plan with 403, before checking for an existing team", async () => {
    queues.subscriptions = [{ data: { plan: "basic", status: "active" }, error: null }];

    const { req, res } = mockReqRes("POST", { name: "My Team" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
    expect(JSON.parse(res._getData()).error).toMatch(/Agency/);
  });

  it("rejects team creation from a cancelled Agency subscription", async () => {
    queues.subscriptions = [{ data: { plan: "agency", status: "cancelled" }, error: null }];

    const { req, res } = mockReqRes("POST", { name: "Ops" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
  });

  it("allows team creation from an Agency plan", async () => {
    queues.subscriptions = [{ data: { plan: "agency", status: "active" }, error: null }];
    queues.teams = [
      { data: null, error: null }, // "do they already own a team" check
      { data: { id: "t1", name: "My Team", created_at: "2026-01-01" }, error: null }, // insert result
    ];

    const { req, res } = mockReqRes("POST", { name: "My Team" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(201);
  });

  it("leaves GET (viewing the team) unaffected by plan — a downgraded owner can still see who's on it", async () => {
    queues.teams = [{ data: null, error: null }];
    queues.team_members = [{ data: [], error: null }];

    const { req, res } = mockReqRes("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
  });
});
