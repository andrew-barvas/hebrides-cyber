import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, planGateMock, state } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  planGateMock: vi.fn(),
  state: { tables: {} as Record<string, unknown[]>, upserts: [] as unknown[], updates: [] as unknown[] },
}));

function builder(table: string) {
  const next = () => Promise.resolve((state.tables[table] ?? []).shift() ?? { data: null, error: null });
  const b: Record<string, unknown> = {
    select: () => b,
    eq: () => b,
    maybeSingle: next,
    upsert: (row: unknown) => (state.upserts.push(row), Promise.resolve({ error: null })),
    update: (row: unknown) => (state.updates.push(row), b),
    then: (r: (v: unknown) => void) => Promise.resolve({ error: null }).then(r),
  };
  return b;
}

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authenticateApiRequestMock, supabaseAdmin: { from: (t: string) => builder(t) } }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: vi.fn() }));
vi.mock("@/lib/planAccess", () => ({ planGate: planGateMock }));

import handler from "@/pages/api/team/invites/accept";
import { newInviteToken } from "@/lib/teamInvites";

const { token } = newInviteToken();
const INVITE = { id: "inv-1", team_id: "team-1", email: "sam@example.com", role: "developer", expires_at: "2099-01-01T00:00:00Z", accepted_at: null };

async function accept(body: Record<string, unknown> = { token }) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "POST", body });
  await handler(req, res);
  return res;
}

describe("POST /api/team/invites/accept", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "user-sam", via: "session" });
    planGateMock.mockReset().mockResolvedValue("ok");
    state.tables = {
      team_invites: [{ data: INVITE, error: null }],
      users: [{ data: { email: "Sam@Example.com" }, error: null }],
      teams: [{ data: { id: "team-1", name: "Harbour Digital", owner_id: "owner-1" }, error: null }],
    };
    state.upserts = [];
    state.updates = [];
  });

  it("joins the team with the invited role and marks the invite used", async () => {
    const res = await accept();
    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toEqual({ joined: true, teamName: "Harbour Digital", role: "developer" });
    expect(state.upserts).toEqual([{ team_id: "team-1", user_id: "user-sam", role: "developer" }]);
    expect(state.updates).toHaveLength(1);
  });

  it("refuses someone signed in with a different address", async () => {
    state.tables.users = [{ data: { email: "mallory@example.com" }, error: null }];
    const res = await accept();
    expect(res._getStatusCode()).toBe(403);
    expect(state.upserts).toEqual([]);
  });

  it("refuses a malformed or unknown token without looking further", async () => {
    expect((await accept({ token: "nope" }))._getStatusCode()).toBe(404);
    state.tables.team_invites = [{ data: null, error: null }];
    expect((await accept())._getStatusCode()).toBe(404);
    expect(state.upserts).toEqual([]);
  });

  it("refuses when the team owner is no longer on Agency", async () => {
    planGateMock.mockResolvedValue("denied");
    expect((await accept())._getStatusCode()).toBe(403);
    expect(state.upserts).toEqual([]);
  });

  it("needs a signed-in session", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    expect((await accept())._getStatusCode()).toBe(401);
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "user-sam", via: "api_key" });
    expect((await accept())._getStatusCode()).toBe(403);
  });
});
