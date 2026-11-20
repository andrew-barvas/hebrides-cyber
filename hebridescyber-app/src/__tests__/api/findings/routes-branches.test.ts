import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

// Branches of the findings routes added since 2026-11-18 that their main
// tests don't reach: accounts for an API key, the assign route's account
// lookup, failures, and unassign errors.

const m = vi.hoisted(() => ({
  auth: vi.fn(),
  canView: vi.fn(),
  list: vi.fn(),
  assignees: vi.fn(),
  audit: vi.fn(),
  email: vi.fn(),
  db: { selectError: null as unknown, deleteError: null as unknown, upsertError: null as unknown },
}));

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: m.auth,
  supabaseAdmin: {
    from: () => {
      const q: Record<string, unknown> = {
        select: () => q, eq: () => q,
        limit: async () => ({ data: [], error: m.db.selectError }),
        delete: () => {
          const d: Record<string, unknown> = { eq: () => d, then: (r: (v: unknown) => void) => r({ error: m.db.deleteError }) };
          return d;
        },
        upsert: async () => ({ error: m.db.upsertError }),
      };
      return q;
    },
  },
}));
vi.mock("@/lib/teamAccess", () => ({ callerCanView: m.canView, listViewableAccounts: m.list }));
vi.mock("@/lib/findingAssignments", async (o) => ({ ...(await o<typeof import("@/lib/findingAssignments")>()), loadAssignees: m.assignees }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: m.audit }));
vi.mock("@/lib/email", async (o) => ({ ...(await o<typeof import("@/lib/email")>()), sendEmail: m.email }));

import accounts from "@/pages/api/findings/accounts";
import assign from "@/pages/api/findings/assign";

const ME = "11111111-1111-4111-8111-111111111111";
const BOSS = "33333333-3333-4333-8333-333333333333";
const DEV = "22222222-2222-4222-8222-222222222222";

async function call(handler: typeof assign, method: RequestMethod, body?: unknown, query: Record<string, string> = {}) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, body: body as Record<string, unknown>, query });
  await handler(req, res);
  return { status: res._getStatusCode(), body: JSON.parse(res._getData() || "{}") as Record<string, unknown> };
}

const ITEMS = [{ targetHost: "www.example.com", checkId: "headers.hsts" }];

beforeEach(() => {
  m.auth.mockReset().mockResolvedValue({ ownerId: ME, via: "session" });
  m.canView.mockReset().mockResolvedValue(true);
  m.list.mockReset().mockResolvedValue([]);
  m.assignees.mockReset().mockResolvedValue({ ok: true, assignees: [{ id: ME, email: "me@x.test", role: "owner" }, { id: DEV, email: null, role: "member" }] });
  m.audit.mockReset();
  m.email.mockReset().mockResolvedValue({ ok: true });
  m.db.selectError = null;
  m.db.deleteError = null;
  m.db.upsertError = null;
});

describe("GET /api/findings/accounts", () => {
  it("answers 405/401, and an API key only ever sees its own account", async () => {
    expect((await call(accounts, "POST")).status).toBe(405);
    m.auth.mockResolvedValueOnce(null);
    expect((await call(accounts, "GET")).status).toBe(401);
    m.auth.mockResolvedValueOnce({ ownerId: ME, via: "api_key" });
    expect((await call(accounts, "GET")).body).toEqual({ accounts: [{ ownerId: ME, email: null, role: "owner", own: true }] });
    expect(m.list).not.toHaveBeenCalled();
  });
});

describe("/api/findings/assign branches", () => {
  it("answers 405 for other methods", async () => {
    expect((await call(assign, "DELETE")).status).toBe(405);
  });

  it("lets a team member read the owner's assignee list, and refuses others", async () => {
    const ok = await call(assign, "GET", undefined, { account: BOSS });
    expect(ok.status).toBe(200);
    expect(m.assignees).toHaveBeenCalledWith(expect.anything(), BOSS);
    m.canView.mockResolvedValueOnce(false);
    expect((await call(assign, "GET", undefined, { account: BOSS })).status).toBe(404);
    m.auth.mockResolvedValueOnce({ ownerId: ME, via: "api_key" });
    expect((await call(assign, "GET", undefined, { account: BOSS })).status).toBe(404);
  });

  it("500s when the assignees or the table can't be read", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    m.assignees.mockResolvedValueOnce({ ok: false });
    expect((await call(assign, "GET")).status).toBe(500);
    m.db.selectError = { message: "boom" };
    expect((await call(assign, "GET")).status).toBe(500);
    err.mockRestore();
  });

  it("maps unassign and assign write failures", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    m.db.deleteError = { code: "42P01", message: 'relation "finding_assignments" does not exist' };
    expect((await call(assign, "PUT", { items: ITEMS, assigneeId: null })).status).toBe(503);
    m.db.deleteError = { message: "boom" };
    expect((await call(assign, "PUT", { items: ITEMS, assigneeId: null })).status).toBe(500);
    m.db.upsertError = { message: "boom" };
    expect((await call(assign, "PUT", { items: ITEMS, assigneeId: DEV })).status).toBe(500);
    err.mockRestore();
  });

  it("doesn't email a member without an address", async () => {
    expect((await call(assign, "PUT", { items: ITEMS, assigneeId: DEV })).status).toBe(200);
    expect(m.email).not.toHaveBeenCalled();
  });
});
