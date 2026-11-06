// The /api/engagements* routes, with the auth and record layers stubbed. The record
// layer is covered by src/lib/engagements.test.ts, and abort_engagement() by
// tests/db/abortEngagement.db.test.ts.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const m = vi.hoisted(() => ({
  requireAdmin: vi.fn(),
  auth: vi.fn(),
  audit: vi.fn(),
  account: vi.fn(),
  load: vi.fn(),
  hostFacts: vi.fn(),
  update: vi.fn(),
  scope: vi.fn(),
  abort: vi.fn(),
  insert: vi.fn(),
}));

vi.mock("@/lib/adminAuth", () => ({
  requireAdmin: m.requireAdmin,
  supabaseAdmin: {
    from: () => ({ insert: (row: unknown) => ({ select: () => ({ single: () => m.insert(row) }) }) }),
  },
}));
vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: m.auth, supabaseAdmin: { tag: "admin" } }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: m.audit }));
vi.mock("@/lib/engagements", async (original) => ({
  ...(await original<typeof import("@/lib/engagements")>()),
  accountExists: m.account,
  loadEngagement: m.load,
  loadIncludedHostFacts: m.hostFacts,
  updateEngagement: m.update,
  applyScopeChanges: m.scope,
  abortEngagement: m.abort,
}));

import createHandler from "@/pages/api/engagements/index";
import patchHandler from "@/pages/api/engagements/[id]/index";
import scopeHandler from "@/pages/api/engagements/[id]/scope";
import abortHandler from "@/pages/api/engagements/[id]/abort";

const ID = "e1000000-0000-4000-8000-000000000001";
const OWNER = "a1000000-0000-4000-8000-000000000001";
const ADMIN = "a2000000-0000-4000-8000-000000000002";
const START = "2026-11-01T00:00:00.000Z";
const END = "2026-11-30T00:00:00.000Z";

const engagement = (over = {}) => ({ id: ID, owner: OWNER, state: "scoped", window_start: START, window_end: END, contract_signed_at: START, ...over });

async function call(handler: typeof createHandler, method: string, body?: unknown, id = ID) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "POST", query: { id }, body: body as Record<string, unknown>, headers: { authorization: "Bearer t" } });
  await handler(req, res);
  return { status: res._getStatusCode(), body: res._getJSONData() as Record<string, unknown>, allow: res.getHeader("Allow") };
}

const auditActions = () => m.audit.mock.calls.map((c) => (c[1] as { action: string }).action);

beforeEach(() => {
  for (const fn of Object.values(m)) fn.mockReset();
  m.requireAdmin.mockResolvedValue(ADMIN);
  m.auth.mockResolvedValue({ ownerId: OWNER, via: "session" });
  m.account.mockResolvedValue({ status: "ok", data: true });
  m.load.mockResolvedValue({ status: "ok", data: engagement() });
  m.update.mockImplementation(async (_a, _id, _from, changes) => ({ status: "ok", data: engagement(changes) }));
  m.hostFacts.mockResolvedValue({ status: "ok", data: [{ host: "a.test", domainVerified: true, authorizationLinkedAndCurrent: true }] });
  m.scope.mockResolvedValue({ status: "ok", data: { added: [], removed: [], refused: [] } });
  m.insert.mockResolvedValue({ data: { id: ID }, error: null });
  m.abort.mockResolvedValue({ status: "ok", data: { outcome: "aborted", from: "in_window", revokedHosts: ["a.test", "b.test"], simulationsWithdrawn: 1 } });
});

describe.each([
  ["POST /api/engagements", createHandler, "POST", { owner: OWNER, reference: "ENG-1" }],
  ["PATCH /api/engagements/{id}", patchHandler, "PATCH", { to: "authorised" }],
  ["POST /api/engagements/{id}/scope", scopeHandler, "POST", { add: [{ host: "a.test", included: true }] }],
] as const)("%s", (_name, handler, method, body) => {
  it("is 403 for anyone but an admin session, which covers API keys, and changes nothing", async () => {
    m.requireAdmin.mockResolvedValue(null);
    expect((await call(handler, method, body)).status).toBe(403);
    for (const write of [m.insert, m.update, m.scope]) expect(write).not.toHaveBeenCalled();
  });

  it("rejects other methods, with Allow", async () => {
    const { status, allow } = await call(handler, "GET");
    expect(status).toBe(405);
    expect(allow).toBe(method);
  });
});

describe("POST /api/engagements", () => {
  const body = { owner: OWNER, reference: "ENG-1" };

  it("creates a booked engagement, defaulting to the non-intrusive profile, and audits it", async () => {
    expect((await call(createHandler, "POST", body)).status).toBe(201);
    expect(m.insert).toHaveBeenCalledWith(expect.objectContaining({ owner: OWNER, reference: "ENG-1", scan_profile: "exposure", created_by: ADMIN }));
    expect(m.insert.mock.calls[0][0]).not.toHaveProperty("state");
    expect(auditActions()).toEqual(["engagement.created"]);
  });

  it("refuses an account that doesn't exist, and a window that ends before it starts", async () => {
    m.account.mockResolvedValue({ status: "ok", data: false });
    expect((await call(createHandler, "POST", body)).status).toBe(400);
    m.account.mockResolvedValue({ status: "ok", data: true });
    expect((await call(createHandler, "POST", { ...body, windowStart: END, windowEnd: START })).status).toBe(400);
    expect(m.insert).not.toHaveBeenCalled();
  });

  it("is 409 for a repeated reference and hides database text otherwise", async () => {
    m.insert.mockResolvedValue({ data: null, error: { code: "23505", message: "dup" } });
    expect((await call(createHandler, "POST", body)).status).toBe(409);
    m.insert.mockResolvedValue({ data: null, error: { code: "XX000", message: "secret table detail" } });
    const failed = await call(createHandler, "POST", body);
    expect(failed.status).toBe(500);
    expect(JSON.stringify(failed.body)).not.toContain("secret");
    expect(auditActions()).toEqual([]);
  });

  it("is 503 before the migration", async () => {
    m.insert.mockResolvedValue({ data: null, error: { code: "42P01", message: "missing" } });
    expect((await call(createHandler, "POST", body)).status).toBe(503);
  });
});

describe("PATCH /api/engagements/{id}", () => {
  it("moves one state on when the facts hold, and audits from and to", async () => {
    const { status } = await call(patchHandler, "PATCH", { to: "authorised" });
    expect(status).toBe(200);
    expect(m.update).toHaveBeenCalledWith(expect.anything(), ID, "scoped", { state: "authorised" });
    expect(m.audit.mock.calls[0][1]).toMatchObject({ action: "engagement.state_changed", metadata: { from: "scoped", to: "authorised" } });
  });

  it("refuses a jump, naming the reason, and writes nothing", async () => {
    const { status, body } = await call(patchHandler, "PATCH", { to: "closed" });
    expect(status).toBe(409);
    expect(body.reason).toBe("transition_not_allowed");
    expect(m.update).not.toHaveBeenCalled();
    expect(auditActions()).toEqual([]);
  });

  it("refuses `authorised` on a missing fact, naming the host", async () => {
    m.hostFacts.mockResolvedValue({ status: "ok", data: [{ host: "a.test", domainVerified: true, authorizationLinkedAndCurrent: false }] });
    const { status, body } = await call(patchHandler, "PATCH", { to: "authorised" });
    expect(status).toBe(409);
    expect(body).toMatchObject({ reason: "authorization_missing", host: "a.test" });
    expect(m.update).not.toHaveBeenCalled();
  });

  it("fails closed when the host facts can't be read", async () => {
    m.hostFacts.mockResolvedValue({ status: "error", error: { message: "down" } });
    expect((await call(patchHandler, "PATCH", { to: "authorised" })).status).toBe(500);
    expect(m.update).not.toHaveBeenCalled();
  });

  it("won't take `aborted`: stopping goes through /abort", async () => {
    expect((await call(patchHandler, "PATCH", { to: "aborted" })).status).toBe(400);
    expect(m.update).not.toHaveBeenCalled();
  });

  it("checks a contract sent in the same request as the move", async () => {
    m.load.mockResolvedValue({ status: "ok", data: engagement({ contract_signed_at: null }) });
    expect((await call(patchHandler, "PATCH", { to: "authorised" })).body.reason).toBe("contract_not_signed");
    const contract = { signedAt: START, signedByName: "A Person", signedByRole: "CTO" };
    expect((await call(patchHandler, "PATCH", { to: "authorised", contract })).status).toBe(200);
    expect(auditActions()).toEqual(["engagement.updated", "engagement.state_changed"]);
  });

  it("freezes the window and contract once authorised", async () => {
    m.load.mockResolvedValue({ status: "ok", data: engagement({ state: "authorised" }) });
    expect((await call(patchHandler, "PATCH", { windowEnd: END })).status).toBe(409);
    expect(m.update).not.toHaveBeenCalled();
  });

  it("checks a new window against the stored end", async () => {
    expect((await call(patchHandler, "PATCH", { windowStart: "2027-01-01T00:00:00.000Z" })).status).toBe(400);
  });

  it("is 409 when someone else moved it first, without auditing a move that didn't happen", async () => {
    m.update.mockResolvedValue({ status: "ok", data: null });
    expect((await call(patchHandler, "PATCH", { to: "authorised" })).status).toBe(409);
    expect(auditActions()).toEqual([]);
  });

  it("sets closed_at on closing", async () => {
    m.load.mockResolvedValue({ status: "ok", data: engagement({ state: "reported" }) });
    await call(patchHandler, "PATCH", { to: "closed" });
    expect(m.update.mock.calls[0][3]).toEqual({ state: "closed", closed_at: expect.any(String) });
  });

  it("is 404 for a malformed id or a missing engagement, and 400 for an empty body", async () => {
    expect((await call(patchHandler, "PATCH", { to: "authorised" }, "nope")).status).toBe(404);
    m.load.mockResolvedValue({ status: "not_found" });
    expect((await call(patchHandler, "PATCH", { to: "authorised" })).status).toBe(404);
    expect((await call(patchHandler, "PATCH", {})).status).toBe(400);
  });
});

describe("POST /api/engagements/{id}/scope", () => {
  it("passes the edit on and returns the per-host outcome", async () => {
    m.scope.mockResolvedValue({ status: "ok", data: { added: [], removed: [], refused: [{ host: "a.test", reason: "domain_not_verified" }] } });
    const { status, body } = await call(scopeHandler, "POST", { add: [{ host: "a.test", included: true }] });
    expect(status).toBe(200);
    expect(body.refused).toEqual([{ host: "a.test", reason: "domain_not_verified" }]);
    expect(m.scope.mock.calls[0][2]).toBe(ADMIN);
  });

  it.each(["authorised", "in_window", "reported", "closed", "aborted"])("is 409 in state %s", async (state) => {
    m.load.mockResolvedValue({ status: "ok", data: engagement({ state }) });
    expect((await call(scopeHandler, "POST", { remove: ["a.test"] })).status).toBe(409);
    expect(m.scope).not.toHaveBeenCalled();
  });

  it("is 400 for an empty edit or an oversized list", async () => {
    expect((await call(scopeHandler, "POST", {})).status).toBe(400);
    expect((await call(scopeHandler, "POST", { remove: Array(201).fill("a.test") })).status).toBe(400);
  });
});

describe("POST /api/engagements/{id}/abort", () => {
  beforeEach(() => {
    m.load.mockResolvedValue({ status: "ok", data: engagement({ state: "in_window" }) });
    m.requireAdmin.mockResolvedValue(null);
  });

  it("lets the owner stop it, reporting what was revoked, and audits every revocation", async () => {
    const { status, body } = await call(abortHandler, "POST", { reason: "client asked" });
    expect(status).toBe(200);
    expect(body).toEqual({ state: "aborted", authorisationsRevoked: 2, simulationsWithdrawn: 1 });
    expect(m.abort).toHaveBeenCalledWith({ tag: "admin" }, ID, "client asked");
    expect(auditActions()).toEqual(["offensive_scan.revoked", "offensive_scan.revoked", "engagement.aborted"]);
    expect(m.audit.mock.calls[2][1]).toMatchObject({ actorId: OWNER, metadata: { authorisations_revoked: 2, reason: "client asked" } });
  });

  it("works with no body, and an admin can stop someone else's", async () => {
    m.auth.mockResolvedValue({ ownerId: ADMIN, via: "session" });
    m.requireAdmin.mockResolvedValue(ADMIN);
    expect((await call(abortHandler, "POST")).status).toBe(200);
    expect(m.audit.mock.calls[2][1]).toMatchObject({ actorId: ADMIN });
  });

  it("is 404, not 403, for someone else's engagement", async () => {
    m.auth.mockResolvedValue({ ownerId: "someone-else", via: "session" });
    expect((await call(abortHandler, "POST")).status).toBe(404);
    expect(m.abort).not.toHaveBeenCalled();
  });

  it("refuses an API key and no caller", async () => {
    m.auth.mockResolvedValue({ ownerId: OWNER, via: "key" });
    expect((await call(abortHandler, "POST")).status).toBe(403);
    m.auth.mockResolvedValue(null);
    expect((await call(abortHandler, "POST")).status).toBe(401);
    expect(m.abort).not.toHaveBeenCalled();
  });

  it("is 409 once closed", async () => {
    m.abort.mockResolvedValue({ status: "ok", data: { outcome: "closed" } });
    expect((await call(abortHandler, "POST")).status).toBe(409);
    expect(auditActions()).toEqual([]);
  });

  it("is safe to repeat: audits late revocations but not a second abort", async () => {
    m.abort.mockResolvedValue({ status: "ok", data: { outcome: "already_aborted", from: "aborted", revokedHosts: ["late.test"], simulationsWithdrawn: 0 } });
    expect((await call(abortHandler, "POST")).status).toBe(200);
    expect(auditActions()).toEqual(["offensive_scan.revoked"]);
  });

  it("reports a failed stop as a failure, so the caller knows to retry", async () => {
    m.abort.mockResolvedValue({ status: "error", error: { message: "secret detail" } });
    const failed = await call(abortHandler, "POST");
    expect(failed.status).toBe(500);
    expect(JSON.stringify(failed.body)).not.toContain("secret");
    expect(auditActions()).toEqual([]);
  });

  it("has no plan gate: a lapsed account can still stop", async () => {
    // planAccess isn't even loaded by this route; the stop must not depend on it.
    const source = (await import("node:fs")).readFileSync("src/pages/api/engagements/[id]/abort.ts", "utf8");
    expect(source).not.toMatch(/planGate|checkRateLimit/);
  });
});
