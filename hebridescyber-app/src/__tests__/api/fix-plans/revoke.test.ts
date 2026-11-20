import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, auditMock, state } = vi.hoisted(() => ({
  authMock: vi.fn(),
  auditMock: vi.fn(),
  state: { updated: [] as unknown[], existing: null as unknown, eqs: [] as Array<[string, unknown]> },
}));

function builder() {
  const q: Record<string, unknown> = {};
  q.update = () => q;
  q.is = () => q;
  q.eq = (c: string, v: unknown) => {
    state.eqs.push([c, v]);
    return q;
  };
  q.select = () => q;
  q.maybeSingle = async () => ({ data: state.existing, error: null });
  q.then = (r: (v: unknown) => void) => r({ data: state.updated, error: null });
  return q;
}

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authMock, supabaseAdmin: { from: () => builder() } }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: auditMock }));

import handler from "@/pages/api/fix-plans/[id]";

const ID = "22222222-2222-4222-8222-222222222222";
const call = async (method: "DELETE" | "GET", id = ID) => {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, query: { id }, headers: { authorization: "Bearer t" } });
  await handler(req, res);
  return res;
};

describe("DELETE /api/fix-plans/[id]", () => {
  beforeEach(() => {
    authMock.mockReset().mockResolvedValue({ ownerId: "o1", via: "session" });
    auditMock.mockReset();
    state.updated = [];
    state.existing = null;
    state.eqs = [];
  });

  it("405 for other methods, 401 unauthenticated, 404 for a malformed id", async () => {
    expect((await call("GET"))._getStatusCode()).toBe(405);
    authMock.mockResolvedValueOnce(null);
    expect((await call("DELETE"))._getStatusCode()).toBe(401);
    expect((await call("DELETE", "nope"))._getStatusCode()).toBe(404);
  });

  it("revokes only the caller's own plan, and audits it", async () => {
    state.updated = [{ id: ID }];
    const res = await call("DELETE");
    expect(res._getStatusCode()).toBe(200);
    expect(state.eqs).toContainEqual(["owner", "o1"]);
    expect(auditMock.mock.calls[0][1]).toMatchObject({ action: "fix_plan.revoked", resourceId: ID });
  });

  it("404 for someone else's plan; an already-revoked one of yours is fine", async () => {
    expect((await call("DELETE"))._getStatusCode()).toBe(404);
    state.existing = { id: ID };
    expect((await call("DELETE"))._getStatusCode()).toBe(200);
    expect(auditMock).not.toHaveBeenCalled();
  });
});
