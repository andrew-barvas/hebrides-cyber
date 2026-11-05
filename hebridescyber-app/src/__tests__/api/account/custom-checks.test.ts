import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { auth, gate, db } = vi.hoisted(() => ({ auth: vi.fn(), gate: vi.fn(), db: { result: {} as Record<string, unknown>, inserted: null as unknown } }));

function builder(table: string) {
  const b: Record<string, unknown> = {
    select: () => b,
    order: () => b,
    eq: () => b,
    update: () => b,
    delete: () => b,
    insert: (row: unknown) => ((db.inserted = row), b),
    single: () => Promise.resolve(db.result.single ?? { data: { id: "11111111-1111-4111-8111-111111111111", ...(db.inserted as object) }, error: null }),
    maybeSingle: () => Promise.resolve(db.result.maybeSingle ?? { data: null, error: null }),
    then: (resolve: (v: unknown) => unknown) => Promise.resolve(db.result[table] ?? { data: [], error: null, count: 0 }).then(resolve),
  };
  return b;
}
vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: auth, supabaseAdmin: { from: builder } }));
vi.mock("@/lib/planAccess", () => ({ planGate: gate }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: vi.fn() }));

import handler from "@/pages/api/account/custom-checks";

const GOOD = `id: internal-admin
info:
  name: Admin reachable
  severity: high
http:
  - method: GET
    path: ["{{BaseURL}}/internal-admin"]
    matchers:
      - type: status
        status: [200]
`;

const call = async (method: string, body?: unknown) => {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "GET", body: body as never, headers: { authorization: "Bearer t" } });
  await handler(req, res);
  return res;
};

beforeEach(() => {
  auth.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
  gate.mockReset().mockResolvedValue("ok");
  db.result = {};
  db.inserted = null;
});

describe("/api/account/custom-checks", () => {
  it("is signed-in, session-only and Agency-only", async () => {
    auth.mockResolvedValueOnce(null);
    expect((await call("GET")).statusCode).toBe(401);
    auth.mockResolvedValueOnce({ ownerId: "o", via: "api_key" });
    expect((await call("POST", { yaml: GOOD })).statusCode).toBe(403);
    gate.mockResolvedValueOnce("denied");
    expect((await call("POST", { yaml: GOOD })).statusCode).toBe(403);
    gate.mockResolvedValueOnce("error");
    expect((await call("GET")).statusCode).toBe(500);
    expect(gate).toHaveBeenCalledWith(expect.anything(), "owner-1", "agency");
  });

  it("saves a valid check, owned by the caller, with the id, name and severity the validator read", async () => {
    const res = await call("POST", { yaml: GOOD });
    expect(res.statusCode).toBe(201);
    expect(db.inserted).toEqual({ owner: "owner-1", template_id: "internal-admin", name: "Admin reachable", severity: "high", yaml: GOOD });
  });

  it("refuses an invalid check with the reasons, and stores nothing", async () => {
    const res = await call("POST", { yaml: GOOD.replace('"{{BaseURL}}/internal-admin"', '"http://evil.example/"') });
    expect(res.statusCode).toBe(422);
    expect(JSON.parse(res._getData()).problems.join(" ")).toContain("BaseURL");
    expect(db.inserted).toBeNull();
  });

  it("enforces the per-account limit and reports a duplicate id", async () => {
    db.result.custom_nuclei_templates = { data: null, error: null, count: 20 };
    expect((await call("POST", { yaml: GOOD })).statusCode).toBe(409);
    expect(db.inserted).toBeNull();
    db.result = { single: { data: null, error: { code: "23505", message: "dup" } } };
    expect((await call("POST", { yaml: GOOD })).statusCode).toBe(409);
  });

  it("validates ids on PATCH and DELETE, and 404s a check that is not the caller's", async () => {
    expect((await call("DELETE", { id: "nope" })).statusCode).toBe(400);
    expect((await call("PATCH", { id: "nope", enabled: true })).statusCode).toBe(400);
    expect((await call("PATCH", { id: "11111111-1111-4111-8111-111111111111", enabled: false })).statusCode).toBe(404);
  });
});
