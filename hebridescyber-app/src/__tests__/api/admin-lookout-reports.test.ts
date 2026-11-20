import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { requireAdminMock, draftMock, auditMock } = vi.hoisted(() => ({
  requireAdminMock: vi.fn(),
  draftMock: vi.fn(),
  auditMock: vi.fn(),
}));

const CUSTOMER = "11111111-1111-4111-8111-111111111111";
type Call = { table: string; filters: Array<[string, string, unknown]>; insert?: unknown };
let calls: Call[];
let users: Array<{ id: string; email: string }>;

function builder(table: string) {
  const call: Call = { table, filters: [] };
  calls.push(call);
  const result = () => {
    if (table === "users") {
      let rows = users;
      for (const [op, col, val] of call.filters) {
        if (op === "eq") rows = rows.filter((u) => (u as Record<string, unknown>)[col] === val);
        if (op === "ilike") rows = rows.filter((u) => u.email.toLowerCase() === String(val).replace(/\\(.)/g, "$1").toLowerCase());
        if (op === "in") rows = rows.filter((u) => (val as string[]).includes(u.id));
      }
      return { data: rows, error: null };
    }
    if (table === "lookout_reports" && call.insert) return { data: { id: "r1", customer: CUSTOMER, period_start: "a", period_end: "b", status: "draft", summary: "" }, error: null };
    if (table === "lookout_reports") return { data: [{ id: "r1", customer: CUSTOMER }], error: null };
    return { data: null, error: null };
  };
  const b: Record<string, unknown> = {
    select: () => b,
    order: () => b,
    limit: () => b,
    eq: (col: string, val: unknown) => (call.filters.push(["eq", col, val]), b),
    ilike: (col: string, val: unknown) => (call.filters.push(["ilike", col, val]), b),
    in: (col: string, val: unknown) => (call.filters.push(["in", col, val]), b),
    insert: (row: unknown) => ((call.insert = row), b),
    single: async () => result(),
    then: (r: (v: unknown) => void) => r(result()),
  };
  return b;
}

vi.mock("@/lib/adminAuth", () => ({ requireAdmin: requireAdminMock, supabaseAdmin: { from: (t: string) => builder(t) } }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: auditMock }));
vi.mock("@/lib/lookoutReports", () => ({ loadDraftInputs: draftMock }));

import handler from "@/pages/api/admin/lookout/reports/index";

async function call(method: RequestMethod, opts: { body?: unknown; query?: Record<string, string> } = {}) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, body: opts.body as Record<string, unknown>, query: opts.query });
  await handler(req, res);
  return { status: res._getStatusCode(), body: JSON.parse(res._getData() || "{}") as Record<string, unknown> };
}

describe("/api/admin/lookout/reports: customer by email or id", () => {
  beforeEach(() => {
    calls = [];
    users = [{ id: CUSTOMER, email: "Owner@Example.com" }, { id: "22222222-2222-4222-8222-222222222222", email: "axb@example.com" }];
    requireAdminMock.mockReset().mockResolvedValue("admin-1");
    draftMock.mockReset().mockResolvedValue({ items: [], summary: "s" });
    auditMock.mockReset();
  });

  it("creates a draft for the account with that email, case-insensitively", async () => {
    const { status } = await call("POST", { body: { customer: " owner@example.com ", period_days: 30 } });
    expect(status).toBe(201);
    expect(draftMock).toHaveBeenCalledWith(expect.anything(), CUSTOMER, 30);
    expect(calls.find((c) => c.table === "lookout_reports" && c.insert)?.insert).toMatchObject({ customer: CUSTOMER });
  });

  it("still accepts a user id", async () => {
    expect((await call("POST", { body: { customer: CUSTOMER } })).status).toBe(201);
    expect(draftMock).toHaveBeenCalledWith(expect.anything(), CUSTOMER, 30);
  });

  it("escapes wildcards so an email only matches itself", async () => {
    const { status, body } = await call("POST", { body: { customer: "a_b@example.com" } });
    expect(status).toBe(404);
    expect(body.error).toBe("No account uses a_b@example.com.");
    expect(draftMock).not.toHaveBeenCalled();
  });

  it("rejects input that is neither an email nor an id", async () => {
    expect((await call("POST", { body: { customer: "not an account" } })).status).toBe(400);
  });

  it("filters the list by email and shows each customer's email", async () => {
    const { body } = await call("GET", { query: { customer: "owner@example.com" } });
    expect(body.reports).toEqual([{ id: "r1", customer: CUSTOMER, customer_email: "Owner@Example.com" }]);
    const unknown = await call("GET", { query: { customer: "nobody@example.com" } });
    expect(unknown.body.reports).toEqual([]);
  });

  it("is admin only", async () => {
    requireAdminMock.mockResolvedValue(null);
    expect((await call("GET")).status).toBe(403);
  });
});
