import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { makeAdminSupabaseMock } from "./_supabaseQueueMock";

const { requireAdminMock } = vi.hoisted(() => ({ requireAdminMock: vi.fn() }));
// A plain top-level const (not vi.hoisted) — makeAdminSupabaseMock comes
// from a REAL, unmocked module, so it resolves during normal import
// evaluation, before this line runs. What matters is that the vi.mock
// factory below reads `mock.supabaseAdmin` LAZILY (inside the `from`
// closure, only invoked once a route handler actually calls
// supabaseAdmin.from(...) during a test) rather than eagerly returning it
// as a property value — an eager reference there resolves to `mock`
// before this const has been assigned, since Vitest evaluates a mocked
// module's factory as part of resolving the `import handler from
// "@/pages/api/admin/audit"` line below, which runs earlier than this.
const mock = makeAdminSupabaseMock();

vi.mock("@/lib/adminAuth", () => ({
  requireAdmin: requireAdminMock,
  supabaseAdmin: { from: (table: string) => mock.supabaseAdmin.from(table) },
}));

import handler from "@/pages/api/admin/audit";

function mockReqRes(query: Record<string, string> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query, headers: { authorization: "Bearer t" } });
}

describe("GET /api/admin/audit", () => {
  beforeEach(() => {
    mock.reset();
    requireAdminMock.mockReset();
  });

  it("rejects non-GET methods with 405", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "POST" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 403 when the caller is not an admin", async () => {
    requireAdminMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns paginated logs on the happy path", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      audit_logs: [{ data: [{ id: "1", action: "scan.started" }], error: null, count: 1 }],
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toEqual({ logs: [{ id: "1", action: "scan.started" }], total: 1, page: 1, pageSize: 50 });
  });

  it("accepts the structured category and date-range filters without erroring", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      audit_logs: [{ data: [{ id: "1", action: "stripe.checkout.completed" }], error: null, count: 1 }],
    });
    const { req, res } = mockReqRes({ category: "stripe", from: "2026-06-01", to: "2026-06-30" });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toMatchObject({ total: 1, page: 1 });
  });

  it("returns 500 when the query errors", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({ audit_logs: [{ data: null, error: { message: "db down" }, count: null }] });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getStatusCode()).toBe(500);
  });

  it("clamps a page value below 1 up to 1", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({ audit_logs: [{ data: [], error: null, count: 0 }] });
    const { req, res } = mockReqRes({ page: "-5" });

    await handler(req, res);

    expect((res._getJSONData() as { page: number }).page).toBe(1);
  });

  it("defaults to an empty array when data is null", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({ audit_logs: [{ data: null, error: null, count: null }] });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getJSONData()).toMatchObject({ logs: [], total: 0 });
  });
});
