import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { makeAdminSupabaseMock } from "./_supabaseQueueMock";

const { requireAdminMock } = vi.hoisted(() => ({ requireAdminMock: vi.fn() }));
const mock = makeAdminSupabaseMock();

vi.mock("@/lib/adminAuth", () => ({
  requireAdmin: requireAdminMock,
  supabaseAdmin: { from: (table: string) => mock.supabaseAdmin.from(table) },
}));

import handler from "@/pages/api/admin/deletion-requests";

function mockReqRes(method: "GET" | "POST" = "GET") {
  return createMocks<NextApiRequest, NextApiResponse>({ method, headers: { authorization: "Bearer t" } });
}

describe("GET /api/admin/deletion-requests", () => {
  beforeEach(() => {
    mock.reset();
    requireAdminMock.mockReset();
  });

  it("rejects non-GET with 405", async () => {
    const { req, res } = mockReqRes("POST");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 403 when not an admin", async () => {
    requireAdminMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 500 when the deletion_requests query errors", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({ deletion_requests: [{ data: null, error: { message: "db down" } }] });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(500);
  });

  it("lists pending requests soonest-first with overdue flags and owner emails", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    const past = new Date(Date.now() - 2 * 86_400_000).toISOString();
    const future = new Date(Date.now() + 10 * 86_400_000).toISOString();
    mock.setQueues({
      deletion_requests: [
        {
          data: [
            { id: "f", owner: "u2", status: "pending", requested_at: past, due_at: future, reminded_at: null },
            { id: "o", owner: "u1", status: "pending", requested_at: past, due_at: past, reminded_at: null },
          ],
          error: null,
        },
      ],
      users: [{ data: [{ id: "u1", email: "a@example.com" }, { id: "u2", email: "b@example.com" }], error: null }],
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const body = res._getJSONData() as {
      overdueCount: number;
      requests: { id: string; overdue: boolean; email: string | null }[];
    };
    expect(body.overdueCount).toBe(1);
    expect(body.requests.map((r) => r.id)).toEqual(["o", "f"]); // overdue (soonest due) first
    expect(body.requests[0]).toMatchObject({ overdue: true, email: "a@example.com" });
    expect(body.requests[1]).toMatchObject({ overdue: false, email: "b@example.com" });
  });

  it("returns an empty queue without looking up emails when nothing is pending", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({ deletion_requests: [{ data: [], error: null }] });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getJSONData()).toEqual({ overdueCount: 0, requests: [] });
  });
});
