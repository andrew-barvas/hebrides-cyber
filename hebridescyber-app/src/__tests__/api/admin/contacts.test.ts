import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { makeAdminSupabaseMock } from "./_supabaseQueueMock";

const { getUserMock } = vi.hoisted(() => ({ getUserMock: vi.fn() }));
const mock = makeAdminSupabaseMock();

// E-08 (docs/ENHANCEMENTS.md): contacts.ts now goes through the shared
// requireAdmin() (src/lib/adminAuth.ts), which calls supabaseAdmin's own
// auth.getUser directly — mock that module the same way overview.test.ts
// does, rather than @supabase/supabase-js's createClient factory.
vi.mock("@/lib/supabaseAdmin", () => ({
  supabaseAdmin: {
    auth: { getUser: getUserMock },
    from: (table: string) => mock.supabaseAdmin.from(table),
  },
}));

import handler from "@/pages/api/admin/contacts";

function mockReqRes(overrides: Partial<Parameters<typeof createMocks>[0]> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "GET", headers: { authorization: "Bearer t" }, ...overrides });
}

describe("/api/admin/contacts", () => {
  beforeEach(() => {
    mock.reset();
    getUserMock.mockReset();
  });

  it("returns 403 when the Authorization header is missing", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 403 when the token doesn't resolve to a user", async () => {
    getUserMock.mockResolvedValue({ data: { user: null } });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 403 when the caller resolves but is not an admin", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "u1" } } });
    mock.setQueues({ users: [{ data: { is_admin: false } }] });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 403 (not 500) when the auth check throws", async () => {
    getUserMock.mockRejectedValue(new Error("network error"));
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  describe("as an admin", () => {
    beforeEach(() => {
      getUserMock.mockResolvedValue({ data: { user: { id: "admin-1" } } });
    });

    it("GET returns the paginated enquiry list, including the lead-qualification fields when present", async () => {
      mock.setQueues({
        users: [{ data: { is_admin: true } }],
        contact_enquiries: [
          {
            data: [
              {
                id: "c1",
                name: "Jane",
                email: "jane@example.com",
                message: "hi",
                company: "Acme Ltd",
                team_size: "11_50",
                budget_range: "300_800",
                read: false,
              },
              { id: "c2", name: "Jo", email: "jo@example.com", message: "hey", company: null, team_size: null, budget_range: null, read: true },
            ],
            count: 2,
            error: null,
          },
        ],
      });
      const { req, res } = mockReqRes();

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(res._getJSONData()).toEqual({
        enquiries: [
          { id: "c1", name: "Jane", email: "jane@example.com", message: "hi", company: "Acme Ltd", team_size: "11_50", budget_range: "300_800", read: false },
          { id: "c2", name: "Jo", email: "jo@example.com", message: "hey", company: null, team_size: null, budget_range: null, read: true },
        ],
        total: 2,
        page: 1,
        pageSize: 25,
      });
    });

    it("GET honours the page query param", async () => {
      mock.setQueues({
        users: [{ data: { is_admin: true } }],
        contact_enquiries: [{ data: [], count: 30, error: null }],
      });
      const { req, res } = mockReqRes({ query: { page: "2" } });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      const body = res._getJSONData() as { page: number; total: number };
      expect(body.page).toBe(2);
      expect(body.total).toBe(30);
    });

    it("GET returns 500 on a query error", async () => {
      mock.setQueues({ users: [{ data: { is_admin: true } }], contact_enquiries: [{ data: null, error: { message: "db down" } }] });
      const { req, res } = mockReqRes();
      await handler(req, res);
      expect(res._getStatusCode()).toBe(500);
    });

    it("PATCH requires an id", async () => {
      mock.setQueues({ users: [{ data: { is_admin: true } }] });
      const { req, res } = mockReqRes({ method: "PATCH", body: { read: true } });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(400);
    });

    it("PATCH marks an enquiry read", async () => {
      mock.setQueues({ users: [{ data: { is_admin: true } }], contact_enquiries: [{ error: null }] });
      const { req, res } = mockReqRes({ method: "PATCH", body: { id: "c1", read: true } });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(res._getJSONData()).toEqual({ ok: true });
      expect(mock.updated).toEqual([{ table: "contact_enquiries", payload: { read: true } }]);
    });

    it("rejects other methods with 405", async () => {
      mock.setQueues({ users: [{ data: { is_admin: true } }] });
      const { req, res } = mockReqRes({ method: "DELETE" });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(405);
    });
  });
});
