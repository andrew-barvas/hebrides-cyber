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

    it("GET returns the enquiry list", async () => {
      mock.setQueues({
        users: [{ data: { is_admin: true } }],
        contact_enquiries: [{ data: [{ id: "c1", name: "Jane", email: "jane@example.com", message: "hi", read: false }], error: null }],
      });
      const { req, res } = mockReqRes();

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(res._getJSONData()).toEqual([{ id: "c1", name: "Jane", email: "jane@example.com", message: "hi", read: false }]);
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
