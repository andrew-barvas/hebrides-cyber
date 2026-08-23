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

import handler from "@/pages/api/admin/blog";

function mockReqRes(overrides: Partial<Parameters<typeof createMocks>[0]> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "GET", headers: { authorization: "Bearer t" }, ...overrides });
}

describe("/api/admin/blog", () => {
  beforeEach(() => {
    mock.reset();
    requireAdminMock.mockReset();
  });

  it("returns 403 when the caller is not an admin", async () => {
    requireAdminMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  describe("GET", () => {
    it("returns paginated posts", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      mock.setQueues({ blog_posts: [{ data: [{ id: "p1", slug: "hello", title: "Hello" }], error: null, count: 1 }] });
      const { req, res } = mockReqRes();

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(res._getJSONData()).toEqual({ posts: [{ id: "p1", slug: "hello", title: "Hello" }], total: 1, page: 1, pageSize: 20 });
    });

    it("returns 500 on a query error", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      mock.setQueues({ blog_posts: [{ data: null, error: { message: "db down" } }] });
      const { req, res } = mockReqRes();
      await handler(req, res);
      expect(res._getStatusCode()).toBe(500);
    });
  });

  describe("POST", () => {
    it("returns 400 when title or slug is missing", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      const { req, res } = mockReqRes({ method: "POST", body: { title: "Only a title" } });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(400);
    });

    it("creates a draft post authored by the admin by default", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      mock.setQueues({ blog_posts: [{ data: { id: "p2", slug: "new-post" }, error: null }] });
      const { req, res } = mockReqRes({ method: "POST", body: { title: "New Post", slug: "new-post" } });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(201);
      expect(mock.inserted[0].payload).toMatchObject({ title: "New Post", slug: "new-post", status: "draft", author_id: "admin-1", published_at: null });
    });

    it("sets published_at when created directly as published", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      mock.setQueues({ blog_posts: [{ data: { id: "p3", slug: "live" }, error: null }] });
      const { req, res } = mockReqRes({ method: "POST", body: { title: "Live", slug: "live", status: "published" } });

      await handler(req, res);

      const payload = mock.inserted[0].payload as { published_at: string | null };
      expect(payload.published_at).not.toBeNull();
    });

    it("returns 400 when the insert fails (e.g. duplicate slug)", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      mock.setQueues({ blog_posts: [{ data: null, error: { message: "duplicate key value" } }] });
      const { req, res } = mockReqRes({ method: "POST", body: { title: "Dup", slug: "dup" } });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(400);
    });
  });

  it("rejects other methods with 405", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    const { req, res } = mockReqRes({ method: "DELETE" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });
});
