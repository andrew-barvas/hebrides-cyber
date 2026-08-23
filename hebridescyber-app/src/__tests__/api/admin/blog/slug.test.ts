import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { makeAdminSupabaseMock } from "../_supabaseQueueMock";

const { requireAdminMock } = vi.hoisted(() => ({ requireAdminMock: vi.fn() }));
const mock = makeAdminSupabaseMock();

vi.mock("@/lib/adminAuth", () => ({
  requireAdmin: requireAdminMock,
  supabaseAdmin: { from: (table: string) => mock.supabaseAdmin.from(table) },
}));

import handler from "@/pages/api/admin/blog/[slug]";

function mockReqRes(overrides: Partial<Parameters<typeof createMocks>[0]> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({
    method: "GET",
    headers: { authorization: "Bearer t" },
    query: { slug: "hello-world" },
    ...overrides,
  });
}

describe("/api/admin/blog/[slug]", () => {
  beforeEach(() => {
    mock.reset();
    requireAdminMock.mockReset().mockResolvedValue("admin-1");
  });

  it("returns 403 when the caller is not an admin", async () => {
    requireAdminMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 400 when slug is missing from the query", async () => {
    const { req, res } = mockReqRes({ query: {} });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  describe("GET", () => {
    it("returns 404 when no post matches the slug", async () => {
      mock.setQueues({ blog_posts: [{ data: null, error: null }] });
      const { req, res } = mockReqRes();
      await handler(req, res);
      expect(res._getStatusCode()).toBe(404);
    });

    it("returns the full post on a match", async () => {
      mock.setQueues({ blog_posts: [{ data: { id: "p1", slug: "hello-world", body: "full body" }, error: null }] });
      const { req, res } = mockReqRes();
      await handler(req, res);
      expect(res._getStatusCode()).toBe(200);
      expect(res._getJSONData()).toEqual({ id: "p1", slug: "hello-world", body: "full body" });
    });
  });

  describe("PATCH", () => {
    it("only forwards allowed fields from the request body", async () => {
      mock.setQueues({ blog_posts: [{ data: { id: "p1", slug: "hello-world", status: "draft", updated_at: "now" }, error: null }] });
      const { req, res } = mockReqRes({
        method: "PATCH",
        body: { title: "New title", not_a_real_field: "should be dropped", excerpt: "e" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      const payload = mock.updated[0].payload as Record<string, unknown>;
      expect(payload.title).toBe("New title");
      expect(payload.excerpt).toBe("e");
      expect(payload).not.toHaveProperty("not_a_real_field");
    });

    it("sets published_at when transitioning to published from a non-published status", async () => {
      mock.setQueues({
        blog_posts: [
          { data: { published_at: null, status: "draft" }, error: null }, // the pre-check lookup
          { data: { id: "p1", slug: "hello-world", status: "published", updated_at: "now" }, error: null },
        ],
      });
      const { req, res } = mockReqRes({ method: "PATCH", body: { status: "published" } });

      await handler(req, res);

      const payload = mock.updated[0].payload as { published_at: string | null; status: string };
      expect(payload.status).toBe("published");
      expect(payload.published_at).not.toBeNull();
    });

    it("does not overwrite published_at when already published", async () => {
      mock.setQueues({
        blog_posts: [
          { data: { published_at: "2026-01-01T00:00:00Z", status: "published" }, error: null },
          { data: { id: "p1", slug: "hello-world", status: "published", updated_at: "now" }, error: null },
        ],
      });
      const { req, res } = mockReqRes({ method: "PATCH", body: { status: "published" } });

      await handler(req, res);

      const payload = mock.updated[0].payload as { published_at?: string };
      expect(payload.published_at).toBeUndefined();
    });

    it("clears published_at when moved back to draft", async () => {
      mock.setQueues({ blog_posts: [{ data: { id: "p1", slug: "hello-world", status: "draft", updated_at: "now" }, error: null }] });
      const { req, res } = mockReqRes({ method: "PATCH", body: { status: "draft" } });

      await handler(req, res);

      const payload = mock.updated[0].payload as { published_at: string | null };
      expect(payload.published_at).toBeNull();
    });

    it("returns 400 when the update fails", async () => {
      mock.setQueues({ blog_posts: [{ data: null, error: { message: "constraint violation" } }] });
      const { req, res } = mockReqRes({ method: "PATCH", body: { title: "x" } });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(400);
    });
  });

  describe("DELETE", () => {
    it("deletes the post by slug", async () => {
      mock.setQueues({ blog_posts: [{ error: null }] });
      const { req, res } = mockReqRes({ method: "DELETE" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(res._getJSONData()).toEqual({ ok: true });
      expect(mock.deleted).toEqual([{ table: "blog_posts" }]);
    });

    it("returns 400 when the delete fails", async () => {
      mock.setQueues({ blog_posts: [{ error: { message: "fk violation" } }] });
      const { req, res } = mockReqRes({ method: "DELETE" });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(400);
    });
  });

  it("rejects other methods with 405", async () => {
    const { req, res } = mockReqRes({ method: "PUT" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });
});
