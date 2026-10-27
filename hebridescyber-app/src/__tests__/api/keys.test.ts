import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, logAuditEventMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  logAuditEventMock: vi.fn(),
}));

type Result = { data: unknown; error: { code?: string; message: string } | null };
let listResult: Result = { data: [], error: null };
let updateResult: Result = { data: null, error: null };
let lastUpdate: { values: Record<string, unknown>; filters: string[] } | null = null;
// Each insert consumes the next result; the last one repeats.
let existingResult: Result = { data: [], error: null };
let insertResults: Result[] = [];
let inserts: Record<string, unknown>[] = [];

function makeBuilder() {
  const filters: string[] = [];
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: (col: string, val: unknown) => (filters.push(`eq:${col}=${val}`), builder),
    is: (col: string, val: unknown) => (filters.push(`is:${col}=${val}`), builder),
    order: () => Promise.resolve(listResult),
    update: (values: Record<string, unknown>) => {
      lastUpdate = { values, filters };
      return builder;
    },
    maybeSingle: () => Promise.resolve(updateResult),
    insert: (values: Record<string, unknown>) => {
      inserts.push(values);
      return builder;
    },
    single: () => Promise.resolve(insertResults[Math.min(inserts.length, insertResults.length) - 1]),
    // Awaited directly: the active-key count (POST) and the revoking update (DELETE).
    then: (resolve: (r: Result) => unknown) => resolve(lastUpdate?.filters === filters ? updateResult : existingResult),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: () => makeBuilder() },
}));
vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));

import handler from "@/pages/api/keys";

function call(method: RequestMethod, body?: Record<string, unknown>) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, body });
  return handler(req, res).then(() => res);
}

describe("/api/keys", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
    logAuditEventMock.mockReset();
    listResult = { data: [], error: null };
    updateResult = { data: { id: "key-1" }, error: null };
    lastUpdate = null;
    insertResults = [];
    inserts = [];
    existingResult = { data: [], error: null };
  });

  it("401s without credentials", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    expect((await call("GET"))._getStatusCode()).toBe(401);
  });

  it("405s on an unsupported method", async () => {
    expect((await call("PUT"))._getStatusCode()).toBe(405);
  });

  describe("DELETE", () => {
    it("revokes the caller's own key (soft, keeping the audit trail) and audits it", async () => {
      updateResult = { data: null, error: null };
      const res = await call("DELETE", { id: "key-1" });
      expect(res._getStatusCode()).toBe(200);
      expect(lastUpdate?.values).toHaveProperty("revoked_at");
      expect(lastUpdate?.filters).toEqual(["eq:id=key-1", "eq:owner=owner-1"]);
      expect(logAuditEventMock).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ action: "api_key.revoked", resourceId: "key-1" })
      );
    });

    it("500s, without auditing, when the update fails", async () => {
      updateResult = { data: null, error: { message: "db down" } };
      expect((await call("DELETE", { id: "key-1" }))._getStatusCode()).toBe(500);
      expect(logAuditEventMock).not.toHaveBeenCalled();
    });

    it("400s without an id", async () => {
      expect((await call("DELETE", {}))._getStatusCode()).toBe(400);
    });
  });

  // A key that could edit its own allowlist could simply remove it.
  it("refuses to be driven by an API key", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "key" });
    const res = await call("PATCH", { id: "key-1", allowed_cidrs: [] });
    expect(res._getStatusCode()).toBe(403);
    expect(lastUpdate).toBeNull();
  });

  describe("GET", () => {
    it("never returns key_hash, and defaults the allowlist fields on an unmigrated row", async () => {
      listResult = {
        data: [
          { id: "k1", name: "CI", key_prefix: "hc_live_abcdefgh", key_hash: "secret-hash", last_used_at: null, revoked_at: null, created_at: "2026-09-01" },
        ],
        error: null,
      };
      const res = await call("GET");
      expect(res._getStatusCode()).toBe(200);
      const [key] = (res._getJSONData() as { keys: Record<string, unknown>[] }).keys;
      expect(key).not.toHaveProperty("key_hash");
      expect(key).toMatchObject({ id: "k1", allowed_cidrs: [], last_blocked_ip: null, last_blocked_at: null });
    });

    it("500s when the list query fails", async () => {
      listResult = { data: null, error: { message: "db down" } };
      expect((await call("GET"))._getStatusCode()).toBe(500);
    });

    it("passes a migrated row's allowlist and last refusal through", async () => {
      listResult = {
        data: [
          {
            id: "k1", name: "CI", key_prefix: "hc_live_abcdefgh", key_hash: "h", last_used_at: null, revoked_at: null, created_at: "2026-09-01",
            allowed_cidrs: ["203.0.113.0/24"], last_blocked_ip: "198.51.100.9", last_blocked_at: "2026-09-20T10:00:00Z",
          },
        ],
        error: null,
      };
      const [key] = ((await call("GET"))._getJSONData() as { keys: Record<string, unknown>[] }).keys;
      expect(key).toMatchObject({ allowed_cidrs: ["203.0.113.0/24"], last_blocked_ip: "198.51.100.9" });
    });
  });

  describe("POST", () => {
    const created = { id: "k1", name: "CI", key_prefix: "hc_live_abcdefgh", created_at: "2026-10-26" };

    it("stores the preset's scopes", async () => {
      insertResults = [{ data: { ...created, scopes: ["scans:read"] }, error: null }];
      const res = await call("POST", { name: "CI", preset: "read_only" });
      expect(res._getStatusCode()).toBe(201);
      expect(inserts).toHaveLength(1);
      expect(inserts[0].scopes).toEqual(["scans:read"]);
      expect((res._getJSONData() as { key: string }).key).toBeTruthy();
    });

    it("before migration 062, still mints a full-access key without the scopes column", async () => {
      insertResults = [
        { data: null, error: { code: "PGRST204", message: "column not found" } },
        { data: created, error: null },
      ];
      const res = await call("POST", { name: "CI" });
      expect(res._getStatusCode()).toBe(201);
      expect(inserts).toHaveLength(2);
      expect(inserts[1]).not.toHaveProperty("scopes");
    });

    it("before migration 062, refuses a narrowed preset rather than minting a full-access key", async () => {
      insertResults = [{ data: null, error: { code: "PGRST204", message: "column not found" } }];
      const res = await call("POST", { name: "CI", preset: "read_only" });
      expect(res._getStatusCode()).toBe(503);
      expect((res._getJSONData() as { error: string }).error).toContain("062");
      expect(inserts).toHaveLength(1);
    });

    it("refuses a 21st active key without inserting", async () => {
      existingResult = { data: Array.from({ length: 20 }, (_, i) => ({ id: `k${i}` })), error: null };
      const res = await call("POST", { name: "CI" });
      expect(res._getStatusCode()).toBe(400);
      expect(inserts).toHaveLength(0);
    });

    it("400s on a blank name", async () => {
      expect((await call("POST", { name: "   " }))._getStatusCode()).toBe(400);
      expect(inserts).toHaveLength(0);
    });

    it("500s on any other insert error", async () => {
      insertResults = [{ data: null, error: { code: "XX000", message: "boom" } }];
      expect((await call("POST", { name: "CI" }))._getStatusCode()).toBe(500);
    });
  });

  describe("PATCH (IP allowlist)", () => {
    it("stores the tidied list on the caller's own live key and audits it", async () => {
      const res = await call("PATCH", { id: "key-1", allowed_cidrs: [" 203.0.113.7/32", "2001:DB8::/48", ""] });
      expect(res._getStatusCode()).toBe(200);
      expect(lastUpdate?.values).toEqual({ allowed_cidrs: ["203.0.113.7", "2001:db8::/48"] });
      expect(lastUpdate?.filters).toEqual(["eq:id=key-1", "eq:owner=owner-1", "is:revoked_at=null"]);
      expect(logAuditEventMock).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ action: "api_key.allowlist_updated", resourceId: "key-1" })
      );
    });

    it("accepts an empty list (back to any address)", async () => {
      const res = await call("PATCH", { id: "key-1", allowed_cidrs: [] });
      expect(res._getStatusCode()).toBe(200);
      expect(lastUpdate?.values).toEqual({ allowed_cidrs: [] });
    });

    it("rejects an invalid entry without writing", async () => {
      const res = await call("PATCH", { id: "key-1", allowed_cidrs: ["office wifi"] });
      expect(res._getStatusCode()).toBe(400);
      expect((res._getJSONData() as { error: string }).error).toContain("office");
      expect(lastUpdate).toBeNull();
    });

    it("rejects a list that allows everything", async () => {
      expect((await call("PATCH", { id: "key-1", allowed_cidrs: ["0.0.0.0/0"] }))._getStatusCode()).toBe(400);
    });

    it("404s for someone else's or a revoked key", async () => {
      updateResult = { data: null, error: null };
      expect((await call("PATCH", { id: "key-9", allowed_cidrs: [] }))._getStatusCode()).toBe(404);
      expect(logAuditEventMock).not.toHaveBeenCalled();
    });

    it("500s on any other update error", async () => {
      updateResult = { data: null, error: { code: "XX000", message: "boom" } };
      expect((await call("PATCH", { id: "key-1", allowed_cidrs: [] }))._getStatusCode()).toBe(500);
    });

    it("says so when migration 042 hasn't been applied", async () => {
      updateResult = { data: null, error: { code: "PGRST204", message: "column not found" } };
      const res = await call("PATCH", { id: "key-1", allowed_cidrs: ["203.0.113.7"] });
      expect(res._getStatusCode()).toBe(503);
      expect((res._getJSONData() as { error: string }).error).toContain("042");
    });
  });
});
