import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, logAuditEventMock, hasAgencyAccessMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  logAuditEventMock: vi.fn(),
  hasAgencyAccessMock: vi.fn(),
}));

type Result = { data: unknown; error: { code?: string; message: string } | null; count?: number | null };
type Op = { table: string; kind: string; values?: Record<string, unknown>; filters: string[] };

// Results are keyed by "<table>:<kind>" where kind is the terminal operation.
let results: Record<string, Result> = {};
let ops: Op[] = [];

function makeBuilder(table: string) {
  const op: Op = { table, kind: "select", filters: [] };
  const settle = (): Result => {
    ops.push(op);
    return results[`${table}:${op.kind}`] ?? { data: null, error: null };
  };
  const builder: Record<string, unknown> = {
    select: () => builder,
    insert: (values: Record<string, unknown>) => ((op.kind = "insert"), (op.values = values), builder),
    update: (values: Record<string, unknown>) => ((op.kind = "update"), (op.values = values), builder),
    delete: () => ((op.kind = "delete"), builder),
    eq: (col: string, val: unknown) => (op.filters.push(`eq:${col}=${val}`), builder),
    in: (col: string, val: unknown[]) => (op.filters.push(`in:${col}=${val.join(",")}`), builder),
    order: () => builder,
    maybeSingle: () => Promise.resolve(settle()),
    single: () => Promise.resolve(settle()),
    then: (resolve: (r: Result) => unknown) => resolve(settle()),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));
vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));
vi.mock("@/lib/planAccess", () => ({ hasAgencyAccess: hasAgencyAccessMock }));

import clientsHandler from "@/pages/api/clients";
import assignHandler from "@/pages/api/clients/assign";

function call(handler: typeof clientsHandler, method: RequestMethod, body?: Record<string, unknown>) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, body });
  return handler(req, res).then(() => res);
}
const clients = (method: RequestMethod, body?: Record<string, unknown>) => call(clientsHandler, method, body);
const assign = (body?: Record<string, unknown>) => call(assignHandler, "POST", body);
const lastOp = (table: string, kind: string) => [...ops].reverse().find((o) => o.table === table && o.kind === kind);

const ROW = { id: "c1", name: "Acme", notes: null, brand_name: null, brand_logo_url: null, created_at: "2026-10-01" };

describe("/api/clients", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
    hasAgencyAccessMock.mockReset().mockResolvedValue(true);
    logAuditEventMock.mockReset();
    results = {};
    ops = [];
  });

  it("401s without credentials", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    expect((await clients("GET"))._getStatusCode()).toBe(401);
  });

  it("403s when driven by an API key", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "key" });
    expect((await clients("POST", { name: "Acme" }))._getStatusCode()).toBe(403);
    expect(ops).toEqual([]);
  });

  it("403s without Agency access, before touching the database", async () => {
    hasAgencyAccessMock.mockResolvedValue(false);
    const res = await clients("GET");
    expect(res._getStatusCode()).toBe(403);
    expect(ops).toEqual([]);
  });

  it("405s on an unsupported method", async () => {
    expect((await clients("PUT"))._getStatusCode()).toBe(405);
  });

  describe("GET", () => {
    it("lists clients with per-client and unassigned site counts, scoped to the owner", async () => {
      results["clients:select"] = { data: [ROW, { ...ROW, id: "c2", name: "Beta" }], error: null };
      results["monitored_targets:select"] = {
        data: [{ client_id: "c1" }, { client_id: "c1" }, { client_id: "c2" }, { client_id: null }],
        error: null,
      };
      const res = await clients("GET");
      expect(res._getStatusCode()).toBe(200);
      const body = res._getJSONData() as { clients: { id: string; site_count: number }[]; unassigned_sites: number };
      expect(body.clients.map((c) => [c.id, c.site_count])).toEqual([["c1", 2], ["c2", 1]]);
      expect(body.unassigned_sites).toBe(1);
      expect(lastOp("clients", "select")?.filters).toEqual(["eq:owner=owner-1"]);
      expect(lastOp("monitored_targets", "select")?.filters).toEqual(["eq:owner=owner-1"]);
    });

    it("returns an empty list for a new agency", async () => {
      results["clients:select"] = { data: [], error: null };
      results["monitored_targets:select"] = { data: [], error: null };
      expect((await clients("GET"))._getJSONData()).toEqual({ clients: [], unassigned_sites: 0 });
    });

    it("500s when the list query fails", async () => {
      results["clients:select"] = { data: null, error: { message: "db down" } };
      expect((await clients("GET"))._getStatusCode()).toBe(500);
    });

    it("503s when migration 063 is not applied", async () => {
      results["clients:select"] = { data: null, error: { code: "42P01", message: "relation does not exist" } };
      expect((await clients("GET"))._getStatusCode()).toBe(503);
    });
  });

  describe("POST", () => {
    beforeEach(() => {
      results["clients:select"] = { data: null, error: null, count: 0 };
      results["clients:insert"] = { data: ROW, error: null };
    });

    it("creates a client owned by the caller and audits it", async () => {
      const res = await clients("POST", { name: "  Acme  ", notes: "Retainer" });
      expect(res._getStatusCode()).toBe(201);
      expect(res._getJSONData()).toMatchObject({ id: "c1", site_count: 0 });
      expect(lastOp("clients", "insert")?.values).toMatchObject({ owner: "owner-1", name: "Acme", notes: "Retainer", brand_name: null });
      expect(logAuditEventMock).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ action: "client.created", resourceType: "client", resourceId: "c1", actorId: "owner-1" }),
      );
    });

    it("400s without a name", async () => {
      expect((await clients("POST", {}))._getStatusCode()).toBe(400);
      expect((await clients("POST", { name: "   " }))._getStatusCode()).toBe(400);
    });

    it("400s on an over-long name", async () => {
      expect((await clients("POST", { name: "x".repeat(81) }))._getStatusCode()).toBe(400);
    });

    it("rejects a non-https brand logo", async () => {
      const res = await clients("POST", { name: "Acme", brand_logo_url: "http://x.test/logo.png" });
      expect(res._getStatusCode()).toBe(400);
      expect(ops).toEqual([]);
    });

    it("accepts an https brand logo and brand name", async () => {
      const res = await clients("POST", { name: "Acme", brand_name: "Acme Ltd", brand_logo_url: "https://x.test/logo.png" });
      expect(res._getStatusCode()).toBe(201);
      expect(lastOp("clients", "insert")?.values).toMatchObject({ brand_name: "Acme Ltd", brand_logo_url: "https://x.test/logo.png" });
    });

    it("409s on a duplicate name", async () => {
      results["clients:insert"] = { data: null, error: { code: "23505", message: "duplicate key" } };
      expect((await clients("POST", { name: "Acme" }))._getStatusCode()).toBe(409);
      expect(logAuditEventMock).not.toHaveBeenCalled();
    });

    it("400s at the client limit", async () => {
      results["clients:select"] = { data: null, error: null, count: 100 };
      expect((await clients("POST", { name: "Acme" }))._getStatusCode()).toBe(400);
      expect(lastOp("clients", "insert")).toBeUndefined();
    });

    it("500s, without auditing, when the insert fails", async () => {
      results["clients:insert"] = { data: null, error: { message: "db down" } };
      expect((await clients("POST", { name: "Acme" }))._getStatusCode()).toBe(500);
      expect(logAuditEventMock).not.toHaveBeenCalled();
    });
  });

  describe("PATCH", () => {
    it("updates only the supplied fields, scoped to id and owner, and audits it", async () => {
      results["clients:update"] = { data: { ...ROW, name: "Acme 2" }, error: null };
      const res = await clients("PATCH", { id: "c1", name: "Acme 2" });
      expect(res._getStatusCode()).toBe(200);
      expect(lastOp("clients", "update")?.values).toEqual({ name: "Acme 2" });
      expect(lastOp("clients", "update")?.filters).toEqual(["eq:id=c1", "eq:owner=owner-1"]);
      expect(logAuditEventMock).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ action: "client.updated", resourceId: "c1", metadata: { fields: ["name"] } }),
      );
    });

    it("clears a brand override when sent a blank string or null", async () => {
      results["clients:update"] = { data: ROW, error: null };
      await clients("PATCH", { id: "c1", brand_name: "", brand_logo_url: null });
      expect(lastOp("clients", "update")?.values).toEqual({ brand_name: null, brand_logo_url: null });
    });

    it("404s for a client the caller does not own", async () => {
      results["clients:update"] = { data: null, error: null };
      expect((await clients("PATCH", { id: "other", name: "X" }))._getStatusCode()).toBe(404);
      expect(logAuditEventMock).not.toHaveBeenCalled();
    });

    it("400s with nothing to update, or without an id", async () => {
      expect((await clients("PATCH", { id: "c1" }))._getStatusCode()).toBe(400);
      expect((await clients("PATCH", { name: "X" }))._getStatusCode()).toBe(400);
    });

    it("409s when renaming onto an existing client", async () => {
      results["clients:update"] = { data: null, error: { code: "23505", message: "dup" } };
      expect((await clients("PATCH", { id: "c1", name: "Beta" }))._getStatusCode()).toBe(409);
    });
  });

  describe("DELETE", () => {
    it("deletes the caller's client and audits it", async () => {
      results["clients:delete"] = { data: { id: "c1", name: "Acme" }, error: null };
      const res = await clients("DELETE", { id: "c1" });
      expect(res._getStatusCode()).toBe(200);
      expect(lastOp("clients", "delete")?.filters).toEqual(["eq:id=c1", "eq:owner=owner-1"]);
      expect(logAuditEventMock).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ action: "client.deleted", resourceId: "c1", metadata: { name: "Acme" } }),
      );
    });

    it("404s for another owner's client", async () => {
      results["clients:delete"] = { data: null, error: null };
      expect((await clients("DELETE", { id: "other" }))._getStatusCode()).toBe(404);
      expect(logAuditEventMock).not.toHaveBeenCalled();
    });

    it("400s without an id", async () => {
      expect((await clients("DELETE", {}))._getStatusCode()).toBe(400);
    });

    it("500s when the delete fails", async () => {
      results["clients:delete"] = { data: null, error: { message: "db down" } };
      expect((await clients("DELETE", { id: "c1" }))._getStatusCode()).toBe(500);
    });
  });
});

describe("/api/clients/assign", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
    hasAgencyAccessMock.mockReset().mockResolvedValue(true);
    logAuditEventMock.mockReset();
    results = {
      "clients:select": { data: { id: "c1" }, error: null },
      "monitored_targets:update": { data: [{ id: "t1" }, { id: "t2" }], error: null },
      "verifications:update": { data: [{ id: "v1" }], error: null },
    };
    ops = [];
  });

  it("405s on anything but POST", async () => {
    expect((await call(assignHandler, "GET"))._getStatusCode()).toBe(405);
  });

  it("401s without credentials and 403s for API keys or non-Agency plans", async () => {
    authenticateApiRequestMock.mockResolvedValueOnce(null);
    expect((await assign({ client_id: "c1", target_ids: ["t1"] }))._getStatusCode()).toBe(401);
    authenticateApiRequestMock.mockResolvedValueOnce({ ownerId: "owner-1", via: "key" });
    expect((await assign({ client_id: "c1", target_ids: ["t1"] }))._getStatusCode()).toBe(403);
    hasAgencyAccessMock.mockResolvedValueOnce(false);
    expect((await assign({ client_id: "c1", target_ids: ["t1"] }))._getStatusCode()).toBe(403);
    expect(ops).toEqual([]);
  });

  it("assigns sites and domains, filtering updates by owner, and audits the counts", async () => {
    const res = await assign({ client_id: "c1", target_ids: ["t1", "t2"], verification_ids: ["v1"] });
    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toEqual({ updated: { sites: 2, domains: 1 } });
    expect(lastOp("monitored_targets", "update")?.values).toEqual({ client_id: "c1" });
    expect(lastOp("monitored_targets", "update")?.filters).toEqual(["in:id=t1,t2", "eq:owner=owner-1"]);
    expect(logAuditEventMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ action: "client.sites_assigned", resourceId: "c1", metadata: { sites: 2, domains: 1 } }),
    );
  });

  it("404s, without updating anything, when the client belongs to someone else", async () => {
    results["clients:select"] = { data: null, error: null };
    const res = await assign({ client_id: "foreign", target_ids: ["t1"] });
    expect(res._getStatusCode()).toBe(404);
    expect(lastOp("monitored_targets", "update")).toBeUndefined();
  });

  it("unassigns with client_id null, skipping the client lookup", async () => {
    const res = await assign({ client_id: null, target_ids: ["t1"] });
    expect(res._getStatusCode()).toBe(200);
    expect(lastOp("monitored_targets", "update")?.values).toEqual({ client_id: null });
    expect(lastOp("clients", "select")).toBeUndefined();
    expect(lastOp("verifications", "update")).toBeUndefined();
  });

  it("400s with no ids or a missing client_id", async () => {
    expect((await assign({ client_id: "c1" }))._getStatusCode()).toBe(400);
    expect((await assign({ target_ids: ["t1"] }))._getStatusCode()).toBe(400);
  });

  it("500s on a database error and 503s when migration 063 is pending", async () => {
    results["monitored_targets:update"] = { data: null, error: { message: "db down" } };
    expect((await assign({ client_id: "c1", target_ids: ["t1"] }))._getStatusCode()).toBe(500);
    results["monitored_targets:update"] = { data: null, error: { code: "42703", message: "no column client_id" } };
    expect((await assign({ client_id: "c1", target_ids: ["t1"] }))._getStatusCode()).toBe(503);
  });
});
