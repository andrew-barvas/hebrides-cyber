import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, validateMock, auditMock, db } = vi.hoisted(() => ({
  authMock: vi.fn(),
  validateMock: vi.fn(),
  auditMock: vi.fn(),
  db: { result: { data: null, error: null } as { data: unknown; error: unknown }, calls: [] as Array<[string, unknown]> },
}));

// Chainable query builder that records each call and resolves to db.result.
function builder() {
  const b: Record<string, unknown> = {};
  for (const m of ["select", "eq", "order", "insert", "update", "delete", "single"]) {
    b[m] = (arg: unknown, val?: unknown) => {
      db.calls.push([m, m === "eq" ? `${String(arg)}=${String(val)}` : arg]);
      return b;
    };
  }
  b.then = (resolve: (v: unknown) => void) => resolve(db.result);
  return b;
}

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authMock, supabaseAdmin: { from: () => builder() } }));
vi.mock("@/lib/siemIntegration", () => ({ validateSiemWebhook: validateMock }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: auditMock }));

import handler from "@/pages/api/account/siem-integration";

const UUID = "7d0c5d0e-1b7e-4a3c-9d57-0f6f3f5a1c11";

function call(method: string, body?: unknown) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "GET", body: body as Record<string, unknown> });
  return handler(req, res).then(() => res as Omit<typeof res, "_getJSONData"> & { _getJSONData(): any }); // eslint-disable-line @typescript-eslint/no-explicit-any
}
const callsTo = (name: string) => db.calls.filter(([m]) => m === name).map(([, a]) => a);

beforeEach(() => {
  authMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
  validateMock.mockReset().mockResolvedValue({ ok: true });
  auditMock.mockReset();
  db.calls = [];
  db.result = { data: null, error: null };
});

describe("/api/account/siem-integration", () => {
  it("401s when unauthenticated", async () => {
    authMock.mockResolvedValue(null);
    expect((await call("GET")).statusCode).toBe(401);
  });

  it("405s on an unsupported method", async () => {
    expect((await call("PUT")).statusCode).toBe(405);
  });

  describe("GET", () => {
    it("lists the caller's integrations and never selects the auth header", async () => {
      db.result = { data: [{ id: "a" }], error: null };
      const res = await call("GET");
      expect(res.statusCode).toBe(200);
      expect(res._getJSONData()).toEqual({ integrations: [{ id: "a" }] });
      expect(callsTo("eq")).toContain("owner=owner-1");
      expect(String(callsTo("select")[0])).not.toContain("auth_header");
    });

    it("500s on a database error", async () => {
      db.result = { data: null, error: { message: "db down" } };
      expect((await call("GET")).statusCode).toBe(500);
    });
  });

  describe("POST", () => {
    it("rejects an unknown type or an empty endpoint", async () => {
      expect((await call("POST", { type: "carrier-pigeon", endpoint: "x" })).statusCode).toBe(400);
      expect((await call("POST", { type: "webhook", endpoint: "" })).statusCode).toBe(400);
    });

    it("validates a webhook endpoint first and refuses to store one that fails", async () => {
      validateMock.mockResolvedValue({ ok: false, error: "private address" });
      const res = await call("POST", { type: "webhook", endpoint: "http://10.0.0.1/x" });
      expect(res.statusCode).toBe(400);
      expect(res._getJSONData().error).toContain("private address");
      expect(callsTo("insert")).toEqual([]);
    });

    it("skips webhook validation for syslog", async () => {
      db.result = { data: { id: UUID }, error: null };
      await call("POST", { type: "syslog", endpoint: "syslog.example.com:514" });
      expect(validateMock).not.toHaveBeenCalled();
    });

    it("creates with defaults, tags the owner, and audits it", async () => {
      db.result = { data: { id: UUID }, error: null };
      const res = await call("POST", { type: "webhook", endpoint: "https://siem.example.com/hook" });
      expect(res.statusCode).toBe(201);
      expect(callsTo("insert")[0]).toMatchObject({
        owner: "owner-1",
        name: "Default SIEM",
        format: "json",
        event_types: ["scan.completed", "finding.new", "finding.fixed"],
      });
      expect(auditMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "siem_integration.created", resourceId: UUID }));
    });

    it("500s without auditing when the insert fails", async () => {
      db.result = { data: null, error: { message: "boom" } };
      expect((await call("POST", { type: "syslog", endpoint: "h:514" })).statusCode).toBe(500);
      expect(auditMock).not.toHaveBeenCalled();
    });
  });

  describe("PATCH", () => {
    it("requires a uuid id", async () => {
      expect((await call("PATCH", { id: "nope", enabled: false })).statusCode).toBe(400);
    });

    it("maps only the supplied fields and scopes the update to the owner", async () => {
      const res = await call("PATCH", { id: UUID, enabled: false, eventTypes: ["finding.new"] });
      expect(res.statusCode).toBe(200);
      const update = callsTo("update")[0] as Record<string, unknown>;
      expect(update).toMatchObject({ enabled: false, event_types: ["finding.new"] });
      expect(update).not.toHaveProperty("endpoint");
      expect(callsTo("eq")).toEqual(expect.arrayContaining([`id=${UUID}`, "owner=owner-1"]));
    });
  });

  describe("DELETE", () => {
    it("deletes scoped to the owner and audits it", async () => {
      const res = await call("DELETE", { id: UUID });
      expect(res.statusCode).toBe(200);
      expect(callsTo("eq")).toEqual(expect.arrayContaining([`id=${UUID}`, "owner=owner-1"]));
      expect(auditMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "siem_integration.deleted", resourceId: UUID }));
    });

    it("500s without auditing when the delete fails", async () => {
      db.result = { data: null, error: { message: "boom" } };
      expect((await call("DELETE", { id: UUID })).statusCode).toBe(500);
      expect(auditMock).not.toHaveBeenCalled();
    });
  });
});
