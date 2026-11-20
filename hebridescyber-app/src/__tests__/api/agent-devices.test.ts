import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, auditMock, gateMock } = vi.hoisted(() => ({ authMock: vi.fn(), auditMock: vi.fn(), gateMock: vi.fn() }));

type Result = { data: unknown; error: { code?: string; message: string } | null; count?: number | null };
let listResult: Result;
let countResult: Result;
let insertResult: Result;
let revokeResult: Result;
let lastInsert: Record<string, unknown> | null;
let lastRevoke: { values: Record<string, unknown>; filters: Array<[string, unknown]> } | null;

function builder() {
  const filters: Array<[string, unknown]> = [];
  let mode: "list" | "count" | "insert" | "update" = "list";
  let values: Record<string, unknown> = {};
  const b: Record<string, unknown> = {
    select: (_cols: string, opts?: { head?: boolean }) => {
      if (opts?.head) mode = "count";
      return b;
    },
    eq: (c: string, v: unknown) => (filters.push([c, v]), b),
    is: (c: string, v: unknown) => {
      filters.push([c, v]);
      return mode === "count" ? Promise.resolve(countResult) : b;
    },
    order: () => Promise.resolve(listResult),
    insert: (v: Record<string, unknown>) => {
      mode = "insert";
      lastInsert = v;
      return b;
    },
    single: () => Promise.resolve(insertResult),
    update: (v: Record<string, unknown>) => {
      mode = "update";
      values = v;
      return b;
    },
    maybeSingle: () => {
      lastRevoke = { values, filters: [...filters] };
      return Promise.resolve(revokeResult);
    },
  };
  return b;
}

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authMock, supabaseAdmin: { from: () => builder() } }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: auditMock }));
vi.mock("@/lib/deviceAgent/access", () => ({ deviceAgentGate: gateMock, MAX_ACTIVE_DEVICES: 3 }));

import handler, { toClientDevice } from "@/pages/api/agent/devices";

function call(method: RequestMethod, body?: Record<string, unknown>) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, body });
  return handler(req, res).then(() => res);
}

const row = {
  id: "11111111-1111-4111-8111-111111111111",
  name: "Reception PC",
  token_prefix: "hcd_abcdefgh",
  token_hash: "f".repeat(64),
  created_at: "2026-11-01T00:00:00Z",
  revoked_at: null,
  last_seen_at: "2026-11-19T09:00:00Z",
  hostname: "RECEPTION-PC",
  os_family: "windows",
  os_name: "Microsoft Windows 11 Pro",
  os_version: "10.0.22631.3447",
  agent_version: "0.1.0",
  patch_status: "fails",
  evaluation: { summary: "Misses the 14-day rule: 1 item overdue." },
  last_match: { status: "checked", cves: Array.from({ length: 30 }, (_, i) => ({ id: `CVE-${i}` })), osEol: null, coverage: { softwareTotal: 3, softwareChecked: 2 } },
  matched_at: "2026-11-19T10:00:00Z",
};

describe("/api/agent/devices", () => {
  beforeEach(() => {
    authMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
    auditMock.mockReset();
    gateMock.mockReset().mockResolvedValue("ok");
    listResult = { data: [row], error: null };
    countResult = { data: null, error: null, count: 0 };
    insertResult = { data: { id: "dev-new", name: "Laptop", token_prefix: "hcd_xxxxxxxx", created_at: "2026-11-20" }, error: null };
    revokeResult = { data: { id: row.id }, error: null };
    lastInsert = null;
    lastRevoke = null;
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-11-20T09:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("needs a session: no caller is 401, an API key is 403", async () => {
    authMock.mockResolvedValueOnce(null);
    expect((await call("GET"))._getStatusCode()).toBe(401);
    authMock.mockResolvedValueOnce({ ownerId: "owner-1", via: "key" });
    expect((await call("POST", { name: "x" }))._getStatusCode()).toBe(403);
    expect(lastInsert).toBeNull();
  });

  describe("GET", () => {
    it("lists devices without the token hash, with display status and a capped CVE list", async () => {
      const res = await call("GET");
      expect(res._getStatusCode()).toBe(200);
      const body = res._getJSONData() as { enabled: boolean; devices: Array<{ match: { cves: unknown[]; cve_count: number } } & Record<string, unknown>> };
      expect(body.enabled).toBe(true);
      const [d] = body.devices;
      expect(JSON.stringify(d)).not.toContain("f".repeat(64));
      expect(d).toMatchObject({ id: row.id, status: "fails", os: { family: "windows", version: "10.0.22631.3447" } });
      expect(d.match.cves).toHaveLength(25);
      expect(d.match.cve_count).toBe(30);
    });

    it("answers an empty, disabled list before migration 084, and hides other errors", async () => {
      listResult = { data: null, error: { code: "42P01", message: "relation agent_devices does not exist" } };
      expect((await call("GET"))._getJSONData()).toEqual({ devices: [], enabled: false });
      listResult = { data: null, error: { code: "XX000", message: "agent_devices broke" } };
      const res = await call("GET");
      expect(res._getStatusCode()).toBe(500);
      expect(JSON.stringify(res._getJSONData())).not.toContain("agent_devices");
    });
  });

  describe("toClientDevice", () => {
    const now = new Date("2026-11-20T09:00:00Z");
    it("shows revoked, stale and never-reported devices honestly", () => {
      expect(toClientDevice({ ...row, revoked_at: "2026-11-10" }, now).status).toBe("revoked");
      expect(toClientDevice({ ...row, last_seen_at: "2026-11-01T00:00:00Z" }, now).status).toBe("stale");
      expect(toClientDevice({ ...row, last_seen_at: null, patch_status: "never_reported", evaluation: null, last_match: null }, now)).toMatchObject({ status: "never_reported", evaluation: null, match: null });
    });
    it("tolerates a match with missing fields", () => {
      expect(toClientDevice({ ...row, last_match: {} }, now).match).toEqual({ status: null, cves: [], cve_count: 0, os_eol: null, coverage: null });
    });
  });

  describe("POST", () => {
    it("issues a token once, stores only its hash, and audits", async () => {
      const res = await call("POST", { name: "  Laptop  " });
      expect(res._getStatusCode()).toBe(201);
      const body = res._getJSONData() as { token: string };
      expect(body.token).toMatch(/^hcd_[A-Za-z0-9_-]{43}$/);
      expect(lastInsert).toMatchObject({ owner: "owner-1", name: "Laptop", created_by: "owner-1" });
      expect(lastInsert!.token_hash).toMatch(/^[0-9a-f]{64}$/);
      expect(JSON.stringify(lastInsert)).not.toContain(body.token);
      expect(auditMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "agent_device.created", resourceId: "dev-new" }));
    });

    it("validates the name", async () => {
      expect((await call("POST", { name: "" }))._getStatusCode()).toBe(400);
      expect((await call("POST", { name: "x".repeat(81) }))._getStatusCode()).toBe(400);
    });

    it("is gated on the plan", async () => {
      gateMock.mockResolvedValueOnce("denied");
      expect((await call("POST", { name: "Laptop" }))._getStatusCode()).toBe(403);
      gateMock.mockResolvedValueOnce("error");
      expect((await call("POST", { name: "Laptop" }))._getStatusCode()).toBe(500);
      expect(lastInsert).toBeNull();
    });

    it("caps active devices per account", async () => {
      countResult = { data: null, error: null, count: 3 };
      const res = await call("POST", { name: "Laptop" });
      expect(res._getStatusCode()).toBe(400);
      expect((res._getJSONData() as { error: string }).error).toMatch(/limit reached \(3 active\)/);
    });

    it("503s before migration 084, on the count or the insert, and hides other errors", async () => {
      countResult = { data: null, error: { code: "42P01", message: "missing" } };
      expect((await call("POST", { name: "Laptop" }))._getStatusCode()).toBe(503);
      countResult = { data: null, error: { code: "XX000", message: "count failed" } };
      expect((await call("POST", { name: "Laptop" }))._getStatusCode()).toBe(500);
      countResult = { data: null, error: null, count: 0 };
      insertResult = { data: null, error: { code: "42P01", message: "missing" } };
      expect((await call("POST", { name: "Laptop" }))._getStatusCode()).toBe(503);
      insertResult = { data: null, error: { code: "23505", message: "agent_devices_token_hash_key" } };
      const res = await call("POST", { name: "Laptop" });
      expect(res._getStatusCode()).toBe(500);
      expect(JSON.stringify(res._getJSONData())).not.toContain("token_hash");
    });
  });

  describe("DELETE", () => {
    it("revokes the caller's own active device and audits", async () => {
      const res = await call("DELETE", { id: row.id });
      expect(res._getStatusCode()).toBe(200);
      expect(lastRevoke!.filters).toEqual([["id", row.id], ["owner", "owner-1"], ["revoked_at", null]]);
      expect(lastRevoke!.values.revoked_at).toBe("2026-11-20T09:00:00.000Z");
      expect(auditMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "agent_device.revoked", resourceId: row.id }));
    });

    it("404s a device that isn't the caller's (or is already revoked) and 400s a bad id", async () => {
      revokeResult = { data: null, error: null };
      expect((await call("DELETE", { id: row.id }))._getStatusCode()).toBe(404);
      expect((await call("DELETE", { id: "nope" }))._getStatusCode()).toBe(400);
      expect(auditMock).not.toHaveBeenCalled();
    });

    it("503s before migration 084 and hides other errors", async () => {
      revokeResult = { data: null, error: { code: "42P01", message: "missing" } };
      expect((await call("DELETE", { id: row.id }))._getStatusCode()).toBe(503);
      revokeResult = { data: null, error: { code: "XX000", message: "agent_devices broke" } };
      expect((await call("DELETE", { id: row.id }))._getStatusCode()).toBe(500);
    });
  });

  it("405s other methods", async () => {
    const res = await call("PUT");
    expect(res._getStatusCode()).toBe(405);
    expect(res.getHeader("Allow")).toBe("GET, POST, DELETE");
  });
});
