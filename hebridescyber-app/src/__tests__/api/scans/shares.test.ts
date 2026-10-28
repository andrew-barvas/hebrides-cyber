import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, auditMock, state } = vi.hoisted(() => ({
  authMock: vi.fn(),
  auditMock: vi.fn(),
  state: {
    scan: { data: { id: "scan-1", owner: "owner-1" } } as { data: unknown },
    activeShares: [] as unknown[],
    list: { data: [] as unknown[], error: null as unknown },
    insert: { data: { id: "share-1", token: "tok" } as unknown, error: null as unknown },
    del: { error: null as unknown },
    inserted: null as unknown,
  },
}));

vi.mock("@/lib/reportShares", () => ({ generateShareToken: () => "tok" }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: auditMock }));
vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authMock,
  supabaseAdmin: {
    from: (table: string) => {
      if (table === "scans") {
        const b: Record<string, unknown> = {};
        for (const m of ["select", "eq"]) b[m] = () => b;
        b.maybeSingle = () => Promise.resolve(state.scan);
        return b;
      }
      // report_shares: the chain differs per operation, so branch on the first call.
      const b: Record<string, unknown> = {};
      let op = "";
      const chain = () => b;
      b.select = () => {
        if (!op) op = "select";
        return b;
      };
      b.insert = (row: unknown) => {
        op = "insert";
        state.inserted = row;
        return b;
      };
      b.delete = () => {
        op = "delete";
        return b;
      };
      b.eq = chain;
      b.order = chain;
      b.single = () => Promise.resolve(state.insert);
      // .is(...) only appears on the active-share count; list ends at .order().
      b.is = () => Promise.resolve({ data: state.activeShares });
      b.then = (resolve: (v: unknown) => void) => resolve(op === "delete" ? state.del : state.list);
      return b;
    },
  },
}));

import handler from "@/pages/api/scans/[id]/shares";

function call(method: string, body?: unknown) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "GET", query: { id: "scan-1" }, body: body as Record<string, unknown> });
  return handler(req, res).then(() => res as Omit<typeof res, "_getJSONData"> & { _getJSONData(): any }); // eslint-disable-line @typescript-eslint/no-explicit-any
}

beforeEach(() => {
  process.env.NEXT_PUBLIC_SITE_URL = "https://www.example.test";
  authMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
  auditMock.mockReset();
  state.scan = { data: { id: "scan-1", owner: "owner-1" } };
  state.activeShares = [];
  state.list = { data: [], error: null };
  state.insert = { data: { id: "share-1", token: "tok" }, error: null };
  state.del = { error: null };
  state.inserted = null;
});

describe("/api/scans/[id]/shares", () => {
  it("401s when unauthenticated", async () => {
    authMock.mockResolvedValue(null);
    expect((await call("GET")).statusCode).toBe(401);
  });

  it("refuses an API key — a public link is an account write", async () => {
    authMock.mockResolvedValue({ ownerId: "owner-1", via: "api_key" });
    expect((await call("POST", {})).statusCode).toBe(403);
  });

  it("404s for an unknown scan and 403s for someone else's", async () => {
    state.scan = { data: null };
    expect((await call("GET")).statusCode).toBe(404);
    state.scan = { data: { id: "scan-1", owner: "someone-else" } };
    expect((await call("GET")).statusCode).toBe(403);
  });

  it("GET lists shares with a full share_url", async () => {
    state.list = { data: [{ token: "abc" }], error: null };
    const res = await call("GET");
    expect(res.statusCode).toBe(200);
    expect(res._getJSONData().shares[0].share_url).toBe("https://www.example.test/share/abc");
  });

  it("POST creates a never-expiring link by default and audits it", async () => {
    const res = await call("POST", {});
    expect(res.statusCode).toBe(201);
    expect(state.inserted).toMatchObject({ scan_id: "scan-1", token: "tok", expires_at: null });
    expect(res._getJSONData().share_url).toBe("https://www.example.test/share/tok");
    expect(auditMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "share_link.created" }));
  });

  it("POST turns expires_in_days into a future timestamp", async () => {
    await call("POST", { expires_in_days: 7 });
    const expiry = new Date((state.inserted as { expires_at: string }).expires_at).getTime();
    expect(expiry - Date.now()).toBeGreaterThan(6.9 * 86_400_000);
    expect(expiry - Date.now()).toBeLessThan(7.1 * 86_400_000);
  });

  it.each([0, 366, 1.5, "7"])("POST rejects expires_in_days=%s", async (days) => {
    expect((await call("POST", { expires_in_days: days })).statusCode).toBe(400);
  });

  it("POST stops at 10 active links per scan", async () => {
    state.activeShares = Array.from({ length: 10 }, (_, i) => ({ id: String(i) }));
    const res = await call("POST", {});
    expect(res.statusCode).toBe(400);
    expect(state.inserted).toBeNull();
  });

  it("DELETE revokes the link and audits it", async () => {
    const res = await call("DELETE", { id: "share-1" });
    expect(res.statusCode).toBe(200);
    expect(auditMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "share_link.revoked", metadata: { share_id: "share-1" } }));
  });

  it("DELETE requires an id and 500s without auditing on a database error", async () => {
    expect((await call("DELETE", {})).statusCode).toBe(400);
    state.del = { error: { message: "boom" } };
    expect((await call("DELETE", { id: "share-1" })).statusCode).toBe(500);
    expect(auditMock).not.toHaveBeenCalled();
  });

  it("405s on an unsupported method", async () => {
    expect((await call("PUT")).statusCode).toBe(405);
  });
});
