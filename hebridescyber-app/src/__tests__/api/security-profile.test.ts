import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, isDomainVerifiedMock, logAuditEventMock, state } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  isDomainVerifiedMock: vi.fn(),
  logAuditEventMock: vi.fn(),
  state: { existing: null as { slug: string } | null, inserted: [] as unknown[], deleted: 0 },
}));

function builder() {
  const b: Record<string, unknown> = {
    select: () => b,
    eq: () => b,
    maybeSingle: () => Promise.resolve({ data: state.existing, error: null }),
    insert: (row: unknown) => {
      state.inserted.push(row);
      return Promise.resolve({ error: null });
    },
    delete: () => {
      state.deleted++;
      const d: Record<string, unknown> = { eq: () => d, then: (r: (v: unknown) => void) => r({ error: null }) };
      return d;
    },
  };
  return b;
}

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authenticateApiRequestMock, supabaseAdmin: { from: () => builder() } }));
vi.mock("@/lib/ownership", () => ({ isDomainVerified: isDomainVerifiedMock }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));

import handler from "@/pages/api/security-profile";

function call(method: RequestMethod, opts: { body?: Record<string, unknown>; query?: Record<string, string> } = {}) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, body: opts.body, query: opts.query });
  return handler(req, res).then(() => res);
}

describe("/api/security-profile", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
    isDomainVerifiedMock.mockReset().mockResolvedValue(true);
    logAuditEventMock.mockReset();
    state.existing = null;
    state.inserted = [];
    state.deleted = 0;
  });

  it("refuses API keys: publishing is a deliberate session action", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "api_key" });
    expect((await call("POST", { body: { targetUrl: "https://shop.example" } }))._getStatusCode()).toBe(403);
  });

  it("refuses to publish for a domain the caller hasn't verified", async () => {
    isDomainVerifiedMock.mockResolvedValue(false);
    const res = await call("POST", { body: { targetUrl: "https://shop.example" } });
    expect(res._getStatusCode()).toBe(403);
    expect(state.inserted).toEqual([]);
  });

  it("publishes with a fresh slug, and publishing again keeps the existing one", async () => {
    const first = await call("POST", { body: { targetUrl: "https://Shop.Example/path" } });
    expect(first._getStatusCode()).toBe(201);
    expect(state.inserted).toEqual([{ owner: "owner-1", target_host: "shop.example", slug: first._getJSONData().slug }]);
    expect(logAuditEventMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "security_profile.published" }));

    state.existing = { slug: "existingslug1234" };
    const again = await call("POST", { body: { targetUrl: "https://shop.example" } });
    expect(again._getJSONData()).toEqual({ slug: "existingslug1234" });
    expect(state.inserted).toHaveLength(1);
  });

  it("looks up and removes a profile", async () => {
    state.existing = { slug: "existingslug1234" };
    expect((await call("GET", { query: { targetUrl: "https://shop.example" } }))._getJSONData()).toEqual({ slug: "existingslug1234" });
    const removed = await call("DELETE", { body: { targetUrl: "https://shop.example" } });
    expect(removed._getJSONData()).toEqual({ removed: true });
    expect(state.deleted).toBe(1);
  });

  it("rejects a missing or non-URL target", async () => {
    expect((await call("POST", { body: {} }))._getStatusCode()).toBe(400);
    expect((await call("GET", { query: { targetUrl: "not a url" } }))._getStatusCode()).toBe(400);
  });
});
