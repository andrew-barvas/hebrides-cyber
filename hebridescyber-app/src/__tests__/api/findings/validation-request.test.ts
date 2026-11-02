import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const h = vi.hoisted(() => ({
  auth: vi.fn(),
  canAct: vi.fn(),
  limit: vi.fn(),
  send: vi.fn(),
  tables: {} as Record<string, unknown>,
  inserted: null as Record<string, unknown> | null,
  insertResult: null as unknown,
}));

function builder(table: string) {
  const b: Record<string, unknown> = {
    select: () => b,
    eq: () => b,
    order: () => b,
    limit: () => b,
    insert: (row: Record<string, unknown>) => ((h.inserted = row), b),
    maybeSingle: () => Promise.resolve(h.tables[table] ?? { data: null, error: null }),
    single: () => Promise.resolve(h.insertResult ?? { data: { id: "req-1", ...(h.inserted ?? {}) }, error: null }),
    then: (resolve: (v: unknown) => unknown) => Promise.resolve(h.tables[table] ?? { data: [], error: null }).then(resolve),
  };
  return b;
}

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: h.auth, supabaseAdmin: { from: builder } }));
vi.mock("@/lib/teamAccess", () => ({ callerCanActFor: h.canAct }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: h.limit }));
vi.mock("@/lib/email", async (orig) => ({ ...(await orig<typeof import("@/lib/email")>()), sendEmail: h.send }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: vi.fn() }));

import handler from "@/pages/api/findings/validation-request";

const SCAN = "11111111-1111-4111-8111-111111111111";
const FINDINGS = [
  { checkId: "xss.reflected", severity: "high", title: "Reflected XSS", detail: "d", remediation: "r", metadata: { proofOfExploit: { confirmed: true, evidence: "ran" } } },
];

const call = async (method: string, body?: unknown, query: Record<string, string> = {}) => {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "POST", body: body as never, query, headers: { authorization: "Bearer t" } });
  await handler(req, res);
  return res;
};

beforeEach(() => {
  h.auth.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
  h.canAct.mockReset().mockResolvedValue(true);
  h.limit.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
  h.send.mockReset().mockResolvedValue({ ok: true });
  h.inserted = null;
  h.insertResult = null;
  h.tables = {
    scans: { data: { id: SCAN, owner: "owner-1", target_url: "https://example.com/app" }, error: null },
    scan_results: { data: { results: { findings: FINDINGS } }, error: null },
    users: { data: { email: "me@example.com" }, error: null },
  };
});

describe("POST /api/findings/validation-request", () => {
  it("needs a signed-in caller and a well-formed body", async () => {
    h.auth.mockResolvedValueOnce(null);
    expect((await call("POST", { scanId: SCAN, checkId: "x" })).statusCode).toBe(401);
    expect((await call("POST", { scanId: "nope", checkId: "x" })).statusCode).toBe(400);
    expect((await call("POST", { scanId: SCAN })).statusCode).toBe(400);
    expect((await call("DELETE")).statusCode).toBe(405);
  });

  it("records a snapshot taken from the stored scan, never from the request", async () => {
    const res = await call("POST", { scanId: SCAN, checkId: "xss.reflected", note: "  our payment page  ", title: "forged", severity: "critical" });
    expect(res.statusCode).toBe(201);
    expect(h.inserted).toMatchObject({
      owner: "owner-1",
      requested_by: "owner-1",
      scan_id: SCAN,
      target_host: "example.com",
      check_id: "xss.reflected",
      severity: "high",
      title: "Reflected XSS",
      confirmed_exploitable: true,
      note: "our payment page",
    });
    expect(JSON.parse(res._getData()).message).toMatch(/Nothing has been tested/);
  });

  it("tells the operator, with the customer's email, and still succeeds if the email cannot be sent", async () => {
    await call("POST", { scanId: SCAN, checkId: "xss.reflected" });
    expect(h.send).toHaveBeenCalledWith(expect.objectContaining({ subject: "Validation request: high on example.com" }));
    expect(h.send.mock.calls[0][0].html).toContain("me@example.com");
    h.send.mockResolvedValueOnce({ ok: false, error: "boom" });
    expect((await call("POST", { scanId: SCAN, checkId: "xss.reflected" })).statusCode).toBe(201);
  });

  it("refuses a scan the caller cannot act on, a missing scan and a finding that is not in the scan", async () => {
    h.canAct.mockResolvedValueOnce(false);
    expect((await call("POST", { scanId: SCAN, checkId: "xss.reflected" })).statusCode).toBe(403);
    h.tables.scans = { data: null, error: null };
    expect((await call("POST", { scanId: SCAN, checkId: "xss.reflected" })).statusCode).toBe(404);
    h.tables.scans = { data: { id: SCAN, owner: "owner-1", target_url: "https://example.com" }, error: null };
    const res = await call("POST", { scanId: SCAN, checkId: "invented.finding" });
    expect(res.statusCode).toBe(404);
    expect(h.inserted).toBeNull();
  });

  it("is rate limited per account, and answers 409 for a request already open", async () => {
    h.limit.mockResolvedValueOnce({ allowed: false, retryAfterSeconds: 90 });
    const limited = await call("POST", { scanId: SCAN, checkId: "xss.reflected" });
    expect(limited.statusCode).toBe(429);
    expect(limited.getHeader("Retry-After")).toBe("90");
    expect(h.send).not.toHaveBeenCalled();
    h.insertResult = { data: null, error: { code: "23505", message: "dup" } };
    expect((await call("POST", { scanId: SCAN, checkId: "xss.reflected" })).statusCode).toBe(409);
    expect(h.send).not.toHaveBeenCalled();
  });

  it("says so, rather than failing, before the migration is applied", async () => {
    h.insertResult = { data: null, error: { code: "42P01", message: 'relation "validation_requests" does not exist' } };
    expect((await call("POST", { scanId: SCAN, checkId: "xss.reflected" })).statusCode).toBe(503);
  });
});

describe("GET /api/findings/validation-request", () => {
  it("lists this account's requests, and rejects a malformed scan id", async () => {
    h.tables.validation_requests = { data: [{ id: "r1" }], error: null };
    const res = await call("GET");
    expect(JSON.parse(res._getData())).toEqual({ available: true, requests: [{ id: "r1" }] });
    expect((await call("GET", undefined, { scanId: "x" })).statusCode).toBe(400);
  });
});
