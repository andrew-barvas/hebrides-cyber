// GET /api/admin/engagements, with the auth, customer lookup and record layers
// stubbed. listAllEngagements is covered by src/lib/engagements.test.ts and the
// customer lookup by src/__tests__/api/admin-lookout-reports.test.ts.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const m = vi.hoisted(() => ({
  requireAdmin: vi.fn(),
  resolve: vi.fn(),
  emails: vi.fn(),
  list: vi.fn(),
  internal: vi.fn(),
}));

vi.mock("@/lib/adminAuth", () => ({ requireAdmin: m.requireAdmin, supabaseAdmin: { tag: "admin" } }));
vi.mock("@/lib/lookoutCustomer", () => ({ resolveLookoutCustomer: m.resolve, customerEmails: m.emails }));
vi.mock("@/lib/engagements", async (original) => ({
  ...(await original<typeof import("@/lib/engagements")>()),
  listAllEngagements: m.list,
}));
vi.mock("@/lib/apiError", async (original) => {
  const real = await original<typeof import("@/lib/apiError")>();
  return {
    ...real,
    respondInternalError: (...args: Parameters<typeof real.respondInternalError>) => {
      m.internal(args[2]);
      args[0].status(500).json({ error: args[3]?.publicMessage ?? real.INTERNAL_ERROR_MESSAGE });
    },
  };
});

import handler from "@/pages/api/admin/engagements";

const ADMIN = "a2000000-0000-4000-8000-000000000002";
const OWNER_A = "a1000000-0000-4000-8000-000000000001";
const OWNER_B = "b1000000-0000-4000-8000-000000000001";

async function call(query: Record<string, string> = {}, method: RequestMethod = "GET") {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, query, headers: { authorization: "Bearer t" } });
  await handler(req, res);
  return { status: res._getStatusCode(), body: res._getJSONData() as Record<string, unknown>, headers: res._getHeaders() };
}

beforeEach(() => {
  for (const fn of Object.values(m)) fn.mockReset();
  m.requireAdmin.mockResolvedValue(ADMIN);
  m.list.mockResolvedValue({
    status: "ok",
    data: {
      engagements: [
        { id: "e1", owner: OWNER_A, reference: "ENG-1", state: "booked" },
        { id: "e2", owner: OWNER_B, reference: "ENG-2", state: "in_window" },
      ],
      truncated: false,
    },
  });
  m.emails.mockResolvedValue(new Map([[OWNER_A, "a@example.com"]]));
});

describe("GET /api/admin/engagements", () => {
  it("is 403 for anyone but an admin, and reads nothing", async () => {
    m.requireAdmin.mockResolvedValue(null);
    expect((await call()).status).toBe(403);
    expect(m.list).not.toHaveBeenCalled();
    expect(m.resolve).not.toHaveBeenCalled();
  });

  it("is 405 for anything but GET, before checking who is asking", async () => {
    const { status, headers } = await call({}, "POST");
    expect(status).toBe(405);
    expect(headers.allow).toBe("GET");
    expect(m.requireAdmin).not.toHaveBeenCalled();
  });

  it("lists every account's engagements with each owner's email, uncached", async () => {
    const { status, body, headers } = await call();
    expect(status).toBe(200);
    expect(headers["cache-control"]).toBe("private, no-store");
    expect(m.list).toHaveBeenCalledWith(expect.anything(), null);
    expect(m.emails).toHaveBeenCalledWith(expect.anything(), [OWNER_A, OWNER_B]);
    expect(body).toEqual({
      customer: null,
      engagements: [
        { id: "e1", owner: OWNER_A, reference: "ENG-1", state: "booked", owner_email: "a@example.com" },
        { id: "e2", owner: OWNER_B, reference: "ENG-2", state: "in_window", owner_email: null },
      ],
      truncated: false,
    });
  });

  it("looks the customer up by email and lists only theirs, returning the account to create under", async () => {
    m.resolve.mockResolvedValue({ ok: true, customer: { id: OWNER_A, email: "a@example.com" } });
    m.list.mockResolvedValue({ status: "ok", data: { engagements: [{ id: "e1", owner: OWNER_A, reference: "ENG-1", state: "booked" }], truncated: true } });
    const { status, body } = await call({ customer: "  A@Example.com " });
    expect(status).toBe(200);
    expect(m.resolve).toHaveBeenCalledWith(expect.anything(), "A@Example.com");
    expect(m.list).toHaveBeenCalledWith(expect.anything(), OWNER_A);
    expect(m.emails).not.toHaveBeenCalled();
    expect(body).toEqual({ customer: { id: OWNER_A, email: "a@example.com" }, engagements: [{ id: "e1", owner: OWNER_A, reference: "ENG-1", state: "booked", owner_email: "a@example.com" }], truncated: true });
  });

  it("passes on the lookup's own refusal for an unknown or ambiguous customer", async () => {
    m.resolve.mockResolvedValue({ ok: false, status: 404, error: "No account uses x@example.com." });
    expect(await call({ customer: "x@example.com" })).toMatchObject({ status: 404, body: { error: "No account uses x@example.com." } });
    m.resolve.mockResolvedValue({ ok: false, status: 400, error: "Enter the customer's email or user id." });
    expect((await call({ customer: "nope" })).status).toBe(400);
    expect(m.list).not.toHaveBeenCalled();
  });

  it("answers a failed lookup with a fixed message, never the database text", async () => {
    m.resolve.mockResolvedValue({ ok: false, status: 500, error: 'relation "users" does not exist' });
    const { status, body } = await call({ customer: "a@example.com" });
    expect(status).toBe(500);
    expect(body).toEqual({ error: "Could not look up the account." });
    expect(m.internal).toHaveBeenCalledWith({ message: 'relation "users" does not exist' });
  });

  it("answers 503 before the engagements table exists, and a fixed message on a read failure", async () => {
    m.list.mockResolvedValue({ status: "unavailable" });
    expect((await call()).status).toBe(503);
    m.list.mockResolvedValue({ status: "error", error: { message: "column engagements.owner" } });
    const failed = await call();
    expect(failed.status).toBe(500);
    expect(JSON.stringify(failed.body)).not.toContain("engagements.owner");
  });
});
