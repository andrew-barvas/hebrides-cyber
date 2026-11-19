import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, logAuditEventMock, sendEmailMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  logAuditEventMock: vi.fn(),
  sendEmailMock: vi.fn(),
}));

const OWNER = "11111111-1111-4111-8111-111111111111";
const MEMBER = "22222222-2222-4222-8222-222222222222";
const OUTSIDER = "33333333-3333-4333-8333-333333333333";

type Result = { data: unknown; error: unknown };
let assignmentsError: unknown = null;
let upserted: unknown[] | null = null;
let deleted: Array<Record<string, unknown>> = [];

function builder(table: string) {
  const filters: Record<string, unknown> = {};
  let mode: "select" | "delete" = "select";
  const result = (): Result => {
    if (table === "teams") return { data: { id: "team-1" }, error: null };
    if (table === "team_members") return { data: [{ user_id: MEMBER, role: "developer" }], error: null };
    if (table === "users") return { data: [{ id: OWNER, email: "owner@example.com" }, { id: MEMBER, email: "dev@example.com" }], error: null };
    if (table === "finding_assignments") {
      if (mode === "delete") deleted.push({ ...filters });
      return { data: [], error: assignmentsError };
    }
    return { data: null, error: null };
  };
  const b: Record<string, unknown> = {
    select: () => b,
    eq: (col: string, val: unknown) => {
      filters[col] = val;
      return b;
    },
    in: () => b,
    limit: () => b,
    delete: () => {
      mode = "delete";
      return b;
    },
    upsert: (rows: unknown[]) => {
      upserted = rows;
      return Promise.resolve({ data: null, error: assignmentsError });
    },
    maybeSingle: () => Promise.resolve(result()),
    then: (resolve: (v: Result) => void) => Promise.resolve(result()).then(resolve),
  };
  return b;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (t: string) => builder(t) },
}));
vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));
vi.mock("@/lib/email", async (orig) => ({ ...(await orig<typeof import("@/lib/email")>()), sendEmail: sendEmailMock }));

import handler from "@/pages/api/findings/assign";

function call(method: RequestMethod, body?: unknown) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, body: body as Record<string, unknown> });
  return handler(req, res).then(() => ({ status: res._getStatusCode(), body: JSON.parse(res._getData() || "{}") as Record<string, unknown> }));
}

const ITEMS = [
  { targetHost: "www.example.com", checkId: "headers.hsts" },
  { targetHost: "https://WWW.example.com/", checkId: "headers.hsts" },
  { targetHost: "shop.example.com", checkId: "dns.spf" },
];

describe("/api/findings/assign", () => {
  beforeEach(() => {
    assignmentsError = null;
    upserted = null;
    deleted = [];
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER, via: "session" });
    logAuditEventMock.mockReset();
    sendEmailMock.mockReset().mockResolvedValue({ ok: true });
  });

  it("needs a caller", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    expect((await call("GET")).status).toBe(401);
  });

  it("lists the owner first, then team members", async () => {
    const { status, body } = await call("GET");
    expect(status).toBe(200);
    expect(body).toEqual({
      available: true,
      assignees: [
        { id: OWNER, email: "owner@example.com", role: "owner" },
        { id: MEMBER, email: "dev@example.com", role: "developer" },
      ],
    });
  });

  it("assigns to a team member once per finding, audits it and emails them", async () => {
    const { status, body } = await call("PUT", { items: ITEMS, titles: ["Missing HSTS", "Missing HSTS", "No SPF"], assigneeId: MEMBER });
    expect(status).toBe(200);
    expect(body.count).toBe(2);
    expect(upserted).toEqual([
      expect.objectContaining({ owner: OWNER, target_host: "www.example.com", check_id: "headers.hsts", assignee: MEMBER, assigned_by: OWNER }),
      expect.objectContaining({ owner: OWNER, target_host: "shop.example.com", check_id: "dns.spf", assignee: MEMBER }),
    ]);
    expect(logAuditEventMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "finding.assigned" }));
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    const email = sendEmailMock.mock.calls[0][0] as { to: string; subject: string; html: string };
    expect(email.to).toBe("dev@example.com");
    expect(email.subject).toBe("2 security findings assigned to you");
    expect(email.html).toContain("No SPF");
  });

  it("doesn't email the owner about their own assignment", async () => {
    expect((await call("PUT", { items: ITEMS.slice(0, 1), assigneeId: OWNER })).status).toBe(200);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("refuses anyone outside the account", async () => {
    const { status } = await call("PUT", { items: ITEMS, assigneeId: OUTSIDER });
    expect(status).toBe(400);
    expect(upserted).toBeNull();
  });

  it("unassigns with assigneeId null", async () => {
    const { status, body } = await call("PUT", { items: ITEMS, assigneeId: null });
    expect(status).toBe(200);
    expect(body).toEqual({ count: 2, assignee: null });
    expect(deleted).toEqual([
      { owner: OWNER, target_host: "www.example.com", check_id: "headers.hsts" },
      { owner: OWNER, target_host: "shop.example.com", check_id: "dns.spf" },
    ]);
    expect(logAuditEventMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "finding.unassigned" }));
  });

  it("rejects a bad host or an empty list", async () => {
    expect((await call("PUT", { items: [{ targetHost: "not a host!", checkId: "x" }], assigneeId: MEMBER })).status).toBe(400);
    expect((await call("PUT", { items: [], assigneeId: MEMBER })).status).toBe(400);
  });

  it("answers 503 before migration 078 and hides the feature on GET", async () => {
    assignmentsError = { code: "42P01", message: 'relation "finding_assignments" does not exist' };
    expect((await call("PUT", { items: ITEMS, assigneeId: MEMBER })).status).toBe(503);
    expect((await call("GET")).body.available).toBe(false);
  });
});
