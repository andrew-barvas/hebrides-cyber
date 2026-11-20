import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { rateMock, auditMock, sendEmailMock, tables, updates, eqCalls, readError } = vi.hoisted(() => ({
  readError: { current: null as unknown },
  eqCalls: [] as Array<[string, string, unknown]>,
  rateMock: vi.fn(),
  auditMock: vi.fn(),
  sendEmailMock: vi.fn(),
  tables: {} as Record<string, { single?: unknown; list?: unknown[] }>,
  updates: [] as Array<{ table: string; row: unknown }>,
}));

function builder(table: string) {
  const q: Record<string, unknown> = {};
  for (const m of ["select", "order", "limit", "in", "is"]) q[m] = () => q;
  q.eq = (column: string, value: unknown) => {
    eqCalls.push([table, column, value]);
    return q;
  };
  q.maybeSingle = async () => ({ data: tables[table]?.single ?? null, error: table === "fix_plans" ? readError.current : null });
  q.update = (row: unknown) => {
    updates.push({ table, row });
    return q;
  };
  q.then = (r: (v: unknown) => void) => r({ data: tables[table]?.list ?? [], error: null });
  return q;
}

vi.mock("@/lib/supabaseAdmin", () => ({ supabaseAdmin: { from: (t: string) => builder(t) } }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: rateMock, getClientIp: () => "203.0.113.9" }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: auditMock }));
vi.mock("@/lib/email", async (orig) => ({ ...(await orig<typeof import("@/lib/email")>()), sendEmail: sendEmailMock }));

import viewHandler from "@/pages/api/plans/[token]";
import doneHandler from "@/pages/api/plans/[token]/done";
import { hashPlanToken } from "@/lib/fixPlans";

const TOKEN = "A".repeat(43);
const plan = { id: "p1", owner: "o1", target_host: "shop.example.com", title: "Go-live", created_at: "2026-11-01T00:00:00Z", expires_at: "2099-01-01T00:00:00Z", revoked_at: null };
const items = [
  { check_id: "headers.hsts", position: 1, severity: "medium", title: "Missing HSTS", remediation: "Add the header.", client_done_at: null, client_note: "" },
  { check_id: "tls.old", position: 2, severity: "high", title: "Old TLS", remediation: "", client_done_at: null, client_note: "" },
];

async function view(token: string) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query: { token } });
  await viewHandler(req, res);
  return res;
}
async function done(token: string, body: unknown) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "POST", query: { token }, body: body as never });
  await doneHandler(req, res);
  return res;
}

describe("shared fix plan link", () => {
  beforeEach(() => {
    rateMock.mockReset().mockResolvedValue({ allowed: true });
    auditMock.mockReset();
    sendEmailMock.mockReset().mockResolvedValue({ ok: true });
    updates.length = 0;
    eqCalls.length = 0;
    readError.current = null;
    for (const k of Object.keys(tables)) delete tables[k];
    tables.fix_plans = { single: plan };
    tables.fix_plan_items = { list: items };
    tables.finding_lifecycle = { list: [{ check_id: "tls.old", resolved_at: "2026-11-10T00:00:00Z" }] };
    tables.users = { single: { email: "owner@example.com" } };
  });

  it("shows the plan with statuses, uncached and unindexed, and nothing about the owner", async () => {
    const res = await view(TOKEN);
    expect(res._getStatusCode()).toBe(200);
    const body = res._getJSONData() as { title: string; items: Array<{ checkId: string; status: string }>; progress: unknown };
    expect(body.title).toBe("Go-live");
    expect(body.items.map((i) => [i.checkId, i.status])).toEqual([
      ["headers.hsts", "open"],
      ["tls.old", "fixed"],
    ]);
    expect(JSON.stringify(body)).not.toContain("o1");
    expect(res.getHeader("Cache-Control")).toBe("private, no-store");
    expect(res.getHeader("X-Robots-Tag")).toBe("noindex");
  });

  it("answers the same 404 for a malformed, unknown, revoked or expired link", async () => {
    const malformed = await view("short");
    expect(malformed._getStatusCode()).toBe(404);
    const message = (malformed._getJSONData() as { error: string }).error;
    tables.fix_plans = { single: null };
    expect((await view(TOKEN))._getJSONData()).toEqual({ error: message });
    tables.fix_plans = { single: { ...plan, revoked_at: "2026-11-02T00:00:00Z" } };
    expect((await view(TOKEN))._getJSONData()).toEqual({ error: message });
    tables.fix_plans = { single: { ...plan, expires_at: "2026-01-01T00:00:00Z" } };
    expect((await view(TOKEN))._getStatusCode()).toBe(404);
  });

  it("rate-limits per IP", async () => {
    rateMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 60 });
    expect((await view(TOKEN))._getStatusCode()).toBe(429);
    expect((await done(TOKEN, { checkId: "headers.hsts", done: true }))._getStatusCode()).toBe(429);
  });

  it("marks an item done with a note, audits it under the owner, and emails the owner once", async () => {
    const res = await done(TOKEN, { checkId: "headers.hsts", done: true, note: "Added it in Cloudflare" });
    expect(res._getStatusCode()).toBe(200);
    expect(updates[0]).toMatchObject({ table: "fix_plan_items", row: { client_note: "Added it in Cloudflare" } });
    expect(auditMock.mock.calls[0][1]).toMatchObject({ actorId: "o1", action: "fix_plan.item_marked_done" });
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    expect(sendEmailMock.mock.calls[0][0].to).toBe("owner@example.com");
    expect(sendEmailMock.mock.calls[0][0].html).toContain("Added it in Cloudflare");
  });

  it("can undo, without emailing, and refuses items not in the plan", async () => {
    tables.fix_plan_items = { list: [{ ...items[0], client_done_at: "2026-11-05T00:00:00Z" }, items[1]] };
    const res = await done(TOKEN, { checkId: "headers.hsts", done: false });
    expect(res._getStatusCode()).toBe(200);
    expect(updates[0].row).toEqual({ client_done_at: null, client_note: "" });
    expect(sendEmailMock).not.toHaveBeenCalled();
    expect((await done(TOKEN, { checkId: "other", done: true }))._getStatusCode()).toBe(404);
  });

  it("looks the plan up by the token's hash, never the token itself", async () => {
    await view(TOKEN);
    expect(eqCalls).toContainEqual(["fix_plans", "token_hash", hashPlanToken(TOKEN)]);
    expect(eqCalls.some(([, , value]) => value === TOKEN)).toBe(false);
  });

  it("refuses other methods, a malformed body, and answers 500 when the plan can't be read", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const get = createMocks<NextApiRequest, NextApiResponse>({ method: "POST", query: { token: TOKEN } });
    await viewHandler(get.req, get.res);
    expect(get.res._getStatusCode()).toBe(405);
    const put = createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query: { token: TOKEN } });
    await doneHandler(put.req, put.res);
    expect(put.res._getStatusCode()).toBe(405);
    expect((await done(TOKEN, { checkId: "headers.hsts" }))._getStatusCode()).toBe(400);
    readError.current = { message: "db down" };
    expect((await view(TOKEN))._getStatusCode()).toBe(500);
    expect((await done(TOKEN, { checkId: "headers.hsts", done: true }))._getStatusCode()).toBe(500);
    spy.mockRestore();
  });
});
