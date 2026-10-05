import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, hasSlaAccessMock, logAuditEventMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  hasSlaAccessMock: vi.fn(),
  logAuditEventMock: vi.fn(),
}));

type Result = { data: unknown; error: { code?: string; message: string } | null };
let results: { policy: Result; open: Result; resolved: Result; upsert: Result; triage: Result };
let upserted: { row: Record<string, unknown>; options: unknown } | null;

function builder(table: string) {
  let kind: "open" | "resolved" | null = null;
  const b: Record<string, unknown> = {
    select: () => b,
    eq: () => b,
    is: () => ((kind = "open"), b),
    gte: () => ((kind = "resolved"), b),
    maybeSingle: () => Promise.resolve(results.policy),
    upsert: (row: Record<string, unknown>, options: unknown) => {
      upserted = { row, options };
      return Promise.resolve(results.upsert);
    },
    then: (resolve: (v: unknown) => unknown) =>
      Promise.resolve(table === "finding_triage" ? results.triage : kind === "resolved" ? results.resolved : results.open).then(resolve),
  };
  return b;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (t: string) => builder(t) },
}));
vi.mock("@/lib/slaAlerts", () => ({ hasSlaAccess: hasSlaAccessMock }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));

import handler from "@/pages/api/account/sla";

function call(method: RequestMethod, body?: Record<string, unknown>) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, body });
  return handler(req, res).then(() => res);
}

const daysAgo = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString();
const lifecycle = (id: string, severity: string, firstSeen: number, resolved: number | null = null) => ({
  id, target_host: "shop.example", check_id: `c.${id}`, severity, title: id,
  first_seen_at: daysAgo(firstSeen), last_seen_at: daysAgo(0), resolved_at: resolved === null ? null : daysAgo(resolved),
});

const validPolicy = { days: { critical: 7, high: 14, medium: 60, low: 120 }, warnDays: 2, alertsEnabled: true };

describe("/api/account/sla", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "o1", via: "session" });
    hasSlaAccessMock.mockReset().mockResolvedValue(true);
    logAuditEventMock.mockReset();
    upserted = null;
    results = {
      policy: { data: null, error: null },
      open: { data: [lifecycle("late", "critical", 20), lifecycle("ok", "low", 2)], error: null },
      resolved: { data: [lifecycle("fixed", "high", 40, 30)], error: null },
      upsert: { data: null, error: null },
      triage: { data: [], error: null },
    };
  });

  it("requires authentication", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    expect((await call("GET"))._getStatusCode()).toBe(401);
  });

  it("tells a non-Agency account it has no access, without loading findings", async () => {
    hasSlaAccessMock.mockResolvedValue(false);
    const res = await call("GET");
    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toMatchObject({ access: false, summary: null });
    expect((await call("PUT", validPolicy))._getStatusCode()).toBe(403);
    expect(upserted).toBeNull();
  });

  it("summarises open findings against the default policy, with time-to-fix", async () => {
    const body = (await call("GET"))._getJSONData() as {
      policy: { days: Record<string, number> };
      summary: { open: number; breached: number; items: { id: string }[]; resolved: { high: { count: number } }; truncated: boolean };
    };
    expect(body.policy.days).toEqual({ critical: 15, high: 30, medium: 90, low: 180 });
    expect(body.summary).toMatchObject({ open: 2, breached: 1, truncated: false });
    expect(body.summary.items.map((i) => i.id)).toEqual(["late", "ok"]);
    expect(body.summary.resolved.high.count).toBe(1);
  });

  it("leaves triaged findings out of SLA tracking and counts them", async () => {
    results.triage.data = [{
      id: "t1", owner: "o1", target_host: "shop.example", check_id: "c.late", state: "false_positive", reason: "Scanner hit a WAF page",
      expires_at: null, created_by: "o1", created_at: daysAgo(1), updated_at: daysAgo(1),
    }];
    const body = (await call("GET"))._getJSONData() as { summary: { open: number; breached: number; triaged: number } };
    expect(body.summary).toMatchObject({ open: 1, breached: 0, triaged: 1 });
  });

  it("treats triage as nothing triaged before migration 046", async () => {
    results.triage = { data: null, error: { code: "PGRST205", message: "Could not find the table" } };
    const body = (await call("GET"))._getJSONData() as { summary: { open: number; triaged: number } };
    expect(body.summary).toMatchObject({ open: 2, triaged: 0 });
  });

  it("fails rather than report accepted findings as breaching when triage can't be read", async () => {
    results.triage = { data: null, error: { code: "57014", message: "timeout" } };
    expect((await call("GET"))._getStatusCode()).toBe(500);
  });

  it("applies the account's own targets", async () => {
    results.policy.data = { critical_days: 30, high_days: 30, medium_days: 90, low_days: 180, warn_days: 3, alerts_enabled: true };
    const body = (await call("GET"))._getJSONData() as { summary: { breached: number } };
    expect(body.summary.breached).toBe(0);
  });

  it("reports unavailable, not an error, before migration 043", async () => {
    results.open = { data: null, error: { code: "PGRST205", message: "Could not find the table" } };
    const res = await call("GET");
    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toMatchObject({ access: true, available: false });
  });

  it("saves a valid policy and audits it", async () => {
    const res = await call("PUT", validPolicy);
    expect(res._getStatusCode()).toBe(200);
    expect(upserted?.row).toMatchObject({ owner: "o1", critical_days: 7, high_days: 14, medium_days: 60, low_days: 120, warn_days: 2, alerts_enabled: true });
    expect(upserted?.options).toEqual({ onConflict: "owner" });
    expect(logAuditEventMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "sla_policy.updated" }));
  });

  it.each([
    ["a zero-day target", { ...validPolicy, days: { ...validPolicy.days, critical: 0 } }],
    ["a fractional target", { ...validPolicy, days: { ...validPolicy.days, high: 1.5 } }],
    ["an over-long warning window", { ...validPolicy, warnDays: 45 }],
    ["a missing field", { days: validPolicy.days, warnDays: 3 }],
  ])("rejects %s", async (_label, body) => {
    expect((await call("PUT", body as Record<string, unknown>))._getStatusCode()).toBe(400);
    expect(upserted).toBeNull();
  });

  it("returns 503 when saving before migration 043", async () => {
    results.upsert = { data: null, error: { code: "PGRST205", message: "Could not find the table" } };
    expect((await call("PUT", validPolicy))._getStatusCode()).toBe(503);
  });
});
