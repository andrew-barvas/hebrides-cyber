import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, logAuditEventMock, callerCanActForMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  logAuditEventMock: vi.fn(),
  callerCanActForMock: vi.fn(),
}));

type Result = { data: unknown; error: { code?: string; message: string } | null };
type Op = { table: string; kind: string; payload?: unknown; options?: unknown; filters: Array<[string, string, unknown]> };

let tables: Record<string, Result>;
let writeResult: Result | null;
let ops: Op[];

function builder(table: string) {
  const op: Op = { table, kind: "select", filters: [] };
  ops.push(op);
  const b: Record<string, unknown> = {
    select: () => b,
    eq: (col: string, val: unknown) => (op.filters.push(["eq", col, val]), b),
    in: (col: string, val: unknown) => (op.filters.push(["in", col, val]), b),
    upsert: (payload: unknown, options: unknown) => ((op.kind = "upsert"), (op.payload = payload), (op.options = options), b),
    delete: () => ((op.kind = "delete"), b),
    then: (resolve: (v: unknown) => unknown) => {
      if (op.kind === "upsert") {
        // Echo the written rows back, as .select() after an upsert does.
        const rows = (op.payload as Array<Record<string, unknown>>).map((r) => ({ id: "x", created_at: "2026-09-01T00:00:00.000Z", ...r }));
        return Promise.resolve(writeResult ?? { data: rows, error: null }).then(resolve);
      }
      if (op.kind === "delete") return Promise.resolve(writeResult ?? tables.finding_triage).then(resolve);
      return Promise.resolve(tables[table] ?? { data: [], error: null }).then(resolve);
    },
  };
  return b;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (t: string) => builder(t) },
}));
vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));
vi.mock("@/lib/teamAccess", () => ({ callerCanActFor: callerCanActForMock }));

import handler from "@/pages/api/findings/triage";

const SCAN = "11111111-2222-4333-8444-555555555555";
const OTHER_SCAN = "99999999-2222-4333-8444-555555555555";
const inDays = (n: number) => new Date(Date.now() + n * 86_400_000).toISOString();

// The JSON body each test reads, typed so the assertions compile against
// any node-mocks-http typing (its _getJSONData() is `unknown` in some builds).
type TriageBody = {
  available?: boolean;
  host?: string;
  items: Array<Record<string, unknown> & { checkId: string; active: boolean }>;
  item?: Record<string, unknown>;
  error?: string;
  count?: number;
  deleted?: number;
};
const json = (res: { _getJSONData(): unknown }): TriageBody => res._getJSONData() as TriageBody;

function call(method: RequestMethod, body?: unknown, query: Record<string, string> = {}) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, body: body as Record<string, unknown>, query });
  return handler(req, res).then(() => res);
}

const triageRow = (check_id: string, overrides: Record<string, unknown> = {}) => ({
  id: `id-${check_id}`, owner: "o1", target_host: "shop.example", check_id, state: "accepted_risk", reason: "Agreed",
  expires_at: null, created_by: "o1", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-02T00:00:00Z", ...overrides,
});

const upserts = () => ops.filter((o) => o.kind === "upsert");
const deletes = () => ops.filter((o) => o.kind === "delete");

describe("/api/findings/triage", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "o1", via: "session" });
    logAuditEventMock.mockReset();
    callerCanActForMock.mockReset().mockResolvedValue(false);
    writeResult = null;
    ops = [];
    tables = {
      scans: { data: [{ id: SCAN, owner: "o1", target_url: "https://Shop.Example/checkout" }], error: null },
      users: { data: [{ id: "o1", email: "owner@shop.example" }], error: null },
      finding_triage: { data: [], error: null },
    };
  });

  it("requires authentication and a supported method", async () => {
    expect((await call("POST"))._getStatusCode()).toBe(405);
    authenticateApiRequestMock.mockResolvedValue(null);
    expect((await call("GET"))._getStatusCode()).toBe(401);
  });

  describe("GET", () => {
    it("lists a scan's site triage, flagging expired rows inactive, with who triaged", async () => {
      tables.finding_triage.data = [
        triageRow("a"),
        triageRow("b", { state: "snoozed", expires_at: inDays(-1), updated_at: "2026-09-03T00:00:00Z" }),
      ];
      const res = await call("GET", undefined, { scanId: SCAN });
      expect(res._getStatusCode()).toBe(200);
      const body = json(res);
      expect(body).toMatchObject({ available: true, host: "shop.example" });
      expect(body.items.map((i: { checkId: string; active: boolean }) => [i.checkId, i.active])).toEqual([["b", false], ["a", true]]);
      expect(body.items[1]).toMatchObject({ targetHost: "shop.example", state: "accepted_risk", triagedByEmail: "owner@shop.example" });
      const triageRead = ops.find((o) => o.table === "finding_triage")!;
      expect(triageRead.filters).toEqual([["eq", "owner", "o1"], ["eq", "target_host", "shop.example"]]);
    });

    it("lists by host on the caller's own account, or the whole account", async () => {
      await call("GET", undefined, { host: "https://SHOP.example/" });
      expect(ops.find((o) => o.table === "finding_triage")!.filters).toEqual([["eq", "owner", "o1"], ["eq", "target_host", "shop.example"]]);
      ops = [];
      await call("GET");
      expect(ops.find((o) => o.table === "finding_triage")!.filters).toEqual([["eq", "owner", "o1"]]);
    });

    it("refuses another account's scan unless the caller is on its team", async () => {
      tables.scans.data = [{ id: SCAN, owner: "someone-else", target_url: "https://shop.example" }];
      expect((await call("GET", undefined, { scanId: SCAN }))._getStatusCode()).toBe(403);
      callerCanActForMock.mockResolvedValue(true);
      expect((await call("GET", undefined, { scanId: SCAN }))._getStatusCode()).toBe(200);
      expect(ops.find((o) => o.table === "finding_triage")!.filters).toContainEqual(["eq", "owner", "someone-else"]);
    });

    it("rejects bad parameters", async () => {
      expect((await call("GET", undefined, { scanId: "nope" }))._getStatusCode()).toBe(400);
      expect((await call("GET", undefined, { host: "not a host" }))._getStatusCode()).toBe(400);
      expect((await call("GET", undefined, { host: "a.example", scanId: SCAN }))._getStatusCode()).toBe(400);
      expect((await call("GET", undefined, { scanId: OTHER_SCAN }))._getStatusCode()).toBe(404);
    });

    it("reports unavailable, not an error, before migration 046", async () => {
      tables.finding_triage = { data: null, error: { code: "PGRST205", message: "Could not find the table" } };
      const res = await call("GET", undefined, { host: "shop.example" });
      expect(res._getStatusCode()).toBe(200);
      expect(json(res)).toEqual({ available: false, host: "shop.example", items: [] });
    });
  });

  describe("PUT", () => {
    it("saves one decision against the scan's site, attributed to the caller, and audits it", async () => {
      const res = await call("PUT", { scanId: SCAN, checkId: "headers.csp-absent", state: "accepted_risk", reason: "  Legacy app, WAF in front  " });
      expect(res._getStatusCode()).toBe(200);
      const [op] = upserts();
      expect(op.options).toEqual({ onConflict: "owner,target_host,check_id" });
      expect(op.payload).toEqual([
        expect.objectContaining({
          owner: "o1", target_host: "shop.example", check_id: "headers.csp-absent", state: "accepted_risk",
          reason: "Legacy app, WAF in front", expires_at: null, created_by: "o1",
        }),
      ]);
      expect(json(res).item).toMatchObject({ checkId: "headers.csp-absent", active: true, triagedByEmail: "owner@shop.example" });
      expect(logAuditEventMock).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ action: "finding.triaged", resourceType: "finding", resourceId: "shop.example/headers.csp-absent" })
      );
    });

    it("snoozes until a normalised expiry", async () => {
      const expiresAt = inDays(30);
      const res = await call("PUT", { targetHost: "Shop.Example", checkId: "tls.expiring", state: "snoozed", reason: "Renewal booked", expiresAt });
      expect(res._getStatusCode()).toBe(200);
      expect((upserts()[0].payload as Array<{ expires_at: string }>)[0].expires_at).toBe(expiresAt);
    });

    it.each([
      ["a snooze without an expiry", { state: "snoozed" }, "expiresAt"],
      ["an expiry in the past", { state: "snoozed", expiresAt: inDays(-1) }, "expiresAt"],
      ["an expiry more than a year out", { state: "snoozed", expiresAt: inDays(400) }, "expiresAt"],
      ["a garbage expiry", { state: "accepted_risk", expiresAt: "tomorrow" }, "expiresAt"],
      ["a too-short reason", { reason: "  ok  " }, "reason"],
      ["a too-long reason", { reason: "x".repeat(2001) }, "reason"],
      ["an unknown state", { state: "ignored" }, "state"],
      ["both targetHost and scanId", { scanId: SCAN }, "targetHost"],
      ["neither targetHost nor scanId", { targetHost: undefined }, "targetHost"],
      ["an invalid host", { targetHost: "not a host" }, "targetHost"],
      ["a missing checkId", { checkId: "" }, "checkId"],
    ])("rejects %s", async (_label, override, field) => {
      const res = await call("PUT", { targetHost: "shop.example", checkId: "a.b", state: "accepted_risk", reason: "Because", ...override });
      expect(res._getStatusCode()).toBe(400);
      expect(json(res).error).toMatch(new RegExp(`^${field}`));
      expect(upserts()).toHaveLength(0);
    });

    it("bulk-triages any checkId, last decision winning per finding, in one upsert and one audit event", async () => {
      const items = [
        { targetHost: "shop.example", checkId: "script-inventory.unreviewed:https://cdn.example.net", state: "accepted_risk", reason: "Authorised: payments widget" },
        { targetHost: "shop.example", checkId: "script-inventory.unreviewed:https://cdn.example.net", state: "accepted_risk", reason: "Authorised: payments widget v2" },
        { scanId: SCAN, checkId: "dns.dmarc-missing", state: "false_positive", reason: "Parked domain" },
      ];
      const res = await call("PUT", { items });
      expect(res._getStatusCode()).toBe(200);
      expect(json(res).count).toBe(2);
      const payload = upserts()[0].payload as Array<{ check_id: string; reason: string }>;
      expect(payload.map((r) => [r.check_id, r.reason])).toEqual([
        ["script-inventory.unreviewed:https://cdn.example.net", "Authorised: payments widget v2"],
        ["dns.dmarc-missing", "Parked domain"],
      ]);
      expect(logAuditEventMock).toHaveBeenCalledTimes(1);
      expect(logAuditEventMock.mock.calls[0][1]).toMatchObject({ action: "finding.triaged", resourceId: null, metadata: { count: 2 } });
    });

    it("caps a bulk request, and reports which item is invalid", async () => {
      const item = { targetHost: "shop.example", checkId: "a.b", state: "accepted_risk", reason: "Because" };
      expect((await call("PUT", { items: Array(201).fill(item) }))._getStatusCode()).toBe(400);
      expect((await call("PUT", { items: [] }))._getStatusCode()).toBe(400);
      const res = await call("PUT", { items: [item, { ...item, reason: "" }] });
      expect(json(res).error).toMatch(/^items\.1\.reason/);
      expect(upserts()).toHaveLength(0);
    });

    it("is all-or-nothing when any scan can't be acted on", async () => {
      tables.scans.data = [{ id: SCAN, owner: "someone-else", target_url: "https://shop.example" }];
      const res = await call("PUT", {
        items: [
          { targetHost: "shop.example", checkId: "a.b", state: "accepted_risk", reason: "Mine" },
          { scanId: SCAN, checkId: "c.d", state: "accepted_risk", reason: "Theirs" },
        ],
      });
      expect(res._getStatusCode()).toBe(403);
      expect(upserts()).toHaveLength(0);
    });

    it("lets a team admin/developer triage on the owner's scan, owned by the owner", async () => {
      tables.scans.data = [{ id: SCAN, owner: "owner-2", target_url: "https://shop.example" }];
      callerCanActForMock.mockResolvedValue(true);
      expect((await call("PUT", { scanId: SCAN, checkId: "a.b", state: "false_positive", reason: "Confirmed" }))._getStatusCode()).toBe(200);
      expect((upserts()[0].payload as Array<Record<string, unknown>>)[0]).toMatchObject({ owner: "owner-2", created_by: "o1" });
    });

    it("returns 503 before migration 046", async () => {
      writeResult = { data: null, error: { code: "PGRST205", message: "Could not find the table" } };
      const res = await call("PUT", { targetHost: "shop.example", checkId: "a.b", state: "accepted_risk", reason: "Because" });
      expect(res._getStatusCode()).toBe(503);
      expect(logAuditEventMock).not.toHaveBeenCalled();
    });

    it("returns 500 on any other write failure", async () => {
      writeResult = { data: null, error: { code: "23514", message: "check violation" } };
      expect((await call("PUT", { targetHost: "shop.example", checkId: "a.b", state: "accepted_risk", reason: "Because" }))._getStatusCode()).toBe(500);
    });
  });

  describe("DELETE", () => {
    it("undoes one decision and audits what it was", async () => {
      tables.finding_triage.data = [triageRow("a.b", { state: "snoozed", reason: "Later", expires_at: inDays(3) })];
      const res = await call("DELETE", { scanId: SCAN, checkId: "a.b" });
      expect(res._getStatusCode()).toBe(200);
      expect(json(res)).toEqual({ deleted: 1, items: [{ targetHost: "shop.example", checkId: "a.b" }] });
      expect(deletes()[0].filters).toEqual([["eq", "owner", "o1"], ["eq", "target_host", "shop.example"], ["in", "check_id", ["a.b"]]]);
      expect(logAuditEventMock.mock.calls[0][1]).toMatchObject({
        action: "finding.untriaged",
        resourceId: "shop.example/a.b",
        metadata: { items: [expect.objectContaining({ state: "snoozed", reason: "Later" })] },
      });
    });

    it("accepts query parameters, and is a no-op (no audit) when nothing matched", async () => {
      const res = await call("DELETE", undefined, { host: "shop.example", checkId: "a.b" });
      expect(res._getStatusCode()).toBe(200);
      expect(json(res).deleted).toBe(0);
      expect(logAuditEventMock).not.toHaveBeenCalled();
    });

    it("bulk-deletes with one query per site", async () => {
      await call("DELETE", {
        items: [
          { targetHost: "shop.example", checkId: "a" },
          { scanId: SCAN, checkId: "b" },
          { targetHost: "blog.example", checkId: "c" },
        ],
      });
      expect(deletes().map((d) => d.filters)).toEqual([
        [["eq", "owner", "o1"], ["eq", "target_host", "shop.example"], ["in", "check_id", ["a", "b"]]],
        [["eq", "owner", "o1"], ["eq", "target_host", "blog.example"], ["in", "check_id", ["c"]]],
      ]);
    });

    it("validates and returns 503 before migration 046", async () => {
      expect((await call("DELETE", { checkId: "a.b" }))._getStatusCode()).toBe(400);
      writeResult = { data: null, error: { code: "42P01", message: "relation does not exist" } };
      expect((await call("DELETE", { targetHost: "shop.example", checkId: "a.b" }))._getStatusCode()).toBe(503);
    });
  });
});
