import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, planGateMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  planGateMock: vi.fn(),
}));

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};
let writes: { op: "insert" | "update"; row: Record<string, unknown> }[] = [];

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    insert: (row: Record<string, unknown>) => {
      writes.push({ op: "insert", row });
      return builder;
    },
    update: (row: Record<string, unknown>) => {
      writes.push({ op: "update", row });
      return builder;
    },
    delete: () => builder,
    eq: () => builder,
    order: () => next(),
    single: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

vi.mock("@/lib/planAccess", () => ({ planGate: planGateMock }));

import handler from "@/pages/api/account/scheduled-reports";

const OWNER_ID = "55555555-5555-5555-5555-555555555555";

function mockReqRes(method: RequestMethod, body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method, body });
}

describe("GET/POST/PATCH/DELETE /api/account/scheduled-reports", () => {
  beforeEach(() => {
    queues = {};
    writes = [];
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
    planGateMock.mockReset().mockResolvedValue("ok");
  });

  it("GET returns stored reports", async () => {
    queues.scheduled_reports = [{ data: [{ id: "1", frequency: "weekly" }], error: null }];

    const { req, res } = mockReqRes("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(JSON.parse(res._getData()).reports).toHaveLength(1);
  });

  it("GET degrades to an empty list (200) rather than 500 when migration 032 hasn't been applied", async () => {
    queues.scheduled_reports = [{ data: null, error: { code: "42P01", message: 'relation "scheduled_reports" does not exist' } }];

    const { req, res } = mockReqRes("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(JSON.parse(res._getData())).toEqual({ reports: [] });
  });

  it("GET still returns 500 for a genuine, non-missing-schema error", async () => {
    queues.scheduled_reports = [{ data: null, error: { code: "500", message: "connection refused" } }];

    const { req, res } = mockReqRes("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(500);
  });

  it("POST creates a scheduled report", async () => {
    queues.scheduled_reports = [{ data: { id: "1" }, error: null }];

    const { req, res } = mockReqRes("POST", {
      frequency: "weekly",
      recipients: ["a@example.com"],
    });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(201);
  });

  it("POST defaults the format to pdf, which the sender now attaches as a real PDF", async () => {
    queues.scheduled_reports = [{ data: { id: "1" }, error: null }];

    const { req, res } = mockReqRes("POST", { frequency: "weekly", recipients: ["a@example.com"] });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(201);
    expect(writes).toEqual([{ op: "insert", row: expect.objectContaining({ format: "pdf", frequency: "weekly", target_url: null }) }]);
  });

  it.each(["pdf", "csv", "json"])("POST stores an explicit %s format as given", async (format) => {
    queues.scheduled_reports = [{ data: { id: "1" }, error: null }];

    const { req, res } = mockReqRes("POST", { frequency: "daily", format, recipients: ["a@example.com"] });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(201);
    expect(writes[0].row.format).toBe(format);
  });

  it("POST and PATCH reject a format the sender can't produce with 400, writing nothing", async () => {
    const { req, res } = mockReqRes("POST", { frequency: "weekly", format: "xlsx", recipients: ["a@example.com"] });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);

    const patch = mockReqRes("PATCH", { id: "11111111-1111-4111-8111-111111111111", format: "html" });
    await handler(patch.req, patch.res);
    expect(patch.res._getStatusCode()).toBe(400);

    expect(writes).toEqual([]);
  });

  it("PATCH can switch an existing report to pdf", async () => {
    queues.scheduled_reports = [{ error: null }];

    const { req, res } = mockReqRes("PATCH", { id: "11111111-1111-4111-8111-111111111111", format: "pdf" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(writes).toEqual([{ op: "update", row: expect.objectContaining({ format: "pdf" }) }]);
  });

  it("POST returns 503 (not 500) when migration 032 hasn't been applied", async () => {
    queues.scheduled_reports = [{ data: null, error: { code: "42P01", message: "relation does not exist" } }];

    const { req, res } = mockReqRes("POST", {
      frequency: "weekly",
      recipients: ["a@example.com"],
    });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(503);
  });

  it("PATCH updates a scheduled report", async () => {
    queues.scheduled_reports = [{ error: null }];

    const { req, res } = mockReqRes("PATCH", { id: "11111111-1111-4111-8111-111111111111", enabled: false });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
  });

  it("DELETE removes a scheduled report", async () => {
    queues.scheduled_reports = [{ error: null }];

    const { req, res } = mockReqRes("DELETE", { id: "11111111-1111-4111-8111-111111111111" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
  });

  describe("plan gate", () => {
    const REPORT_ID = "11111111-1111-4111-8111-111111111111";

    it("checks the paid-plan tier for the caller's account", async () => {
      queues.scheduled_reports = [{ data: { id: "1" }, error: null }];

      const { req, res } = mockReqRes("POST", { frequency: "weekly", recipients: ["a@example.com"] });
      await handler(req, res);

      expect(res._getStatusCode()).toBe(201);
      expect(planGateMock).toHaveBeenCalledWith(expect.anything(), OWNER_ID, "basic");
    });

    it("POST answers 403 plan_required below a paid plan, and writes nothing", async () => {
      planGateMock.mockResolvedValue("denied");

      const { req, res } = mockReqRes("POST", { frequency: "weekly", recipients: ["a@example.com"] });
      await handler(req, res);

      expect(res._getStatusCode()).toBe(403);
      expect(JSON.parse(res._getData())).toEqual({ error: "Scheduled reports are part of the paid plans.", code: "plan_required" });
      expect(writes).toEqual([]);
    });

    it("POST answers 500, not 403, when the plan can't be read, and writes nothing", async () => {
      planGateMock.mockResolvedValue("error");

      const { req, res } = mockReqRes("POST", { frequency: "weekly", recipients: ["a@example.com"] });
      await handler(req, res);

      expect(res._getStatusCode()).toBe(500);
      expect(JSON.parse(res._getData()).error).toMatch(/Could not check your plan/);
      expect(writes).toEqual([]);
    });

    it("PATCH answers 403 for edits and for re-enabling below a paid plan, and writes nothing", async () => {
      planGateMock.mockResolvedValue("denied");

      for (const change of [{ enabled: true }, { frequency: "daily" }, { format: "csv" }, { recipients: ["a@example.com"] }, { enabled: false, format: "pdf" }]) {
        const { req, res } = mockReqRes("PATCH", { id: REPORT_ID, ...change });
        await handler(req, res);
        expect(res._getStatusCode()).toBe(403);
      }
      expect(writes).toEqual([]);
    });

    it("PATCH still lets a lapsed account pause a report, without even checking the plan", async () => {
      planGateMock.mockResolvedValue("denied");
      queues.scheduled_reports = [{ error: null }];

      const { req, res } = mockReqRes("PATCH", { id: REPORT_ID, enabled: false });
      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(planGateMock).not.toHaveBeenCalled();
      expect(writes).toEqual([{ op: "update", row: expect.objectContaining({ enabled: false }) }]);
    });

    it("GET and DELETE never need a paid plan, so a lapsed account can see and clear what it set up", async () => {
      planGateMock.mockResolvedValue("denied");
      queues.scheduled_reports = [{ data: [{ id: "1" }], error: null }, { error: null }];

      const get = mockReqRes("GET");
      await handler(get.req, get.res);
      const del = mockReqRes("DELETE", { id: REPORT_ID });
      await handler(del.req, del.res);

      expect(get.res._getStatusCode()).toBe(200);
      expect(del.res._getStatusCode()).toBe(200);
      expect(planGateMock).not.toHaveBeenCalled();
    });

    it("an invalid body is a 400 before any plan lookup", async () => {
      const { req, res } = mockReqRes("POST", { frequency: "hourly", recipients: [] });
      await handler(req, res);

      expect(res._getStatusCode()).toBe(400);
      expect(planGateMock).not.toHaveBeenCalled();
    });
  });

  it("rejects an unsupported method with 405", async () => {
    const { req, res } = mockReqRes("PUT");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(405);
  });

  it("rejects unauthenticated requests with 401", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);

    const { req, res } = mockReqRes("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(401);
  });
});
