import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
}));

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    insert: () => builder,
    update: () => builder,
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

import handler from "@/pages/api/account/scheduled-reports";

const OWNER_ID = "55555555-5555-5555-5555-555555555555";

function mockReqRes(method: RequestMethod, body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method, body });
}

describe("GET/POST/PATCH/DELETE /api/account/scheduled-reports", () => {
  beforeEach(() => {
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
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
