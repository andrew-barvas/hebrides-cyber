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
    update: () => builder,
    eq: () => builder,
    maybeSingle: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

import handler from "@/pages/api/account/notification-prefs";

const OWNER_ID = "33333333-3333-3333-3333-333333333333";

function mockReqRes(method: RequestMethod, body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method, body });
}

describe("GET/PATCH /api/account/notification-prefs — E-50/E-51", () => {
  beforeEach(() => {
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
  });

  it("GET returns the stored preferences", async () => {
    queues.subscriptions = [
      { data: { notify_email: false, notify_score_threshold: 70, notify_severity_min: "high" }, error: null },
    ];

    const { req, res } = mockReqRes("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(JSON.parse(res._getData())).toEqual({
      notify_email: false,
      notify_score_threshold: 70,
      notify_severity_min: "high",
    });
  });

  it("GET degrades to defaults (200) rather than 500 when migration 027 hasn't been applied", async () => {
    queues.subscriptions = [{ data: null, error: { code: "42703", message: 'column "notify_email" does not exist' } }];

    const { req, res } = mockReqRes("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(JSON.parse(res._getData())).toEqual({
      notify_email: true,
      notify_score_threshold: null,
      notify_severity_min: null,
    });
  });

  it("GET still returns 500 for a genuine, non-missing-column error", async () => {
    queues.subscriptions = [{ data: null, error: { code: "500", message: "connection refused" } }];

    const { req, res } = mockReqRes("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(500);
  });

  it("PATCH saves the updated preferences", async () => {
    queues.subscriptions = [{ error: null }];

    const { req, res } = mockReqRes("PATCH", { notify_email: false, notify_score_threshold: 50 });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(JSON.parse(res._getData())).toMatchObject({ ok: true, notify_email: false, notify_score_threshold: 50 });
  });

  it("PATCH returns 503 (not 500) when migration 027 hasn't been applied", async () => {
    queues.subscriptions = [{ error: { code: "42703", message: 'column "notify_email" does not exist' } }];

    const { req, res } = mockReqRes("PATCH", { notify_email: false });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(503);
    expect(JSON.parse(res._getData()).error).toMatch(/aren't available/);
  });

  it("PATCH still returns 500 for a genuine, non-missing-column error", async () => {
    queues.subscriptions = [{ error: { code: "500", message: "connection refused" } }];

    const { req, res } = mockReqRes("PATCH", { notify_email: false });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(500);
  });

  it("PATCH rejects an empty body with 400", async () => {
    const { req, res } = mockReqRes("PATCH", {});
    await handler(req, res);

    expect(res._getStatusCode()).toBe(400);
  });

  it("rejects unauthenticated requests with 401", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);

    const { req, res } = mockReqRes("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(401);
  });
});
