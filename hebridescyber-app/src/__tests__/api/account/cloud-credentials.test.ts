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
    upsert: () => next(),
    delete: () => builder,
    eq: () => builder,
    order: () => next(),
    maybeSingle: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

import handler from "@/pages/api/account/cloud-credentials";

const OWNER_ID = "44444444-4444-4444-4444-444444444444";

function mockReqRes(method: RequestMethod, body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method, body });
}

describe("GET/POST/DELETE /api/account/cloud-credentials — E-32", () => {
  beforeEach(() => {
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
  });

  it("GET returns stored credentials", async () => {
    queues.cloud_credentials = [{ data: [{ id: "1", provider: "aws", label: "prod" }], error: null }];

    const { req, res } = mockReqRes("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(JSON.parse(res._getData()).credentials).toHaveLength(1);
  });

  it("GET degrades to an empty list (200) rather than 500 when migration 030 hasn't been applied", async () => {
    queues.cloud_credentials = [{ data: null, error: { code: "42P01", message: 'relation "cloud_credentials" does not exist' } }];

    const { req, res } = mockReqRes("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(JSON.parse(res._getData())).toEqual({ credentials: [] });
  });

  it("GET still returns 500 for a genuine, non-missing-schema error", async () => {
    queues.cloud_credentials = [{ data: null, error: { code: "500", message: "connection refused" } }];

    const { req, res } = mockReqRes("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(500);
  });

  it("rejects writes from a non-session caller (API key) with 403", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: OWNER_ID, via: "key" });

    const { req, res } = mockReqRes("POST", {
      provider: "aws",
      label: "prod",
      credentials: { accessKeyId: "AKIAABCDEFGHIJKLMNOP", secretAccessKey: "secret" },
    });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
  });

  it("rejects a POST from a non-Agency plan with 403", async () => {
    queues.subscriptions = [{ data: { plan: "pro" }, error: null }];
    queues.users = [{ data: { is_admin: false }, error: null }];

    const { req, res } = mockReqRes("POST", {
      provider: "aws",
      label: "prod",
      credentials: { accessKeyId: "AKIAABCDEFGHIJKLMNOP", secretAccessKey: "secret" },
    });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
  });

  it("allows a POST from an Agency plan and upserts the credential", async () => {
    queues.subscriptions = [{ data: { plan: "agency" }, error: null }];
    queues.users = [{ data: { is_admin: false }, error: null }];
    queues.cloud_credentials = [{ error: null }];

    const { req, res } = mockReqRes("POST", {
      provider: "aws",
      label: "prod",
      credentials: { accessKeyId: "AKIAABCDEFGHIJKLMNOP", secretAccessKey: "secret" },
    });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
  });

  it("POST returns 503 (not 500) when migration 030 hasn't been applied", async () => {
    queues.subscriptions = [{ data: { plan: "agency" }, error: null }];
    queues.users = [{ data: { is_admin: false }, error: null }];
    queues.cloud_credentials = [{ error: { code: "42P01", message: "relation does not exist" } }];

    const { req, res } = mockReqRes("POST", {
      provider: "aws",
      label: "prod",
      credentials: { accessKeyId: "AKIAABCDEFGHIJKLMNOP", secretAccessKey: "secret" },
    });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(503);
  });
});
