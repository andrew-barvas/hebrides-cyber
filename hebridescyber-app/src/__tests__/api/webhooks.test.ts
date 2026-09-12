import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, resolve4Mock, resolve6Mock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  resolve4Mock: vi.fn(),
  resolve6Mock: vi.fn(),
}));

// See src/lib/webhooks.test.ts for why this exact shape (static factory +
// `default` export) is required for the mock to actually intercept the
// node:dns/promises instance src/lib/ownership.ts imports.
vi.mock("node:dns/promises", () => {
  const exports = { resolve4: resolve4Mock, resolve6: resolve6Mock };
  return { ...exports, default: exports };
});

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    order: () => builder,
    insert: () => builder,
    delete: () => builder,
    single: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

vi.mock("@/lib/audit", () => ({
  logAuditEvent: vi.fn().mockResolvedValue(undefined),
}));

import handler from "@/pages/api/webhooks";

const OWNER_ID = "33333333-3333-3333-3333-333333333333";

function mockReqRes(method: RequestMethod, body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method, body });
}

describe("POST /api/webhooks", () => {
  beforeEach(() => {
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
    resolve4Mock.mockReset();
    resolve6Mock.mockReset();
  });

  it("rejects a non-https URL", async () => {
    const { req, res } = mockReqRes("POST", { url: "http://example.com/hook" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  // Regression guard: the real SSRF fix. A webhook URL here is genuinely
  // arbitrary owner-controlled infrastructure (unlike the Slack/Teams
  // vendor fields), so the check is validateNoSsrf's private-IP/
  // metadata-endpoint block rather than a fixed allowlist.
  it("rejects a URL that resolves to a private IP", async () => {
    resolve4Mock.mockResolvedValue(["10.0.0.5"]);
    resolve6Mock.mockRejectedValue(new Error("ENODATA"));
    const { req, res } = mockReqRes("POST", { url: "https://internal.example.com/hook" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("rejects a bare metadata-endpoint IP with no DNS lookup needed", async () => {
    const { req, res } = mockReqRes("POST", { url: "https://169.254.169.254/latest/meta-data/" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
    expect(resolve4Mock).not.toHaveBeenCalled();
  });

  it("creates a webhook for a URL that resolves to a public address", async () => {
    resolve4Mock.mockResolvedValue(["93.184.216.34"]);
    resolve6Mock.mockRejectedValue(new Error("ENODATA"));
    queues.webhooks = [
      { data: [], error: null }, // the >=20 existing-webhooks count check
      { data: { id: "wh-1", name: null, url: "https://example.com/hook", created_at: "2026-01-01T00:00:00Z" }, error: null }, // the insert().select().single()
    ];
    const { req, res } = mockReqRes("POST", { url: "https://example.com/hook" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(201);
  });

  it("rejects an unsupported HTTP method", async () => {
    const { req, res } = mockReqRes("PATCH");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });
});
