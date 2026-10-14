import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
}));

// 32 bytes, base64 — a throwaway test key, not a real secret.
const TEST_KEY = Buffer.alloc(32, 7).toString("base64");
let upserts: Array<Record<string, unknown>> = [];

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    delete: () => builder,
    upsert: (row: Record<string, unknown>) => {
      upserts.push(row);
      return next();
    },
    maybeSingle: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

import handler from "@/pages/api/account/target-auth";
import { decryptSecret } from "@/lib/credentialEncryption";

const TARGET_ID = "11111111-1111-1111-1111-111111111111";
const OWNER_ID = "22222222-2222-2222-2222-222222222222";

function mockReqRes(method: RequestMethod, body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method, body });
}

describe("POST/DELETE /api/account/target-auth — E-02 plan gate", () => {
  beforeEach(() => {
    process.env.CREDENTIALS_ENC_KEY = TEST_KEY;
    upserts = [];
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
  });

  it("rejects a POST (new credential) from a non-Agency plan with 403, before writing anything", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID }, error: null }];
    queues.subscriptions = [{ data: { plan: "pro", status: "active" }, error: null }];

    const { req, res } = mockReqRes("POST", { monitoredTargetId: TARGET_ID, authType: "cookie", cookieValue: "abc" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
    expect(JSON.parse(res._getData()).error).toMatch(/Agency/);
  });

  it("rejects a POST from a past-due Agency subscription", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID }, error: null }];
    queues.subscriptions = [{ data: { plan: "agency", status: "past_due" }, error: null }];

    const { req, res } = mockReqRes("POST", { monitoredTargetId: TARGET_ID, authType: "cookie", cookieValue: "abc" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
  });

  it("allows a POST from an Agency plan", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID }, error: null }];
    queues.subscriptions = [{ data: { plan: "agency", status: "active" }, error: null }];
    queues.target_auth_credentials = [{ data: null, error: null }];

    const { req, res } = mockReqRes("POST", { monitoredTargetId: TARGET_ID, authType: "cookie", cookieValue: "abc" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
  });

  it("stores the cookie and the Basic Auth password encrypted, never as plaintext", async () => {
    queues.monitored_targets = [
      { data: { id: TARGET_ID, owner: OWNER_ID }, error: null },
      { data: { id: TARGET_ID, owner: OWNER_ID }, error: null },
    ];
    queues.subscriptions = [
      { data: { plan: "agency", status: "active" }, error: null },
      { data: { plan: "agency", status: "active" }, error: null },
    ];

    const a = mockReqRes("POST", { monitoredTargetId: TARGET_ID, authType: "cookie", cookieValue: "session=hunter2" });
    await handler(a.req, a.res);
    const b = mockReqRes("POST", { monitoredTargetId: TARGET_ID, authType: "basic", username: "svc", password: "s3cret-pw" });
    await handler(b.req, b.res);

    expect(a.res._getStatusCode()).toBe(200);
    expect(b.res._getStatusCode()).toBe(200);
    expect(decryptSecret(upserts[0].cookie_value as string)).toBe("session=hunter2");
    expect(upserts[1].basic_username).toBe("svc");
    expect(decryptSecret(upserts[1].basic_password as string)).toBe("s3cret-pw");
    expect(JSON.stringify(upserts)).not.toMatch(/hunter2|s3cret-pw/);
  });

  it("503s with nothing written when no encryption key is configured", async () => {
    delete process.env.CREDENTIALS_ENC_KEY;
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID }, error: null }];
    queues.subscriptions = [{ data: { plan: "agency", status: "active" }, error: null }];

    const { req, res } = mockReqRes("POST", { monitoredTargetId: TARGET_ID, authType: "cookie", cookieValue: "abc" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(503);
    expect(upserts).toHaveLength(0);
  });

  it("allows DELETE regardless of plan, so a downgraded account can still remove its credential", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID }, error: null }];
    queues.target_auth_credentials = [{ data: null, error: null }];

    const { req, res } = mockReqRes("DELETE", { monitoredTargetId: TARGET_ID });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    // The plan gate only runs on POST — no subscriptions queue entry was
    // even needed for this DELETE to succeed.
  });

  it("still 403s a non-owner regardless of plan (ownership check runs before the gate)", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: "someone-else" }, error: null }];

    const { req, res } = mockReqRes("POST", { monitoredTargetId: TARGET_ID, authType: "cookie", cookieValue: "abc" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
    expect(JSON.parse(res._getData()).error).toBe("Forbidden");
  });
});
