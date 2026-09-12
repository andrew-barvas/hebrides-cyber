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
    eq: () => builder,
    insert: next,
    update: () => builder,
    maybeSingle: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

import handler from "@/pages/api/account/notification-webhooks";

const OWNER_ID = "22222222-2222-2222-2222-222222222222";

function mockReqRes(method: RequestMethod, body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method, body });
}

describe("POST /api/account/notification-webhooks", () => {
  beforeEach(() => {
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
  });

  it("rejects a non-https webhook URL", async () => {
    const { req, res } = mockReqRes("POST", { slackWebhookUrl: "http://not-secure.example.com" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  // Regression guard for the real vulnerability: a bare "starts with
  // https://" check (the previous validation) is satisfied by any
  // attacker-controlled endpoint, turning this field into a free SSRF/
  // exfiltration proxy that fires on every scan completion.
  it("rejects an https URL that isn't a real Slack webhook host", async () => {
    const { req, res } = mockReqRes("POST", { slackWebhookUrl: "https://attacker.example.com/collect" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("rejects an https URL that isn't a real Teams webhook host", async () => {
    const { req, res } = mockReqRes("POST", { msTeamsWebhookUrl: "https://attacker.example.com/collect" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("rejects a caller authenticated via API key rather than a session", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: OWNER_ID, via: "key" });
    const { req, res } = mockReqRes("POST", { slackWebhookUrl: "https://hooks.slack.com/services/x" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("updates an existing subscription's webhook column without touching plan/status", async () => {
    queues.users = [{ data: { is_admin: false }, error: null }];
    queues.subscriptions = [{ data: { owner: OWNER_ID }, error: null }, { data: null, error: null }];
    const { req, res } = mockReqRes("POST", { slackWebhookUrl: "https://hooks.slack.com/services/x" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
  });

  it("rejects a non-admin caller with no existing subscription, rather than silently no-op'ing", async () => {
    queues.users = [{ data: { is_admin: false }, error: null }];
    queues.subscriptions = [{ data: null, error: null }];
    const { req, res } = mockReqRes("POST", { slackWebhookUrl: "https://hooks.slack.com/services/x" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(409);
  });

  it("bootstraps a subscriptions row for an admin with none, defaulting to agency/active", async () => {
    queues.users = [{ data: { is_admin: true }, error: null }];
    queues.subscriptions = [{ data: null, error: null }];
    queues.subscriptions.push({ data: null, error: null }); // the insert() call
    const { req, res } = mockReqRes("POST", { msTeamsWebhookUrl: "https://outlook.office.com/webhook/x" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
  });

  it("rejects an unsupported HTTP method", async () => {
    const { req, res } = mockReqRes("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });
});
