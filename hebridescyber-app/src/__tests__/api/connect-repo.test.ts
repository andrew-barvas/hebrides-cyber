import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, resolveGithubAuthMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  resolveGithubAuthMock: vi.fn(),
}));

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};
// The owner's monitored sites, read on every POST (migration 077).
const SITES = { data: [{ target_url: "https://www.example.com" }, { target_url: "https://shop.example.org" }], error: null };
let upserted: Record<string, unknown> | null = null;

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? (table === "monitored_targets" ? SITES : { data: null, error: null }));
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    delete: () => builder,
    upsert: (row: Record<string, unknown>) => {
      upserted = row;
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

vi.mock("@/lib/githubApp", () => ({
  resolveGithubAuth: resolveGithubAuthMock,
}));

import handler from "@/pages/api/account/connect-repo";

const OWNER_ID = "22222222-2222-2222-2222-222222222222";

function mockReqRes(method: RequestMethod, body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method, body });
}

describe("POST/DELETE /api/account/connect-repo — E-02 plan gate", () => {
  beforeEach(() => {
    queues = {};
    upserted = null;
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
    resolveGithubAuthMock.mockReset();
  });

  it("rejects connecting a repo from a Basic plan with 403, before ever calling GitHub", async () => {
    queues.subscriptions = [{ data: { plan: "basic", status: "active" }, error: null }];

    const { req, res } = mockReqRes("POST", { githubRepo: "owner/repo", targetUrl: "https://www.example.com" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
    expect(JSON.parse(res._getData()).error).toMatch(/Pro-and-up/);
    expect(resolveGithubAuthMock).not.toHaveBeenCalled();
  });

  it.each(["cancelled", "past_due"])("rejects a Pro plan whose subscription is %s", async (status) => {
    queues.subscriptions = [{ data: { plan: "pro", status }, error: null }];

    const { req, res } = mockReqRes("POST", { githubRepo: "owner/repo", targetUrl: "https://www.example.com" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
    expect(resolveGithubAuthMock).not.toHaveBeenCalled();
  });

  it("answers 500 when the plan can't be read, and lets an admin through without a subscription", async () => {
    queues.subscriptions = [{ data: null, error: { message: "db down" } }];
    const failed = mockReqRes("POST", { githubRepo: "owner/repo", targetUrl: "https://www.example.com" });
    await handler(failed.req, failed.res);
    expect(failed.res._getStatusCode()).toBe(500);

    queues.users = [{ data: { is_admin: true }, error: null }];
    resolveGithubAuthMock.mockResolvedValue({ token: null });
    const admin = mockReqRes("POST", { githubRepo: "owner/repo", targetUrl: "https://www.example.com" });
    await handler(admin.req, admin.res);
    expect(admin.res._getStatusCode()).not.toBe(403);
    expect(resolveGithubAuthMock).toHaveBeenCalled();
  });

  it.each(["pro", "agency"])("allows connecting a repo from a %s plan", async (plan) => {
    queues.subscriptions = [{ data: { plan, status: "active" }, error: null }];
    resolveGithubAuthMock.mockResolvedValue({ token: "gh-token", via: "app" });
    global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    queues.repo_connections = [{ data: null, error: null }];

    const { req, res } = mockReqRes("POST", { githubRepo: "owner/repo", targetUrl: "https://www.example.com" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
  });

  it("links the repository to the chosen site, matching www and bare hosts", async () => {
    queues.subscriptions = [{ data: { plan: "pro", status: "active" }, error: null }];
    resolveGithubAuthMock.mockResolvedValue({ token: "gh-token", via: "app" });
    global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });

    const { req, res } = mockReqRes("POST", { githubRepo: "owner/repo", targetUrl: "example.com" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(upserted).toMatchObject({ owner: OWNER_ID, github_repo: "owner/repo", target_host: "www.example.com" });
  });

  it.each([[undefined], ["not a host"], ["https://someone-else.com"]])("refuses to connect without one of the owner's sites (%s)", async (targetUrl) => {
    const { req, res } = mockReqRes("POST", { githubRepo: "owner/repo", ...(targetUrl ? { targetUrl } : {}) });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(400);
    expect(upserted).toBeNull();
    expect(resolveGithubAuthMock).not.toHaveBeenCalled();
  });

  it("allows DELETE regardless of plan, so a downgraded account can still disconnect", async () => {
    queues.repo_connections = [{ data: null, error: null }];

    const { req, res } = mockReqRes("DELETE", { githubRepo: "owner/repo" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(resolveGithubAuthMock).not.toHaveBeenCalled();
  });
});
