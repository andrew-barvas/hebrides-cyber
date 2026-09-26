import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, validators, upsertMock, integrationRow } = vi.hoisted(() => ({
  authMock: vi.fn(),
  validators: {
    validateJiraCredentials: vi.fn(),
    validateLinearCredentials: vi.fn(),
    validateServiceNowCredentials: vi.fn(),
    validateGitHubIssuesCredentials: vi.fn(),
  },
  upsertMock: vi.fn(),
  integrationRow: { current: null as Record<string, unknown> | null },
}));

vi.mock("@/lib/ticketIntegrations", () => ({
  validateJiraCredentials: validators.validateJiraCredentials,
  validateLinearCredentials: validators.validateLinearCredentials,
}));
vi.mock("@/lib/ticketProviders", async (importOriginal) => ({
  // isServiceNowInstanceUrl stays real — it's the SSRF guard under test.
  ...(await importOriginal<typeof import("@/lib/ticketProviders")>()),
  validateServiceNowCredentials: validators.validateServiceNowCredentials,
  validateGitHubIssuesCredentials: validators.validateGitHubIssuesCredentials,
}));

function builder() {
  const b: Record<string, unknown> = {};
  for (const m of ["select", "eq", "in", "order", "limit", "update", "delete"]) b[m] = () => b;
  b.maybeSingle = () => Promise.resolve({ data: integrationRow.current, error: null });
  b.upsert = (row: unknown, opts: unknown) => upsertMock(row, opts);
  b.then = (resolve: (v: unknown) => void) => resolve({ error: null });
  return b;
}
vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authMock,
  supabaseAdmin: { from: () => builder() },
}));

import handler from "@/pages/api/account/ticket-integration";

function call(method: string, body?: unknown) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "GET", body: body as Record<string, unknown> });
  return handler(req, res).then(() => res);
}

beforeEach(() => {
  authMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
  for (const v of Object.values(validators)) v.mockReset().mockResolvedValue({ ok: true });
  upsertMock.mockReset().mockResolvedValue({ error: null });
  integrationRow.current = null;
});

describe("GET /api/account/ticket-integration", () => {
  it("returns a summary with no credentials in it", async () => {
    integrationRow.current = { provider: "github", github_owner: "acme", github_repo: "webapp", github_token: "github_pat_secret", auto_close_enabled: true };
    const res = await call("GET");
    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toEqual({ integration: { provider: "github", destination: "acme/webapp", autoCloseEnabled: true } });
    expect(JSON.stringify(res._getJSONData())).not.toContain("github_pat_secret");
  });

  it("returns null when no tracker is connected", async () => {
    const res = await call("GET");
    expect(res._getJSONData()).toEqual({ integration: null });
  });

  it("refuses API-key callers", async () => {
    authMock.mockResolvedValue({ ownerId: "owner-1", via: "api_key" });
    expect((await call("GET"))._getStatusCode()).toBe(403);
  });
});

describe("POST — ServiceNow", () => {
  const valid = { provider: "servicenow", instanceUrl: "https://acme.service-now.com/", username: "svc", password: "pw" };

  it("validates against the instance, then saves with the trailing slash trimmed", async () => {
    const res = await call("POST", valid);
    expect(res._getStatusCode()).toBe(200);
    expect(validators.validateServiceNowCredentials).toHaveBeenCalledWith({ instanceUrl: "https://acme.service-now.com", username: "svc", password: "pw" });
    expect(upsertMock).toHaveBeenCalledWith(
      { owner: "owner-1", provider: "servicenow", servicenow_instance_url: "https://acme.service-now.com", servicenow_username: "svc", servicenow_password: "pw" },
      { onConflict: "owner,provider" }
    );
  });

  // SSRF: a customer-supplied URL the server fetches must never reach an
  // internal address — rejected at validation, before any request.
  it.each(["https://169.254.169.254/latest/meta-data", "http://acme.service-now.com", "https://intranet.local"])(
    "rejects %s without contacting it",
    async (instanceUrl) => {
      const res = await call("POST", { ...valid, instanceUrl });
      expect(res._getStatusCode()).toBe(400);
      expect(validators.validateServiceNowCredentials).not.toHaveBeenCalled();
      expect(upsertMock).not.toHaveBeenCalled();
    }
  );

  it("does not save credentials ServiceNow rejected", async () => {
    validators.validateServiceNowCredentials.mockResolvedValue({ ok: false, error: "ServiceNow rejected the credentials" });
    const res = await call("POST", valid);
    expect(res._getStatusCode()).toBe(400);
    expect((res._getJSONData() as { error: string }).error).toBe("ServiceNow rejected the credentials");
    expect(upsertMock).not.toHaveBeenCalled();
  });

  it("explains plainly when migration 040 hasn't been applied yet", async () => {
    upsertMock.mockResolvedValue({ error: { code: "PGRST204", message: "Could not find the 'servicenow_instance_url' column" } });
    const res = await call("POST", valid);
    expect(res._getStatusCode()).toBe(503);
    expect((res._getJSONData() as { error: string }).error).toMatch(/isn't enabled on this deployment yet/);
  });
});

describe("POST — GitHub Issues", () => {
  it("validates repository access, then saves", async () => {
    const res = await call("POST", { provider: "github", owner: "acme", repo: "web.app-2", token: "github_pat_x" });
    expect(res._getStatusCode()).toBe(200);
    expect(validators.validateGitHubIssuesCredentials).toHaveBeenCalledWith({ owner: "acme", repo: "web.app-2", token: "github_pat_x" });
    expect(upsertMock).toHaveBeenCalledWith(
      { owner: "owner-1", provider: "github", github_owner: "acme", github_repo: "web.app-2", github_token: "github_pat_x" },
      { onConflict: "owner,provider" }
    );
  });

  // owner/repo are interpolated into API paths.
  it.each([
    { owner: "acme/../x", repo: "webapp" },
    { owner: "acme", repo: "web app" },
    { owner: "-acme", repo: "webapp" },
    { owner: "acme", repo: "../../orgs/x" },
  ])("rejects unsafe names %o", async (names) => {
    const res = await call("POST", { provider: "github", token: "t", ...names });
    expect(res._getStatusCode()).toBe(400);
    expect(validators.validateGitHubIssuesCredentials).not.toHaveBeenCalled();
  });
});

describe("PATCH / DELETE accept the new trackers", () => {
  it("toggles auto-close for GitHub", async () => {
    integrationRow.current = { provider: "github" };
    const res = await call("PATCH", { provider: "github", autoCloseEnabled: true });
    expect(res._getStatusCode()).toBe(200);
  });

  it("disconnects ServiceNow", async () => {
    const res = await call("DELETE", { provider: "servicenow" });
    expect(res._getStatusCode()).toBe(200);
  });

  it("will not touch an on-call row through the ticketing route", async () => {
    const res = await call("DELETE", { provider: "pagerduty" });
    expect(res._getStatusCode()).toBe(400);
  });
});
