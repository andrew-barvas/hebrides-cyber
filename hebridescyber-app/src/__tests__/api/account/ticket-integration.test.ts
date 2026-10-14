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
import { decryptSecret, isEncryptedSecret } from "@/lib/credentialEncryption";

// 32 bytes, base64 — a throwaway test key, not a real secret.
const TEST_KEY = Buffer.alloc(32, 7).toString("base64");

function call(method: string, body?: unknown) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "GET", body: body as Record<string, unknown> });
  return handler(req, res).then(() => res);
}

beforeEach(() => {
  process.env.CREDENTIALS_ENC_KEY = TEST_KEY;
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
    const [row, opts] = upsertMock.mock.calls[0] as [Record<string, string>, unknown];
    expect(opts).toEqual({ onConflict: "owner,provider" });
    expect(row).toMatchObject({ owner: "owner-1", provider: "servicenow", servicenow_instance_url: "https://acme.service-now.com", servicenow_username: "svc" });
    // The password is stored encrypted, and round-trips.
    expect(row.servicenow_password).not.toBe("pw");
    expect(isEncryptedSecret(row.servicenow_password)).toBe(true);
    expect(decryptSecret(row.servicenow_password)).toBe("pw");
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
    const [row] = upsertMock.mock.calls[0] as [Record<string, string>];
    expect(row).toMatchObject({ owner: "owner-1", provider: "github", github_owner: "acme", github_repo: "web.app-2" });
    expect(row.github_token).not.toBe("github_pat_x");
    expect(decryptSecret(row.github_token)).toBe("github_pat_x");
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

describe("POST — secrets are never stored in plaintext", () => {
  const bodies = [
    { provider: "jira", baseUrl: "https://acme.atlassian.net", email: "a@acme.test", apiToken: "jira-secret", projectKey: "SEC" },
    { provider: "linear", apiKey: "lin_api_secret", teamId: "team-1" },
    { provider: "servicenow", instanceUrl: "https://acme.service-now.com", username: "svc", password: "sn-secret" },
    { provider: "github", owner: "acme", repo: "webapp", token: "github_pat_secret" },
  ];

  it.each(bodies)("encrypts the $provider credential before saving", async (body) => {
    const res = await call("POST", body);
    expect(res._getStatusCode()).toBe(200);
    const [row] = upsertMock.mock.calls[0] as [Record<string, string>];
    const secretField = { jira: "jira_api_token", linear: "linear_api_key", servicenow: "servicenow_password", github: "github_token" }[body.provider]!;
    expect(isEncryptedSecret(row[secretField])).toBe(true);
    expect(JSON.stringify(row)).not.toMatch(/jira-secret|lin_api_secret|sn-secret|github_pat_secret/);
  });

  it.each(bodies)("refuses a $provider save with 503 when no key is configured, without contacting the tracker", async (body) => {
    delete process.env.CREDENTIALS_ENC_KEY;
    const res = await call("POST", body);
    expect(res._getStatusCode()).toBe(503);
    for (const v of Object.values(validators)) expect(v).not.toHaveBeenCalled();
    expect(upsertMock).not.toHaveBeenCalled();
  });

  it("still lets a customer disconnect or toggle auto-close with no key configured", async () => {
    delete process.env.CREDENTIALS_ENC_KEY;
    integrationRow.current = { provider: "github" };
    expect((await call("DELETE", { provider: "github" }))._getStatusCode()).toBe(200);
    expect((await call("PATCH", { provider: "github", autoCloseEnabled: true }))._getStatusCode()).toBe(200);
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
