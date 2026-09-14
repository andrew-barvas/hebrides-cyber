import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  validateServiceNowCredentials,
  validateGitHubIssuesCredentials,
  createGitHubIssue,
  getGitHubIssue,
  createServiceNowIncident,
  getServiceNowIncident,
} from "./ticketProviders";

describe("ServiceNow", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.restoreAllMocks(); });

  it("validates credentials with a successful call", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, status: 200 }));
    const result = await validateServiceNowCredentials({
      instanceUrl: "https://dev123.service-now.com",
      username: "admin",
      password: "pass",
    });
    expect(result).toEqual({ ok: true });
  });

  it("rejects invalid credentials", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 401 }));
    const result = await validateServiceNowCredentials({
      instanceUrl: "https://dev123.service-now.com",
      username: "admin",
      password: "wrong",
    });
    expect(result).toEqual({ ok: false, error: "ServiceNow rejected the credentials" });
  });

  it("creates an incident", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ result: { sys_id: "abc123", number: "INC0010001" } }),
    }));
    const result = await createServiceNowIncident(
      { instanceUrl: "https://dev123.service-now.com", username: "admin", password: "pass" },
      { title: "Test", body: "Body", reportUrl: "https://example.com/report" },
    );
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.issueKey).toBe("INC0010001");
  });

  it("gets incident state", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ result: [{ state: "7" }] }),
    }));
    const state = await getServiceNowIncident(
      { instanceUrl: "https://dev123.service-now.com", username: "admin", password: "pass" },
      "INC0010001",
    );
    expect(state.status).toBe("done");
  });
});

describe("GitHub Issues", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn()); });
  afterEach(() => { vi.restoreAllMocks(); });

  it("validates credentials", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, status: 200 }));
    const result = await validateGitHubIssuesCredentials({
      token: "ghp_test",
      owner: "acme",
      repo: "webapp",
    });
    expect(result).toEqual({ ok: true });
  });

  it("rejects missing repo", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 404 }));
    const result = await validateGitHubIssuesCredentials({
      token: "ghp_test",
      owner: "acme",
      repo: "nonexistent",
    });
    expect(result.ok).toBe(false);
  });

  it("creates an issue", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ number: 42, html_url: "https://github.com/acme/webapp/issues/42" }),
    }));
    const result = await createGitHubIssue(
      { token: "ghp_test", owner: "acme", repo: "webapp" },
      { title: "Security: XSS", body: "Details", reportUrl: "https://example.com" },
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.issueKey).toBe("42");
      expect(result.url).toContain("github.com");
    }
  });

  it("reads issue state", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ state: "closed" }),
    }));
    const state = await getGitHubIssue({ token: "ghp_test", owner: "acme", repo: "webapp" }, "42");
    expect(state.status).toBe("done");
  });

  it("handles network errors gracefully", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("timeout")));
    const state = await getGitHubIssue({ token: "ghp_test", owner: "acme", repo: "webapp" }, "42");
    expect(state.status).toBe("unknown");
  });
});
