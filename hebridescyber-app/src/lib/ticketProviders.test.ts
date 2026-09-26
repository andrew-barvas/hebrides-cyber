import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  validateServiceNowCredentials,
  validateGitHubIssuesCredentials,
  createGitHubIssue,
  getGitHubIssue,
  createServiceNowIncident,
  getServiceNowIncident,
  addServiceNowComment,
  isServiceNowInstanceUrl,
} from "./ticketProviders";

// The instance URL is customer-supplied and fetched server-side, so this is
// the SSRF boundary for the ServiceNow integration.
describe("isServiceNowInstanceUrl", () => {
  it.each(["https://acme.service-now.com", "https://acme.service-now.com/", "https://dev-12345.service-now.com"])("accepts %s", (url) => {
    expect(isServiceNowInstanceUrl(url)).toBe(true);
  });

  it.each([
    "http://acme.service-now.com", // not https
    "https://169.254.169.254", // cloud metadata
    "https://localhost",
    "https://service-now.com.evil.example",
    "https://evil.example/acme.service-now.com",
    "https://acme.service-now.com.evil.example",
    "https://a.b.service-now.com", // nested subdomain
    "https://acme.service-now.com:8443",
    "https://user:pass@acme.service-now.com",
    "https://acme.service-now.com/api/now/table/sys_user",
    "not a url",
  ])("rejects %s", (url) => {
    expect(isServiceNowInstanceUrl(url)).toBe(false);
  });
});

describe("addServiceNowComment", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("looks up the incident by number, then writes an internal work note", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ result: [{ sys_id: "abc123" }] }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({}) });
    vi.stubGlobal("fetch", fetchMock);

    const result = await addServiceNowComment(
      { instanceUrl: "https://acme.service-now.com", username: "u", password: "p" },
      "INC0012345",
      "Re-detected"
    );

    expect(result).toEqual({ ok: true });
    expect(fetchMock.mock.calls[0][0]).toContain("sysparm_query=number=INC0012345");
    expect(fetchMock.mock.calls[1][0]).toBe("https://acme.service-now.com/api/now/table/incident/abc123");
    expect(fetchMock.mock.calls[1][1].method).toBe("PATCH");
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({ work_notes: "Re-detected" });
  });

  it("reports an incident that no longer exists", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => ({ result: [] }) }));
    const result = await addServiceNowComment({ instanceUrl: "https://acme.service-now.com", username: "u", password: "p" }, "INC0", "x");
    expect(result).toEqual({ ok: false, error: "Incident INC0 not found" });
  });
});

describe("validateGitHubIssuesCredentials — issues disabled", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("refuses a repository with Issues turned off, rather than failing every ticket later", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ has_issues: false }) }));
    const result = await validateGitHubIssuesCredentials({ token: "t", owner: "acme", repo: "webapp" });
    expect(result).toEqual({ ok: false, error: "Issues are turned off for this repository" });
  });
});

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
