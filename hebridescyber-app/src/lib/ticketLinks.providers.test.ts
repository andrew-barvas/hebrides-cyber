import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";

const providers = vi.hoisted(() => ({
  createServiceNowIncident: vi.fn(),
  getServiceNowIncident: vi.fn(),
  addServiceNowComment: vi.fn(),
  closeServiceNowIncident: vi.fn(),
  createGitHubIssue: vi.fn(),
  getGitHubIssue: vi.fn(),
  addGitHubIssueComment: vi.fn(),
  closeGitHubIssue: vi.fn(),
}));
vi.mock("./ticketProviders", () => providers);

import { buildProviderClient, findTicketIntegration, summariseTicketIntegration, TICKET_PROVIDERS, type TicketIntegrationRow } from "./ticketLinks";

const snow: TicketIntegrationRow = {
  provider: "servicenow",
  servicenow_instance_url: "https://acme.service-now.com",
  servicenow_username: "svc-hebrides",
  servicenow_password: "s3cret",
};
const gh: TicketIntegrationRow = { provider: "github", github_owner: "acme", github_repo: "webapp", github_token: "github_pat_x" };

beforeEach(() => {
  for (const fn of Object.values(providers)) fn.mockReset();
});

describe("buildProviderClient — ServiceNow", () => {
  it("routes every operation to the ServiceNow client with the stored config", async () => {
    providers.closeServiceNowIncident.mockResolvedValue({ ok: true });
    const client = buildProviderClient(snow)!;
    expect(client.provider).toBe("servicenow");

    const config = { instanceUrl: "https://acme.service-now.com", username: "svc-hebrides", password: "s3cret" };
    const ticket = { title: "t", body: "b", reportUrl: "https://x" };
    await client.createIssue(ticket);
    await client.getIssue("INC001");
    await client.addComment("INC001", "note");
    expect(await client.closeIssue("INC001")).toEqual({ ok: true, detail: "Resolved" });

    expect(providers.createServiceNowIncident).toHaveBeenCalledWith(config, ticket);
    expect(providers.getServiceNowIncident).toHaveBeenCalledWith(config, "INC001");
    expect(providers.addServiceNowComment).toHaveBeenCalledWith(config, "INC001", "note");
  });

  it("passes a close failure through unchanged", async () => {
    providers.closeServiceNowIncident.mockResolvedValue({ ok: false, error: "nope" });
    expect(await buildProviderClient(snow)!.closeIssue("INC001")).toEqual({ ok: false, error: "nope" });
  });

  it("is null when a credential is missing", () => {
    expect(buildProviderClient({ ...snow, servicenow_password: null })).toBeNull();
  });
});

describe("buildProviderClient — GitHub Issues", () => {
  it("routes every operation to the GitHub client", async () => {
    providers.closeGitHubIssue.mockResolvedValue({ ok: true });
    const client = buildProviderClient(gh)!;
    expect(client.provider).toBe("github");

    const config = { token: "github_pat_x", owner: "acme", repo: "webapp" };
    await client.createIssue({ title: "t", body: "b", reportUrl: "https://x" });
    await client.addComment("42", "note");
    expect(await client.closeIssue("42")).toEqual({ ok: true, detail: "closed as completed" });
    expect(providers.createGitHubIssue).toHaveBeenCalledWith(config, expect.anything());
    expect(providers.addGitHubIssueComment).toHaveBeenCalledWith(config, "42", "note");
  });

  it("is null when the repository is missing", () => {
    expect(buildProviderClient({ ...gh, github_repo: null })).toBeNull();
  });
});

describe("buildProviderClient — non-tracker rows", () => {
  it("returns null for an on-call row that shares the table", () => {
    expect(buildProviderClient({ provider: "pagerduty" } as unknown as TicketIntegrationRow)).toBeNull();
  });
});

describe("summariseTicketIntegration", () => {
  it.each([
    [{ provider: "jira", jira_project_key: "SEC", jira_api_token: "tok" }, "project SEC"],
    [gh, "acme/webapp"],
    [snow, "acme.service-now.com"],
    [{ provider: "linear", linear_api_key: "lin_x", linear_team_id: "uuid" }, null],
  ] as const)("describes %o as %s", (row, destination) => {
    expect(summariseTicketIntegration(row as TicketIntegrationRow).destination).toBe(destination);
  });

  it("never carries a credential", () => {
    for (const row of [snow, gh, { provider: "jira", jira_api_token: "jira-secret", jira_email: "a@b.c" } as TicketIntegrationRow]) {
      const json = JSON.stringify(summariseTicketIntegration(row));
      for (const secret of ["s3cret", "svc-hebrides", "github_pat_x", "jira-secret", "a@b.c"]) expect(json).not.toContain(secret);
    }
  });

  it("reports auto-close as a plain boolean", () => {
    expect(summariseTicketIntegration({ ...gh, auto_close_enabled: null }).autoCloseEnabled).toBe(false);
    expect(summariseTicketIntegration({ ...gh, auto_close_enabled: true }).autoCloseEnabled).toBe(true);
  });
});

describe("findTicketIntegration", () => {
  // Regression: PagerDuty/Opsgenie rows live in the same table, and the
  // "newest row" query used to pick one of those over the actual tracker.
  it("only considers tracker rows, newest first", async () => {
    const calls: Array<[string, unknown[]]> = [];
    const builder: Record<string, unknown> = {};
    for (const m of ["select", "eq", "in", "order", "limit"]) {
      builder[m] = (...args: unknown[]) => {
        calls.push([m, args]);
        return builder;
      };
    }
    builder.maybeSingle = () => Promise.resolve({ data: gh });
    const supabase = { from: () => builder } as unknown as SupabaseClient;

    expect(await findTicketIntegration(supabase, "owner-1")).toEqual(gh);
    expect(calls).toContainEqual(["in", ["provider", [...TICKET_PROVIDERS]]]);
    expect(calls).toContainEqual(["eq", ["owner", "owner-1"]]);
    expect(calls).toContainEqual(["order", ["created_at", { ascending: false }]]);
    expect(TICKET_PROVIDERS).not.toContain("pagerduty");
  });
});
