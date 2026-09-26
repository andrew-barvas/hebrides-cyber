// The finding -> issue ledger (sql/migrations/016_ticket_links.sql) and the
// provider-agnostic client both the manual "Create ticket" button and the
// automatic close-on-fixed hook drive, so neither has to branch on which
// tracker is connected beyond resolving the client once.
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  addJiraComment,
  addLinearComment,
  closeLinearIssue,
  createJiraIssue,
  createLinearIssue,
  getJiraIssue,
  getLinearIssue,
  transitionJiraIssueToDone,
  type CreateIssueResult,
  type IssueState,
} from "./ticketIntegrations";
import {
  addGitHubIssueComment,
  addServiceNowComment,
  closeGitHubIssue,
  closeServiceNowIncident,
  createGitHubIssue,
  createServiceNowIncident,
  getGitHubIssue,
  getServiceNowIncident,
} from "./ticketProviders";
import { TICKET_PROVIDERS, type TicketProvider } from "./ticketProviderList";

export { TICKET_PROVIDERS, type TicketProvider };

/** The columns every ticket code path selects out of ticket_integrations. */
export type TicketIntegrationRow = {
  provider: TicketProvider;
  jira_base_url?: string | null;
  jira_email?: string | null;
  jira_api_token?: string | null;
  jira_project_key?: string | null;
  linear_api_key?: string | null;
  linear_team_id?: string | null;
  servicenow_instance_url?: string | null;
  servicenow_username?: string | null;
  servicenow_password?: string | null;
  github_token?: string | null;
  github_owner?: string | null;
  github_repo?: string | null;
  auto_close_enabled?: boolean | null;
};

/**
 * The newest tracker integration for an owner, or null. Service-role only —
 * the row includes credentials.
 *
 * Selects `*` rather than naming columns on purpose: columns get added by
 * migrations that are applied by hand (040 added ServiceNow/GitHub), and a
 * named column that doesn't exist yet makes PostgREST reject the whole query
 * — which would break Jira/Linear ticketing in the window between a deploy
 * and its migration. The provider filter matters as much: on-call rows
 * (PagerDuty/Opsgenie, 028) live in the same table.
 */
export async function findTicketIntegration(supabaseAdmin: SupabaseClient, owner: string): Promise<TicketIntegrationRow | null> {
  const { data } = await supabaseAdmin
    .from("ticket_integrations")
    .select("*")
    .eq("owner", owner)
    .in("provider", [...TICKET_PROVIDERS])
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  return (data as TicketIntegrationRow | null) ?? null;
}

/** What the settings UI may show about a connection — never a credential. */
export type TicketIntegrationSummary = {
  provider: TicketProvider;
  /** Where tickets go, e.g. "project SEC", "acme/webapp", "acme.service-now.com". */
  destination: string | null;
  autoCloseEnabled: boolean;
};

export function summariseTicketIntegration(row: TicketIntegrationRow): TicketIntegrationSummary {
  let destination: string | null = null;
  switch (row.provider) {
    case "jira":
      destination = row.jira_project_key ? `project ${row.jira_project_key}` : null;
      break;
    case "servicenow":
      try {
        destination = row.servicenow_instance_url ? new URL(row.servicenow_instance_url).hostname : null;
      } catch {
        destination = null;
      }
      break;
    case "github":
      destination = row.github_owner && row.github_repo ? `${row.github_owner}/${row.github_repo}` : null;
      break;
    case "linear":
      destination = null; // team ids are opaque UUIDs — nothing useful to show
      break;
  }
  return { provider: row.provider, destination, autoCloseEnabled: Boolean(row.auto_close_enabled) };
}

export type TicketLink = {
  id: string;
  provider: TicketProvider;
  target_host: string;
  check_id: string;
  issue_key: string;
  issue_url: string;
  first_seen_at: string;
  last_seen_at: string;
  closed_at: string | null;
};

export const TICKET_LINK_COLUMNS =
  "id, provider, target_host, check_id, issue_key, issue_url, first_seen_at, last_seen_at, closed_at";

/**
 * Lowercased hostname, matching how sql/migrations/016_ticket_links.sql keys
 * rows and how scanReport.ts's findPreviousFindings() matches a previous
 * scan. Falls back to the raw string for a target_url that somehow isn't a
 * URL, so a malformed row still groups with itself rather than throwing.
 */
export function ticketHostOf(targetUrl: string): string {
  try {
    return new URL(targetUrl).hostname.toLowerCase();
  } catch {
    return targetUrl.toLowerCase();
  }
}

// ---- Provider client ---------------------------------------------------------

export type TicketProviderClient = {
  provider: TicketProvider;
  createIssue(ticket: { title: string; body: string; reportUrl: string }): Promise<CreateIssueResult>;
  getIssue(issueKey: string): Promise<IssueState>;
  addComment(issueKey: string, text: string): Promise<{ ok: true } | { ok: false; error: string }>;
  closeIssue(issueKey: string): Promise<{ ok: true; detail: string } | { ok: false; error: string }>;
};

/**
 * Returns null when the stored row is missing the credentials its own
 * provider needs — a half-written integration must not throw at call time
 * deep inside a scan's notification phase.
 */
export function buildProviderClient(integration: TicketIntegrationRow): TicketProviderClient | null {
  switch (integration.provider) {
    case "jira": {
      const { jira_base_url: baseUrl, jira_email: email, jira_api_token: apiToken, jira_project_key: projectKey } = integration;
      if (!baseUrl || !email || !apiToken || !projectKey) return null;
      const creds = { baseUrl, email, apiToken };
      return {
        provider: "jira",
        createIssue: (ticket) => createJiraIssue({ ...creds, projectKey }, ticket),
        getIssue: (issueKey) => getJiraIssue(creds, issueKey),
        addComment: (issueKey, text) => addJiraComment(creds, issueKey, text),
        closeIssue: async (issueKey) => {
          const outcome = await transitionJiraIssueToDone(creds, issueKey);
          return outcome.ok ? { ok: true, detail: outcome.transitionName } : outcome;
        },
      };
    }

    case "linear": {
      const { linear_api_key: apiKey, linear_team_id: teamId } = integration;
      if (!apiKey || !teamId) return null;
      return {
        provider: "linear",
        createIssue: (ticket) => createLinearIssue({ apiKey, teamId }, ticket),
        getIssue: (issueKey) => getLinearIssue(apiKey, issueKey),
        addComment: (issueKey, text) => addLinearComment(apiKey, issueKey, text),
        closeIssue: async (issueKey) => {
          const outcome = await closeLinearIssue(apiKey, issueKey);
          return outcome.ok ? { ok: true, detail: outcome.stateName } : outcome;
        },
      };
    }

    case "servicenow": {
      const { servicenow_instance_url: instanceUrl, servicenow_username: username, servicenow_password: password } = integration;
      if (!instanceUrl || !username || !password) return null;
      const config = { instanceUrl, username, password };
      return {
        provider: "servicenow",
        createIssue: (ticket) => createServiceNowIncident(config, ticket),
        getIssue: (issueKey) => getServiceNowIncident(config, issueKey),
        addComment: (issueKey, text) => addServiceNowComment(config, issueKey, text),
        closeIssue: async (issueKey) => {
          const outcome = await closeServiceNowIncident(config, issueKey);
          return outcome.ok ? { ok: true, detail: "Resolved" } : outcome;
        },
      };
    }

    case "github": {
      const { github_token: token, github_owner: owner, github_repo: repo } = integration;
      if (!token || !owner || !repo) return null;
      const config = { token, owner, repo };
      return {
        provider: "github",
        createIssue: (ticket) => createGitHubIssue(config, ticket),
        getIssue: (issueKey) => getGitHubIssue(config, issueKey),
        addComment: (issueKey, text) => addGitHubIssueComment(config, issueKey, text),
        closeIssue: async (issueKey) => {
          const outcome = await closeGitHubIssue(config, issueKey);
          return outcome.ok ? { ok: true, detail: "closed as completed" } : outcome;
        },
      };
    }

    default:
      // An on-call row (pagerduty/opsgenie) or anything else that isn't an
      // issue tracker — callers should have filtered on TICKET_PROVIDERS.
      return null;
  }
}

// ---- Duplicate detection -----------------------------------------------------

export type TicketAction =
  /** No usable existing ticket — create a new one and record it. */
  | { action: "create"; reason: "no-link" | "regressed" | "deleted-in-tracker" }
  /** A live ticket already covers this finding — comment on it, don't duplicate. */
  | { action: "existing"; issueKey: string; issueUrl: string; alreadyResolved: boolean }
  /** Couldn't determine the issue's state — do nothing at all this run. */
  | { action: "blocked"; error: string };

/**
 * The whole duplicate-detection decision, as a pure function of the ledger
 * row and the issue's live state — no I/O, so every branch below is directly
 * unit-testable rather than only reachable through a mocked Jira.
 *
 * Deliberately consults the tracker rather than trusting the ledger alone:
 * a row pointing at an issue somebody deleted in Jira would otherwise
 * suppress ticketing for a finding that is still live, silently and forever.
 *
 * The "blocked" outcome exists because a transport failure is not evidence
 * of anything. Creating on "can't tell" duplicates a ticket someone may
 * already be working; suppressing on "can't tell" hides a real finding.
 * Doing nothing and retrying next scan is the only safe read of that state.
 */
export function decideTicketAction(link: TicketLink | null, issueState: IssueState | null): TicketAction {
  if (!link) return { action: "create", reason: "no-link" };

  // Previously ticketed and confirmed fixed, now detected again. The old
  // issue stays closed as an accurate record of that earlier fix — a fresh
  // ticket is what makes the regression legible, where reopening the old one
  // would quietly erase the fact that it had ever been resolved.
  if (link.closed_at) return { action: "create", reason: "regressed" };

  if (!issueState) return { action: "blocked", error: "Issue state was not checked" };

  switch (issueState.status) {
    case "missing":
      return { action: "create", reason: "deleted-in-tracker" };
    case "unknown":
      return { action: "blocked", error: issueState.error };
    case "done":
      // Someone resolved it by hand but the finding is still present. Comment
      // on the existing issue rather than opening a second one — overriding a
      // human's explicit close with a duplicate ticket is worse than a nudge
      // on the one they already triaged.
      return { action: "existing", issueKey: link.issue_key, issueUrl: link.issue_url, alreadyResolved: true };
    case "open":
      return { action: "existing", issueKey: link.issue_key, issueUrl: link.issue_url, alreadyResolved: false };
  }
}

// ---- Ledger reads/writes -----------------------------------------------------

export async function findTicketLink(
  supabaseAdmin: SupabaseClient,
  owner: string,
  provider: TicketProvider,
  targetHost: string,
  checkId: string
): Promise<TicketLink | null> {
  const { data } = await supabaseAdmin
    .from("ticket_links")
    .select(TICKET_LINK_COLUMNS)
    .eq("owner", owner)
    .eq("provider", provider)
    .eq("target_host", targetHost)
    .eq("check_id", checkId)
    .maybeSingle();
  return (data as TicketLink | null) ?? null;
}

/** All open (not-yet-closed) links for one host — the input to the auto-close sweep. */
export async function findOpenTicketLinks(
  supabaseAdmin: SupabaseClient,
  owner: string,
  provider: TicketProvider,
  targetHost: string
): Promise<TicketLink[]> {
  const { data } = await supabaseAdmin
    .from("ticket_links")
    .select(TICKET_LINK_COLUMNS)
    .eq("owner", owner)
    .eq("provider", provider)
    .eq("target_host", targetHost)
    .is("closed_at", null);
  return (data as TicketLink[] | null) ?? [];
}

/**
 * Records a newly-created issue against a finding. Upserts on the unique key
 * so the regression path (create a second issue for a check_id whose earlier
 * ticket was closed) overwrites the old row rather than colliding with it —
 * first_seen_at resets because this genuinely is a new occurrence, and
 * closed_at clears for the same reason.
 */
export async function recordTicketLink(
  supabaseAdmin: SupabaseClient,
  entry: { owner: string; provider: TicketProvider; targetHost: string; checkId: string; issueKey: string; issueUrl: string }
): Promise<void> {
  const now = new Date().toISOString();
  await supabaseAdmin.from("ticket_links").upsert(
    {
      owner: entry.owner,
      provider: entry.provider,
      target_host: entry.targetHost,
      check_id: entry.checkId,
      issue_key: entry.issueKey,
      issue_url: entry.issueUrl,
      first_seen_at: now,
      last_seen_at: now,
      closed_at: null,
    },
    { onConflict: "owner,provider,target_host,check_id" }
  );
}

/** Bumps last_seen_at on an existing open link — drives the "open for N days" age in reporting. */
export async function touchTicketLink(supabaseAdmin: SupabaseClient, linkId: string): Promise<void> {
  await supabaseAdmin.from("ticket_links").update({ last_seen_at: new Date().toISOString() }).eq("id", linkId);
}

export async function markTicketLinkClosed(supabaseAdmin: SupabaseClient, linkId: string): Promise<void> {
  await supabaseAdmin.from("ticket_links").update({ closed_at: new Date().toISOString() }).eq("id", linkId);
}
