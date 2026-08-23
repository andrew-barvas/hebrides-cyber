// The finding -> issue ledger (sql/migrations/016_ticket_links.sql) and the
// provider-agnostic client both the manual "Create ticket" button and the
// automatic close-on-fixed hook drive, so neither has to branch on
// jira-vs-linear beyond resolving the client once.
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

export type TicketProvider = "jira" | "linear";

/** The columns every ticket code path selects out of ticket_integrations. */
export type TicketIntegrationRow = {
  provider: TicketProvider;
  jira_base_url?: string | null;
  jira_email?: string | null;
  jira_api_token?: string | null;
  jira_project_key?: string | null;
  linear_api_key?: string | null;
  linear_team_id?: string | null;
  auto_close_enabled?: boolean | null;
};

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
  if (integration.provider === "jira") {
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
