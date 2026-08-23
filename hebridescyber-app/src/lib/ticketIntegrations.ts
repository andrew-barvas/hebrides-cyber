// Jira Cloud / Linear ticket creation from a single finding — the
// complementary "send this to where my team actually tracks work" channel
// alongside the existing AI-tailored fix (src/lib/aiRemediation.ts) and
// automated remediation PR (src/pages/api/generate-fix-pr.ts) options on the
// same finding. Deliberately doesn't duplicate either: it reuses whatever
// remediation text the finding already carries (or an AI-tailored one, if
// the caller has one) as the ticket body, rather than generating new prose.
//
// Two independent providers, each with its own credential shape — see
// sql/migrations/013_ticket_integrations.sql for why these live in their own
// table rather than as subscriptions columns. Both validate*() functions
// make one real, read-only API call before src/pages/api/account/
// ticket-integration.ts ever writes a row, same "verify access before
// saving" precedent as connect-repo.ts.

const REQUEST_TIMEOUT_MS = 10_000;

/**
 * Both providers return the created issue's own identifier alongside its
 * URL — Jira's issue key ("SEC-123"), Linear's issue id (a uuid, which is
 * what its GraphQL API addresses issues by; the human-facing "ENG-42"
 * identifier is not an API handle). The URL alone isn't enough: every
 * follow-up call (does this still exist, comment on it, close it) needs the
 * identifier, and it's what sql/migrations/016_ticket_links.sql stores.
 */
export type CreateIssueResult =
  | { ok: true; url: string; issueKey: string }
  | { ok: false; error: string };

/**
 * State of an already-created issue, as far as we can tell.
 *
 * "unknown" is a distinct outcome from "missing" on purpose, and callers
 * must treat it as "do nothing": a network blip or an expired token means
 * we cannot tell whether the issue is still there, and guessing wrong in
 * either direction is harmful — guess "missing" and we open a duplicate of
 * a ticket someone is already working on, guess "open" and we suppress a
 * ticket for a live finding. Only a real 404 is evidence of deletion.
 */
export type IssueState =
  | { status: "open" }
  | { status: "done" }
  | { status: "missing" }
  | { status: "unknown"; error: string };

// ---- Jira Cloud -------------------------------------------------------------

export type JiraConfig = {
  baseUrl: string; // e.g. "https://yourteam.atlassian.net"
  email: string;
  apiToken: string;
  projectKey: string;
};

function jiraAuthHeader(email: string, apiToken: string): string {
  return `Basic ${Buffer.from(`${email}:${apiToken}`).toString("base64")}`;
}

/** One real, read-only call (GET /myself) — confirms the base URL and credentials actually work before anything is saved. */
export async function validateJiraCredentials(config: Pick<JiraConfig, "baseUrl" | "email" | "apiToken">): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const res = await fetch(`${config.baseUrl.replace(/\/$/, "")}/rest/api/3/myself`, {
      headers: { Authorization: jiraAuthHeader(config.email, config.apiToken), Accept: "application/json" },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (res.status === 401 || res.status === 403) return { ok: false, error: "Jira rejected the email/API token" };
    if (!res.ok) return { ok: false, error: `Jira returned HTTP ${res.status}` };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `Could not reach Jira: ${(err as Error).message}` };
  }
}

/**
 * Splits markdown-lite remediation text into Atlassian Document Format
 * paragraphs. Not a full markdown->ADF converter — code fences/bold/lists
 * become plain paragraphs rather than their own ADF node types. That's a
 * deliberate scope cut: the ticket is meant to carry the same information a
 * human would act on, not pixel-perfect formatting, and a partial converter
 * that mishandles an edge case would be worse than a plain but complete one.
 */
function markdownToAdf(markdown: string) {
  const paragraphs = markdown
    .split(/\n{2,}/)
    .map((p) => p.trim())
    .filter(Boolean);

  return {
    type: "doc",
    version: 1,
    content: paragraphs.map((p) => ({
      type: "paragraph",
      content: [{ type: "text", text: p.replace(/\n/g, " ") }],
    })),
  };
}

export async function createJiraIssue(
  config: JiraConfig,
  ticket: { title: string; body: string; reportUrl: string }
): Promise<CreateIssueResult> {
  try {
    const res = await fetch(`${config.baseUrl.replace(/\/$/, "")}/rest/api/3/issue`, {
      method: "POST",
      headers: {
        Authorization: jiraAuthHeader(config.email, config.apiToken),
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        fields: {
          project: { key: config.projectKey },
          summary: ticket.title,
          description: markdownToAdf(`${ticket.body}\n\nFull scan report: ${ticket.reportUrl}`),
          issuetype: { name: "Bug" },
        },
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      return { ok: false, error: `Jira issue creation failed (${res.status}): ${detail.slice(0, 300)}` };
    }
    const body = (await res.json()) as { key?: string };
    if (!body.key) return { ok: false, error: "Jira did not return an issue key" };
    return { ok: true, url: `${config.baseUrl.replace(/\/$/, "")}/browse/${body.key}`, issueKey: body.key };
  } catch (err) {
    return { ok: false, error: `Could not reach Jira: ${(err as Error).message}` };
  }
}

/**
 * Whether a previously-created Jira issue is still there, and whether it's
 * already resolved. Used before reusing a ledger entry: an issue somebody
 * deleted in Jira must not suppress a fresh ticket for a live finding.
 *
 * Jira's statusCategory is the stable, workflow-independent signal here —
 * every project's workflow names its statuses differently ("Done" /
 * "Resolved" / "Shipped"), but they all map onto one of three category keys,
 * of which "done" is the terminal one.
 */
export async function getJiraIssue(config: Pick<JiraConfig, "baseUrl" | "email" | "apiToken">, issueKey: string): Promise<IssueState> {
  try {
    const res = await fetch(`${config.baseUrl.replace(/\/$/, "")}/rest/api/3/issue/${encodeURIComponent(issueKey)}?fields=status`, {
      headers: { Authorization: jiraAuthHeader(config.email, config.apiToken), Accept: "application/json" },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (res.status === 404) return { status: "missing" };
    if (!res.ok) return { status: "unknown", error: `Jira returned HTTP ${res.status}` };
    const body = (await res.json()) as { fields?: { status?: { statusCategory?: { key?: string } } } };
    return body.fields?.status?.statusCategory?.key === "done" ? { status: "done" } : { status: "open" };
  } catch (err) {
    return { status: "unknown", error: `Could not reach Jira: ${(err as Error).message}` };
  }
}

export async function addJiraComment(
  config: Pick<JiraConfig, "baseUrl" | "email" | "apiToken">,
  issueKey: string,
  text: string
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const res = await fetch(`${config.baseUrl.replace(/\/$/, "")}/rest/api/3/issue/${encodeURIComponent(issueKey)}/comment`, {
      method: "POST",
      headers: {
        Authorization: jiraAuthHeader(config.email, config.apiToken),
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ body: markdownToAdf(text) }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) return { ok: false, error: `Jira comment failed (${res.status})` };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `Could not reach Jira: ${(err as Error).message}` };
  }
}

/**
 * Moves a Jira issue to whatever its project's workflow calls "done".
 *
 * Jira has no "set status" API — a status change must go through a
 * transition that is currently available on that specific issue in that
 * specific workflow, and both the transition's id and name are
 * project-specific. So this asks the issue which transitions it has, then
 * picks the first whose *target* status is in the "done" category rather
 * than string-matching a name like "Done", which is exactly the kind of
 * assumption that breaks on any customised workflow.
 *
 * Returns a descriptive error rather than throwing when no done-category
 * transition is available (a workflow can genuinely require an intermediate
 * step first) — the caller logs it and leaves the issue alone.
 */
export async function transitionJiraIssueToDone(
  config: Pick<JiraConfig, "baseUrl" | "email" | "apiToken">,
  issueKey: string
): Promise<{ ok: true; transitionName: string } | { ok: false; error: string }> {
  const base = config.baseUrl.replace(/\/$/, "");
  const auth = { Authorization: jiraAuthHeader(config.email, config.apiToken), Accept: "application/json" };
  try {
    const listRes = await fetch(`${base}/rest/api/3/issue/${encodeURIComponent(issueKey)}/transitions`, {
      headers: auth,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!listRes.ok) return { ok: false, error: `Could not list Jira transitions (${listRes.status})` };

    const listBody = (await listRes.json()) as {
      transitions?: Array<{ id: string; name: string; to?: { statusCategory?: { key?: string } } }>;
    };
    const done = (listBody.transitions ?? []).find((t) => t.to?.statusCategory?.key === "done");
    if (!done) {
      return { ok: false, error: `No transition to a done status is available on ${issueKey} from its current status` };
    }

    const doRes = await fetch(`${base}/rest/api/3/issue/${encodeURIComponent(issueKey)}/transitions`, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({ transition: { id: done.id } }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!doRes.ok) return { ok: false, error: `Jira transition failed (${doRes.status})` };
    return { ok: true, transitionName: done.name };
  } catch (err) {
    return { ok: false, error: `Could not reach Jira: ${(err as Error).message}` };
  }
}

// ---- Linear -------------------------------------------------------------------

export type LinearConfig = {
  apiKey: string;
  teamId: string;
};

const LINEAR_API = "https://api.linear.app/graphql";

async function linearGraphql(apiKey: string, query: string, variables: Record<string, unknown>): Promise<{ data?: Record<string, unknown>; errors?: Array<{ message: string }> }> {
  const res = await fetch(LINEAR_API, {
    method: "POST",
    headers: { Authorization: apiKey, "Content-Type": "application/json" },
    body: JSON.stringify({ query, variables }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  return (await res.json()) as { data?: Record<string, unknown>; errors?: Array<{ message: string }> };
}

/** One real, read-only call ({ viewer { id } }) — confirms the API key actually works before anything is saved. */
export async function validateLinearCredentials(apiKey: string): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const body = await linearGraphql(apiKey, "query { viewer { id } }", {});
    if (body.errors?.length) return { ok: false, error: body.errors[0].message };
    if (!body.data?.viewer) return { ok: false, error: "Linear rejected the API key" };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `Could not reach Linear: ${(err as Error).message}` };
  }
}

// Linear renders markdown natively in issue descriptions, unlike Jira's ADF
// requirement — the remediation text passes through unmodified.
const CREATE_ISSUE_MUTATION = `
  mutation CreateIssue($teamId: String!, $title: String!, $description: String!) {
    issueCreate(input: { teamId: $teamId, title: $title, description: $description }) {
      success
      issue { id url }
    }
  }
`;

export async function createLinearIssue(
  config: LinearConfig,
  ticket: { title: string; body: string; reportUrl: string }
): Promise<CreateIssueResult> {
  try {
    const body = await linearGraphql(config.apiKey, CREATE_ISSUE_MUTATION, {
      teamId: config.teamId,
      title: ticket.title,
      description: `${ticket.body}\n\nFull scan report: ${ticket.reportUrl}`,
    });
    if (body.errors?.length) return { ok: false, error: body.errors[0].message };
    const result = body.data?.issueCreate as { success?: boolean; issue?: { id?: string; url?: string } } | undefined;
    if (!result?.success || !result.issue?.url || !result.issue.id) {
      return { ok: false, error: "Linear did not confirm issue creation" };
    }
    // The issue's id (not its "ENG-42" identifier) is the API handle — see
    // CreateIssueResult's comment.
    return { ok: true, url: result.issue.url, issueKey: result.issue.id };
  } catch (err) {
    return { ok: false, error: `Could not reach Linear: ${(err as Error).message}` };
  }
}

/**
 * Linear's equivalent of getJiraIssue. Its WorkflowState.type vocabulary is
 * fixed and workspace-independent (triage/backlog/unstarted/started/
 * completed/canceled), so unlike Jira there's no per-project naming to work
 * around — "completed" and "canceled" are both terminal, and either means
 * there is nothing left for us to close.
 *
 * A null issue with no GraphQL error is Linear's way of saying "no such
 * issue", which is the missing case; a transport failure stays "unknown".
 */
export async function getLinearIssue(apiKey: string, issueId: string): Promise<IssueState> {
  try {
    const body = await linearGraphql(apiKey, `query Issue($id: String!) { issue(id: $id) { id state { type } } }`, { id: issueId });
    if (body.errors?.length) {
      const message = body.errors[0].message;
      // Linear reports a deleted/unknown issue as an error rather than a
      // null field, so treat only that specific shape as evidence of
      // deletion and leave everything else as "can't tell".
      if (/not found|entity not found|could not find/i.test(message)) return { status: "missing" };
      return { status: "unknown", error: message };
    }
    const issue = body.data?.issue as { id?: string; state?: { type?: string } } | null | undefined;
    if (!issue) return { status: "missing" };
    const type = issue.state?.type;
    return type === "completed" || type === "canceled" ? { status: "done" } : { status: "open" };
  } catch (err) {
    return { status: "unknown", error: `Could not reach Linear: ${(err as Error).message}` };
  }
}

export async function addLinearComment(apiKey: string, issueId: string, text: string): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const body = await linearGraphql(
      apiKey,
      `mutation Comment($issueId: String!, $body: String!) { commentCreate(input: { issueId: $issueId, body: $body }) { success } }`,
      { issueId, body: text }
    );
    if (body.errors?.length) return { ok: false, error: body.errors[0].message };
    const result = body.data?.commentCreate as { success?: boolean } | undefined;
    if (!result?.success) return { ok: false, error: "Linear did not confirm the comment" };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `Could not reach Linear: ${(err as Error).message}` };
  }
}

/**
 * Moves a Linear issue into its team's completed state. The state id is
 * team-specific, so it has to be looked up from the issue's own team rather
 * than configured — which also means this works unchanged if the customer
 * renames their "Done" column.
 */
export async function closeLinearIssue(apiKey: string, issueId: string): Promise<{ ok: true; stateName: string } | { ok: false; error: string }> {
  try {
    const lookup = await linearGraphql(
      apiKey,
      `query IssueStates($id: String!) { issue(id: $id) { team { states { nodes { id name type } } } } }`,
      { id: issueId }
    );
    if (lookup.errors?.length) return { ok: false, error: lookup.errors[0].message };

    const states = (lookup.data?.issue as { team?: { states?: { nodes?: Array<{ id: string; name: string; type: string }> } } } | null)
      ?.team?.states?.nodes;
    const completed = (states ?? []).find((s) => s.type === "completed");
    if (!completed) return { ok: false, error: "This Linear team has no state of type 'completed'" };

    const update = await linearGraphql(
      apiKey,
      `mutation Close($id: String!, $stateId: String!) { issueUpdate(id: $id, input: { stateId: $stateId }) { success } }`,
      { id: issueId, stateId: completed.id }
    );
    if (update.errors?.length) return { ok: false, error: update.errors[0].message };
    const result = update.data?.issueUpdate as { success?: boolean } | undefined;
    if (!result?.success) return { ok: false, error: "Linear did not confirm the state change" };
    return { ok: true, stateName: completed.name };
  } catch (err) {
    return { ok: false, error: `Could not reach Linear: ${(err as Error).message}` };
  }
}
