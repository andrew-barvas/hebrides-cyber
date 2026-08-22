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
): Promise<{ ok: true; url: string } | { ok: false; error: string }> {
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
    return { ok: true, url: `${config.baseUrl.replace(/\/$/, "")}/browse/${body.key}` };
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
      issue { url }
    }
  }
`;

export async function createLinearIssue(
  config: LinearConfig,
  ticket: { title: string; body: string; reportUrl: string }
): Promise<{ ok: true; url: string } | { ok: false; error: string }> {
  try {
    const body = await linearGraphql(config.apiKey, CREATE_ISSUE_MUTATION, {
      teamId: config.teamId,
      title: ticket.title,
      description: `${ticket.body}\n\nFull scan report: ${ticket.reportUrl}`,
    });
    if (body.errors?.length) return { ok: false, error: body.errors[0].message };
    const result = body.data?.issueCreate as { success?: boolean; issue?: { url?: string } } | undefined;
    if (!result?.success || !result.issue?.url) return { ok: false, error: "Linear did not confirm issue creation" };
    return { ok: true, url: result.issue.url };
  } catch (err) {
    return { ok: false, error: `Could not reach Linear: ${(err as Error).message}` };
  }
}
