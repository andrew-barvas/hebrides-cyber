// ServiceNow and GitHub Issues ticket providers — extends the Jira/Linear
// providers in ticketIntegrations.ts with the same CreateIssueResult/IssueState
// contract so ticketLinks.ts and ticketAutoClose.ts work unchanged.

import type { CreateIssueResult, IssueState } from "./ticketIntegrations";

const REQUEST_TIMEOUT_MS = 10_000;

// ---- ServiceNow ---------------------------------------------------------------

export type ServiceNowConfig = {
  instanceUrl: string; // e.g. "https://dev12345.service-now.com"
  username: string;
  password: string;
  tableName?: string; // defaults to "incident"
};

function snowAuthHeader(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`;
}

export async function validateServiceNowCredentials(
  config: Pick<ServiceNowConfig, "instanceUrl" | "username" | "password">,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const base = config.instanceUrl.replace(/\/$/, "");
    const res = await fetch(`${base}/api/now/table/sys_user?sysparm_limit=1`, {
      headers: {
        Authorization: snowAuthHeader(config.username, config.password),
        Accept: "application/json",
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (res.status === 401 || res.status === 403) {
      return { ok: false, error: "ServiceNow rejected the credentials" };
    }
    if (!res.ok) return { ok: false, error: `ServiceNow returned HTTP ${res.status}` };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `Could not reach ServiceNow: ${(err as Error).message}` };
  }
}

export async function createServiceNowIncident(
  config: ServiceNowConfig,
  ticket: { title: string; body: string; reportUrl: string },
): Promise<CreateIssueResult> {
  const base = config.instanceUrl.replace(/\/$/, "");
  const table = config.tableName || "incident";
  try {
    const res = await fetch(`${base}/api/now/table/${encodeURIComponent(table)}`, {
      method: "POST",
      headers: {
        Authorization: snowAuthHeader(config.username, config.password),
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        short_description: ticket.title,
        description: `${ticket.body}\n\nFull scan report: ${ticket.reportUrl}`,
        category: "Security",
        urgency: "2",
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      return { ok: false, error: `ServiceNow incident creation failed (${res.status}): ${detail.slice(0, 300)}` };
    }
    const body = (await res.json()) as { result?: { sys_id?: string; number?: string } };
    const sysId = body.result?.sys_id;
    const number = body.result?.number;
    if (!sysId) return { ok: false, error: "ServiceNow did not return a sys_id" };
    return {
      ok: true,
      url: `${base}/nav_to.do?uri=${encodeURIComponent(table)}.do?sys_id=${sysId}`,
      issueKey: number || sysId,
    };
  } catch (err) {
    return { ok: false, error: `Could not reach ServiceNow: ${(err as Error).message}` };
  }
}

export async function getServiceNowIncident(
  config: Pick<ServiceNowConfig, "instanceUrl" | "username" | "password" | "tableName">,
  issueKey: string,
): Promise<IssueState> {
  const base = config.instanceUrl.replace(/\/$/, "");
  const table = config.tableName || "incident";
  try {
    const res = await fetch(
      `${base}/api/now/table/${encodeURIComponent(table)}?sysparm_query=number=${encodeURIComponent(issueKey)}&sysparm_fields=state&sysparm_limit=1`,
      {
        headers: {
          Authorization: snowAuthHeader(config.username, config.password),
          Accept: "application/json",
        },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      },
    );
    if (!res.ok) return { status: "unknown", error: `ServiceNow returned HTTP ${res.status}` };
    const body = (await res.json()) as { result?: Array<{ state?: string }> };
    if (!body.result?.length) return { status: "missing" };
    const state = body.result[0].state;
    // ServiceNow incident states: 6=Resolved, 7=Closed, 8=Canceled
    return state === "6" || state === "7" || state === "8" ? { status: "done" } : { status: "open" };
  } catch (err) {
    return { status: "unknown", error: `Could not reach ServiceNow: ${(err as Error).message}` };
  }
}

export async function closeServiceNowIncident(
  config: Pick<ServiceNowConfig, "instanceUrl" | "username" | "password" | "tableName">,
  issueKey: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const base = config.instanceUrl.replace(/\/$/, "");
  const table = config.tableName || "incident";
  try {
    // Look up sys_id from number
    const lookupRes = await fetch(
      `${base}/api/now/table/${encodeURIComponent(table)}?sysparm_query=number=${encodeURIComponent(issueKey)}&sysparm_fields=sys_id&sysparm_limit=1`,
      {
        headers: {
          Authorization: snowAuthHeader(config.username, config.password),
          Accept: "application/json",
        },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      },
    );
    if (!lookupRes.ok) return { ok: false, error: `ServiceNow lookup failed (${lookupRes.status})` };
    const lookupBody = (await lookupRes.json()) as { result?: Array<{ sys_id?: string }> };
    const sysId = lookupBody.result?.[0]?.sys_id;
    if (!sysId) return { ok: false, error: `Incident ${issueKey} not found` };

    const res = await fetch(`${base}/api/now/table/${encodeURIComponent(table)}/${sysId}`, {
      method: "PATCH",
      headers: {
        Authorization: snowAuthHeader(config.username, config.password),
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ state: "6", close_code: "Solved (Permanently)", close_notes: "Vulnerability verified as fixed by Hebrides Cyber scan" }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) return { ok: false, error: `ServiceNow close failed (${res.status})` };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `Could not reach ServiceNow: ${(err as Error).message}` };
  }
}

// ---- GitHub Issues --------------------------------------------------------------

export type GitHubIssuesConfig = {
  token: string; // PAT or fine-grained token with issues:write
  owner: string;
  repo: string;
};

export async function validateGitHubIssuesCredentials(
  config: GitHubIssuesConfig,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const res = await fetch(`https://api.github.com/repos/${encodeURIComponent(config.owner)}/${encodeURIComponent(config.repo)}`, {
      headers: {
        Authorization: `Bearer ${config.token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (res.status === 401) return { ok: false, error: "GitHub rejected the token" };
    if (res.status === 404) return { ok: false, error: "Repository not found or token lacks access" };
    if (!res.ok) return { ok: false, error: `GitHub returned HTTP ${res.status}` };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `Could not reach GitHub: ${(err as Error).message}` };
  }
}

export async function createGitHubIssue(
  config: GitHubIssuesConfig,
  ticket: { title: string; body: string; reportUrl: string },
): Promise<CreateIssueResult> {
  try {
    const res = await fetch(
      `https://api.github.com/repos/${encodeURIComponent(config.owner)}/${encodeURIComponent(config.repo)}/issues`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${config.token}`,
          Accept: "application/vnd.github+json",
          "Content-Type": "application/json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        body: JSON.stringify({
          title: ticket.title,
          body: `${ticket.body}\n\n---\n[Full scan report](${ticket.reportUrl})`,
          labels: ["security"],
        }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      },
    );
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      return { ok: false, error: `GitHub issue creation failed (${res.status}): ${detail.slice(0, 300)}` };
    }
    const body = (await res.json()) as { number?: number; html_url?: string };
    if (!body.number || !body.html_url) return { ok: false, error: "GitHub did not return issue data" };
    return { ok: true, url: body.html_url, issueKey: String(body.number) };
  } catch (err) {
    return { ok: false, error: `Could not reach GitHub: ${(err as Error).message}` };
  }
}

export async function getGitHubIssue(config: GitHubIssuesConfig, issueNumber: string): Promise<IssueState> {
  try {
    const res = await fetch(
      `https://api.github.com/repos/${encodeURIComponent(config.owner)}/${encodeURIComponent(config.repo)}/issues/${issueNumber}`,
      {
        headers: {
          Authorization: `Bearer ${config.token}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      },
    );
    if (res.status === 404) return { status: "missing" };
    if (!res.ok) return { status: "unknown", error: `GitHub returned HTTP ${res.status}` };
    const body = (await res.json()) as { state?: string };
    return body.state === "closed" ? { status: "done" } : { status: "open" };
  } catch (err) {
    return { status: "unknown", error: `Could not reach GitHub: ${(err as Error).message}` };
  }
}

export async function closeGitHubIssue(
  config: GitHubIssuesConfig,
  issueNumber: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const res = await fetch(
      `https://api.github.com/repos/${encodeURIComponent(config.owner)}/${encodeURIComponent(config.repo)}/issues/${issueNumber}`,
      {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${config.token}`,
          Accept: "application/vnd.github+json",
          "Content-Type": "application/json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        body: JSON.stringify({ state: "closed", state_reason: "completed" }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      },
    );
    if (!res.ok) return { ok: false, error: `GitHub close failed (${res.status})` };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `Could not reach GitHub: ${(err as Error).message}` };
  }
}

export async function addGitHubIssueComment(
  config: GitHubIssuesConfig,
  issueNumber: string,
  text: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const res = await fetch(
      `https://api.github.com/repos/${encodeURIComponent(config.owner)}/${encodeURIComponent(config.repo)}/issues/${issueNumber}/comments`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${config.token}`,
          Accept: "application/vnd.github+json",
          "Content-Type": "application/json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        body: JSON.stringify({ body: text }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      },
    );
    if (!res.ok) return { ok: false, error: `GitHub comment failed (${res.status})` };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `Could not reach GitHub: ${(err as Error).message}` };
  }
}
