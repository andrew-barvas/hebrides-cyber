// POST/PATCH/DELETE /api/account/ticket-integration — customer-facing half of
// the ticket-creation feature (Jira, Linear, ServiceNow, GitHub Issues): lets
// an account owner save credentials for one tracker, verifying (once, at save
// time) that they actually work before writing a row — same "verify access
// before saving" precedent as src/pages/api/account/connect-repo.ts.
//
// Writes go through supabaseAdmin because
// sql/migrations/013_ticket_integrations.sql deliberately ships with no
// insert/update/delete RLS policy: this route is the only place a tracker row
// in ticket_integrations is allowed to be written, and only after the real
// API call in ticketIntegrations.ts / ticketProviders.ts's validate*()
// functions returns ok. Reads for status display go straight through the
// browser's own session (the table's owner-scoped SELECT policy), but the
// UI must only ever request non-secret columns — see the migration's
// header for why.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { validateJiraCredentials, validateLinearCredentials } from "@/lib/ticketIntegrations";
import { isServiceNowInstanceUrl, validateGitHubIssuesCredentials, validateServiceNowCredentials } from "@/lib/ticketProviders";
import { TICKET_PROVIDERS } from "@/lib/ticketProviderList";
import { findTicketIntegration, summariseTicketIntegration } from "@/lib/ticketLinks";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { parseBody } from "@/lib/validate";

const patchSchema = z.object({
  provider: z.enum(TICKET_PROVIDERS),
  autoCloseEnabled: z.boolean(),
});

const deleteSchema = z.object({
  provider: z.enum(TICKET_PROVIDERS),
});

const postSchema = z.discriminatedUnion("provider", [
  z.object({
    provider: z.literal("jira"),
    baseUrl: z.string().url("baseUrl must be a valid URL"),
    email: z.string().email("email must be a valid email address"),
    apiToken: z.string().min(1, "apiToken is required"),
    projectKey: z.string().min(1, "projectKey is required"),
  }),
  z.object({
    provider: z.literal("linear"),
    apiKey: z.string().min(1, "apiKey is required"),
    teamId: z.string().min(1, "teamId is required"),
  }),
  z.object({
    provider: z.literal("servicenow"),
    // Checked before any request is made — see isServiceNowInstanceUrl for
    // why this is the SSRF guard, not just input tidiness.
    instanceUrl: z
      .string()
      .refine(isServiceNowInstanceUrl, "instanceUrl must be your instance address, e.g. https://acme.service-now.com"),
    username: z.string().min(1, "username is required"),
    password: z.string().min(1, "password is required"),
  }),
  z.object({
    provider: z.literal("github"),
    // Interpolated into API paths, so constrain to GitHub's own name rules.
    owner: z.string().regex(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/, "owner must be a GitHub user or organisation name"),
    repo: z.string().regex(/^[A-Za-z0-9._-]{1,100}$/, "repo must be a repository name"),
    token: z.string().min(1, "token is required"),
  }),
]);

// ServiceNow/GitHub need migration 040's columns and widened CHECK
// constraint. Until it's applied, saving one fails with PGRST204 (unknown
// column in the insert payload), 42703, or 23514 (provider not allowed) —
// report that plainly instead of a raw database error.
function notEnabledYet(error: { code?: string | null } | null): boolean {
  return isMissingSchemaError(error) || error?.code === "PGRST204" || error?.code === "23514";
}
const NOT_ENABLED_MESSAGE = "This tracker isn't enabled on this deployment yet — please try again shortly.";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST" && req.method !== "PATCH" && req.method !== "DELETE") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Ticket integrations can only be managed from a logged-in session, not with an API key." });
  }

  // GET returns a summary with no credentials in it. The settings UI used to
  // select columns straight from the browser, which both relied on every UI
  // author remembering not to request secret columns and broke whenever a
  // column it named hadn't been migrated yet.
  if (req.method === "GET") {
    const integration = await findTicketIntegration(supabaseAdmin, caller.ownerId);
    return res.status(200).json({ integration: integration ? summariseTicketIntegration(integration) : null });
  }

  // PATCH toggles behaviour on an already-connected integration, separate
  // from POST's credential save so flipping auto-close doesn't require
  // re-entering an API token that is never sent back to the browser.
  if (req.method === "PATCH") {
    const patchParsed = parseBody(patchSchema, req.body, res);
    if (!patchParsed) return;
    const { provider, autoCloseEnabled } = patchParsed;
    const { data, error } = await supabaseAdmin
      .from("ticket_integrations")
      .update({ auto_close_enabled: autoCloseEnabled })
      .eq("owner", caller.ownerId)
      .eq("provider", provider)
      .select("provider")
      .maybeSingle();
    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: `No ${provider} integration is connected.` });
    return res.status(200).json({ ok: true, provider, autoCloseEnabled });
  }

  if (req.method === "DELETE") {
    const deleteParsed = parseBody(deleteSchema, req.body, res);
    if (!deleteParsed) return;
    const { provider } = deleteParsed;
    const { error } = await supabaseAdmin.from("ticket_integrations").delete().eq("owner", caller.ownerId).eq("provider", provider);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  const body = parseBody(postSchema, req.body, res);
  if (!body) return;

  if (body.provider === "jira") {
    const { baseUrl, email, apiToken, projectKey } = body;
    const check = await validateJiraCredentials({ baseUrl, email, apiToken });
    if (!check.ok) return res.status(400).json({ error: check.error });

    const { error } = await supabaseAdmin.from("ticket_integrations").upsert(
      { owner: caller.ownerId, provider: "jira", jira_base_url: baseUrl, jira_email: email, jira_api_token: apiToken, jira_project_key: projectKey },
      { onConflict: "owner,provider" }
    );
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true, provider: "jira" });
  }

  if (body.provider === "linear") {
    const { apiKey, teamId } = body;
    const check = await validateLinearCredentials(apiKey);
    if (!check.ok) return res.status(400).json({ error: check.error });

    const { error } = await supabaseAdmin.from("ticket_integrations").upsert(
      { owner: caller.ownerId, provider: "linear", linear_api_key: apiKey, linear_team_id: teamId },
      { onConflict: "owner,provider" }
    );
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true, provider: "linear" });
  }

  if (body.provider === "servicenow") {
    const instanceUrl = body.instanceUrl.replace(/\/$/, "");
    const { username, password } = body;
    const check = await validateServiceNowCredentials({ instanceUrl, username, password });
    if (!check.ok) return res.status(400).json({ error: check.error });

    const { error } = await supabaseAdmin.from("ticket_integrations").upsert(
      { owner: caller.ownerId, provider: "servicenow", servicenow_instance_url: instanceUrl, servicenow_username: username, servicenow_password: password },
      { onConflict: "owner,provider" }
    );
    if (error) return res.status(notEnabledYet(error) ? 503 : 500).json({ error: notEnabledYet(error) ? NOT_ENABLED_MESSAGE : error.message });
    return res.status(200).json({ ok: true, provider: "servicenow" });
  }

  if (body.provider === "github") {
    const { owner, repo, token } = body;
    const check = await validateGitHubIssuesCredentials({ owner, repo, token });
    if (!check.ok) return res.status(400).json({ error: check.error });

    const { error } = await supabaseAdmin.from("ticket_integrations").upsert(
      { owner: caller.ownerId, provider: "github", github_owner: owner, github_repo: repo, github_token: token },
      { onConflict: "owner,provider" }
    );
    if (error) return res.status(notEnabledYet(error) ? 503 : 500).json({ error: notEnabledYet(error) ? NOT_ENABLED_MESSAGE : error.message });
    return res.status(200).json({ ok: true, provider: "github" });
  }

  return res.status(400).json({ error: `provider must be one of: ${TICKET_PROVIDERS.join(", ")}` });
}
