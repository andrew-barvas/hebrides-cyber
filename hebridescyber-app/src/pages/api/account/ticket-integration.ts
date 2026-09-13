// POST/DELETE /api/account/ticket-integration — customer-facing half of the
// Jira/Linear ticket-creation feature: lets an account owner save credentials
// for one provider, verifying (once, at save time) that they actually work
// before writing a row — same "verify access before saving" precedent as
// src/pages/api/account/connect-repo.ts.
//
// Writes go through supabaseAdmin because
// sql/migrations/013_ticket_integrations.sql deliberately ships with no
// insert/update/delete RLS policy: this route is the only place a row in
// ticket_integrations is allowed to be written, and only after the real
// Jira/Linear API call in src/lib/ticketIntegrations.ts's validate*()
// functions returns ok. Reads for status display go straight through the
// browser's own session (the table's owner-scoped SELECT policy), but the
// UI must only ever request non-secret columns — see the migration's
// header for why.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { validateJiraCredentials, validateLinearCredentials } from "@/lib/ticketIntegrations";
import { parseBody } from "@/lib/validate";

const patchSchema = z.object({
  provider: z.enum(["jira", "linear"]),
  autoCloseEnabled: z.boolean(),
});

const deleteSchema = z.object({
  provider: z.enum(["jira", "linear"]),
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
]);

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST" && req.method !== "PATCH" && req.method !== "DELETE") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Ticket integrations can only be managed from a logged-in session, not with an API key." });
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

  return res.status(400).json({ error: "provider must be 'jira' or 'linear'" });
}
