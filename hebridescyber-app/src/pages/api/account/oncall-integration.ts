// POST/DELETE /api/account/oncall-integration — E-54, customer-facing half
// of the PagerDuty/Opsgenie on-call alerting integration: lets an account
// owner save credentials for one provider, verifying (once, at save time)
// that they actually work before writing a row — same "verify access before
// saving" precedent as src/pages/api/account/ticket-integration.ts and
// connect-repo.ts.
//
// Reuses ticket_integrations (sql/migrations/028_oncall_integrations.sql
// extended its provider CHECK to allow 'pagerduty'/'opsgenie';
// sql/migrations/039_oncall_credential_columns.sql added the dedicated
// pagerduty_routing_key/opsgenie_api_key columns). Writes go through
// supabaseAdmin because that table ships with no insert/update/delete RLS
// policy — this route is the only place a pagerduty/opsgenie row gets
// written, and only after validatePagerDutyKey/validateOpsgenieKey (see
// src/lib/oncallIntegrations.ts) return ok.
//
// No PATCH here, unlike ticket-integration.ts's auto-close toggle — for
// pagerduty/opsgenie a row's mere existence IS "alerting is active" (see
// src/lib/oncallAlerts.ts's header), so there is no separate flag to flip.
//
// Reads for status display go straight through the browser's own session
// against ticket_integrations' owner-scoped SELECT policy, same as
// TicketIntegration.tsx — the UI component only ever requests non-secret
// columns (provider, region, created_at), never pagerduty_routing_key/
// opsgenie_api_key.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { validatePagerDutyKey, validateOpsgenieKey } from "@/lib/oncallIntegrations";
import { parseBody } from "@/lib/validate";
import { ENCRYPTION_NOT_CONFIGURED_MESSAGE, isCredentialEncryptionConfigured, sealSecrets } from "@/lib/credentialEncryption";

const deleteSchema = z.object({
  provider: z.enum(["pagerduty", "opsgenie"]),
});

const postSchema = z.discriminatedUnion("provider", [
  z.object({
    provider: z.literal("pagerduty"),
    routingKey: z.string().min(1, "routingKey is required"),
  }),
  z.object({
    provider: z.literal("opsgenie"),
    apiKey: z.string().min(1, "apiKey is required"),
    region: z.enum(["us", "eu"]),
  }),
]);

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST" && req.method !== "DELETE") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "On-call integrations can only be managed from a logged-in session, not with an API key." });
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

  // Keys are stored encrypted (credentialEncryption.ts); never fall back to plaintext.
  if (!isCredentialEncryptionConfigured()) return res.status(503).json({ error: ENCRYPTION_NOT_CONFIGURED_MESSAGE });

  if (body.provider === "pagerduty") {
    const { routingKey } = body;
    const check = await validatePagerDutyKey(routingKey);
    if (!check.ok) return res.status(400).json({ error: check.error });

    const { error } = await supabaseAdmin.from("ticket_integrations").upsert(
      sealSecrets({ owner: caller.ownerId, provider: "pagerduty", pagerduty_routing_key: routingKey }, ["pagerduty_routing_key"]),
      { onConflict: "owner,provider" }
    );
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true, provider: "pagerduty" });
  }

  const { apiKey, region } = body;
  const check = await validateOpsgenieKey(apiKey, region);
  if (!check.ok) return res.status(400).json({ error: check.error });

  const { error } = await supabaseAdmin.from("ticket_integrations").upsert(
    sealSecrets({ owner: caller.ownerId, provider: "opsgenie", opsgenie_api_key: apiKey, region }, ["opsgenie_api_key"]),
    { onConflict: "owner,provider" }
  );
  if (error) return res.status(500).json({ error: error.message });
  return res.status(200).json({ ok: true, provider: "opsgenie" });
}
