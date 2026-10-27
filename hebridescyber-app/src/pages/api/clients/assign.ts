// Assign monitored sites (and/or verified domains) to a client, or pass
// client_id: null to move them back to "Unassigned". Session-only and
// Agency-gated like api/clients.ts. Every id is filtered by owner, so another
// account's rows are untouched and simply not counted as updated.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { hasAgencyAccess } from "@/lib/planAccess";
import { parseBody } from "@/lib/validate";

const schema = z
  .object({
    client_id: z.string().min(1).nullable(),
    target_ids: z.array(z.string().min(1)).max(200).default([]),
    verification_ids: z.array(z.string().min(1)).max(200).default([]),
  })
  .refine((b) => b.target_ids.length + b.verification_ids.length > 0, { message: "target_ids or verification_ids is required" });

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Clients can only be managed from a logged-in session, not with an API key." });
  }
  if (!(await hasAgencyAccess(supabaseAdmin, caller.ownerId))) {
    return res.status(403).json({ error: "Client workspaces are part of the Agency plan." });
  }

  const parsed = parseBody(schema, req.body, res);
  if (!parsed) return;

  if (parsed.client_id) {
    const { data: client, error } = await supabaseAdmin
      .from("clients")
      .select("id")
      .eq("id", parsed.client_id)
      .eq("owner", caller.ownerId)
      .maybeSingle();
    if (error) return res.status(500).json({ error: error.message });
    if (!client) return res.status(404).json({ error: "Client not found" });
  }

  const updateIds = async (table: "monitored_targets" | "verifications", ids: string[]) => {
    if (ids.length === 0) return { count: 0, error: null };
    const { data, error } = await supabaseAdmin
      .from(table)
      .update({ client_id: parsed.client_id })
      .in("id", ids)
      .eq("owner", caller.ownerId)
      .select("id");
    return { count: data?.length ?? 0, error };
  };

  const [sites, domains] = await Promise.all([
    updateIds("monitored_targets", parsed.target_ids),
    updateIds("verifications", parsed.verification_ids),
  ]);
  const error = sites.error ?? domains.error;
  if (error) {
    if (isMissingSchemaError(error)) {
      return res.status(503).json({ error: "Client workspaces aren't enabled on this server yet (database migration 064 pending)." });
    }
    return res.status(500).json({ error: error.message });
  }

  await logAuditEvent(supabaseAdmin, {
    actorId: caller.ownerId,
    action: "client.sites_assigned",
    resourceType: "client",
    resourceId: parsed.client_id ?? "unassigned",
    metadata: { sites: sites.count, domains: domains.count },
  });
  return res.status(200).json({ updated: { sites: sites.count, domains: domains.count } });
}
