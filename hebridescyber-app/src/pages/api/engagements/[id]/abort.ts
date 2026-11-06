// POST /api/engagements/{id}/abort — the stop path (docs/EXPLOITABILITY-ENGINE.md
// §10.6). The owner can always stop their own engagement, and so can an admin, from
// any state but closed. Session only. Deliberately has no plan gate and no rate
// limit: nothing may stand in the way of a stop, including a lapsed subscription.
//
// abort_engagement() does it all in one transaction. Asking again is safe, and
// revokes anything linked since. A job the worker has already claimed keeps running
// until its next gate check (§13 Q5).
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { requireAdmin } from "@/lib/adminAuth";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { abortEngagement, loadEngagement, sendEngagementFailure } from "@/lib/engagements";
import { isUuid } from "@/lib/exploitabilityApi";
import { parseBody } from "@/lib/validate";

const ROUTE = "engagements/[id]/abort";

const bodySchema = z.object({ reason: z.string().trim().min(1).max(500).optional() });

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });
  if (caller.via !== "session") return res.status(403).json({ error: "An engagement can only be stopped from a logged-in session, not with an API key." });

  const body = parseBody(bodySchema, req.body ?? {}, res);
  if (!body) return;

  const id = req.query.id;
  if (!isUuid(id)) return sendEngagementFailure(res, ROUTE, { status: "not_found" });

  const loaded = await loadEngagement(supabaseAdmin, id);
  if (loaded.status !== "ok") return sendEngagementFailure(res, ROUTE, loaded);

  // Someone else's engagement looks exactly like one that doesn't exist.
  let actorId: string | null = loaded.data.owner === caller.ownerId ? caller.ownerId : null;
  if (!actorId) actorId = await requireAdmin(req);
  if (!actorId) return sendEngagementFailure(res, ROUTE, { status: "not_found" });

  const aborted = await abortEngagement(supabaseAdmin, id, body.reason ?? null);
  if (aborted.status !== "ok") return sendEngagementFailure(res, ROUTE, aborted);
  const result = aborted.data;
  if (result.outcome === "not_found") return sendEngagementFailure(res, ROUTE, { status: "not_found" });
  if (result.outcome === "closed") return res.status(409).json({ error: "This engagement is already closed.", state: "closed" });

  for (const host of result.revokedHosts) {
    await logAuditEvent(supabaseAdmin, { actorId, action: "offensive_scan.revoked", resourceType: "monitored_target", resourceId: host, metadata: { owner: loaded.data.owner, engagement_id: id } });
  }
  if (result.outcome === "aborted") {
    await logAuditEvent(supabaseAdmin, {
      actorId,
      action: "engagement.aborted",
      resourceType: "engagement",
      resourceId: id,
      metadata: { from: result.from, reason: body.reason ?? null, authorisations_revoked: result.revokedHosts.length, simulations_withdrawn: result.simulationsWithdrawn },
    });
  }
  return res.status(200).json({ state: "aborted", authorisationsRevoked: result.revokedHosts.length, simulationsWithdrawn: result.simulationsWithdrawn });
}
