// POST /api/engagements/{id}/scope — add or remove hosts on an engagement's signed
// scope list, while it is still booked or scoped. Admin session only. Refusals come
// back per host, so one bad host doesn't lose the rest. Sends nothing to any target.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { applyScopeChanges, loadEngagement, sendEngagementFailure } from "@/lib/engagements";
import { isUuid } from "@/lib/exploitabilityApi";
import { parseBody } from "@/lib/validate";

const ROUTE = "engagements/[id]/scope";

const bodySchema = z
  .object({
    add: z.array(z.object({ host: z.string().min(1).max(253), included: z.boolean(), trustGroup: z.string().trim().min(1).max(100).optional() })).max(200).default([]),
    remove: z.array(z.string().min(1).max(253)).max(200).default([]),
  })
  .refine((b) => b.add.length > 0 || b.remove.length > 0, { message: "Nothing to change." });

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Forbidden" });

  const body = parseBody(bodySchema, req.body, res);
  if (!body) return;

  const id = req.query.id;
  if (!isUuid(id)) return sendEngagementFailure(res, ROUTE, { status: "not_found" });

  const loaded = await loadEngagement(supabaseAdmin, id);
  if (loaded.status !== "ok") return sendEngagementFailure(res, ROUTE, loaded);
  if (loaded.data.state !== "booked" && loaded.data.state !== "scoped") {
    return res.status(409).json({ error: "Scope can't change once an engagement is authorised.", state: loaded.data.state });
  }

  const result = await applyScopeChanges(supabaseAdmin, loaded.data, adminId, body);
  if (result.status !== "ok") return sendEngagementFailure(res, ROUTE, result);
  return res.status(200).json(result.data);
}
