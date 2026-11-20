// PUT /api/engagements/{id}/windows — set an engagement's testing windows: slots
// inside the overall window (say, 09:00 to 17:00 on each agreed day). When any are
// set, active work may run only inside one of them. With none, the overall window
// is the only limit. Replaces the whole list, while the engagement is still booked
// or scoped. Admin session only. Sends nothing to any target.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { logAuditEvent } from "@/lib/audit";
import { checkTestingWindows, isEditableState, loadEngagement, replaceTestingWindows, sendEngagementFailure } from "@/lib/engagements";
import { isUuid } from "@/lib/exploitabilityApi";
import { parseBody } from "@/lib/validate";

const ROUTE = "engagements/[id]/windows";

const bodySchema = z.object({
  windows: z.array(z.object({ startsAt: z.string().datetime(), endsAt: z.string().datetime() })).max(100),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "PUT") {
    res.setHeader("Allow", "PUT");
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
  if (!isEditableState(loaded.data.state)) {
    return res.status(409).json({ error: "Testing windows can't change once an engagement is authorised.", state: loaded.data.state });
  }

  const problem = checkTestingWindows(loaded.data, body.windows);
  if (problem) {
    const error =
      problem.problem === "window_not_set" ? "Set the engagement's overall window first." : problem.problem === "end_before_start" ? "Each testing window must end after it starts." : "Each testing window must sit inside the engagement's overall window.";
    return res.status(400).json({ error, reason: problem.problem, index: problem.index });
  }

  const result = await replaceTestingWindows(supabaseAdmin, loaded.data, adminId, body.windows);
  if (result.status !== "ok") return sendEngagementFailure(res, ROUTE, result);

  await logAuditEvent(supabaseAdmin, { actorId: adminId, action: "engagement.windows_updated", resourceType: "engagement", resourceId: id, metadata: { count: result.data.length } });
  return res.status(200).json({ windows: result.data });
}
