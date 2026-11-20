// DELETE /api/fix-plans/<id> — revoke a shared fix plan's link at once. The
// plan stays (so the audit trail and progress remain) but the link stops
// working. Owner only.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { logAuditEvent } from "@/lib/audit";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "DELETE") {
    res.setHeader("Allow", "DELETE");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  const id = String(req.query.id ?? "");
  if (!/^[0-9a-f-]{36}$/i.test(id)) return res.status(404).json({ error: "Plan not found" });

  const { data, error } = await supabaseAdmin
    .from("fix_plans")
    .update({ revoked_at: new Date().toISOString() })
    .eq("id", id)
    .eq("owner", caller.ownerId)
    .is("revoked_at", null)
    .select("id");
  if (error) return respondInternalError(res, "fix-plans/id", error);
  if (!data || data.length === 0) {
    const { data: existing } = await supabaseAdmin.from("fix_plans").select("id").eq("id", id).eq("owner", caller.ownerId).maybeSingle();
    if (!existing) return res.status(404).json({ error: "Plan not found" });
    return res.status(200).json({ revoked: true });
  }
  await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "fix_plan.revoked", resourceType: "fix_plan", resourceId: id, metadata: {} });
  return res.status(200).json({ revoked: true });
}
