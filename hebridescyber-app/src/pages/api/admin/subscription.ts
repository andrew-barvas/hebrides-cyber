// Admin: manually grant or change a customer's plan without going through
// Stripe (comps, pilots, support goodwill credits). Writes subscriptions.plan
// directly, tagged source="admin" so the row is visibly distinct from a
// Stripe-paid one — see migration 052. A later real Stripe checkout for the
// same owner still overwrites plan/status/source back to "stripe": a real
// payment supersedes a manual grant, not the other way round.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { logAuditEvent } from "@/lib/audit";
import { parseBody } from "@/lib/validate";

const patchSchema = z.object({
  ownerId: z.string().uuid(),
  plan: z.enum(["basic", "pro", "agency", "tier_a"]),
  status: z.enum(["inactive", "active", "past_due", "cancelled"]),
  reason: z.string().trim().min(1, "reason is required").max(500),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  if (req.method !== "PATCH") return res.status(405).end();

  const parsed = parseBody(patchSchema, req.body, res);
  if (!parsed) return;
  const { ownerId, plan, status, reason } = parsed;

  const { data: owner, error: ownerError } = await supabaseAdmin
    .from("users")
    .select("id")
    .eq("id", ownerId)
    .maybeSingle();
  if (ownerError) return res.status(500).json({ error: ownerError.message });
  if (!owner) return res.status(404).json({ error: "Customer not found" });

  const { error } = await supabaseAdmin.from("subscriptions").upsert(
    {
      owner: ownerId,
      plan,
      status,
      source: "admin",
      granted_by: adminId,
      grant_reason: reason,
      updated_at: new Date().toISOString(),
    },
    { onConflict: "owner" }
  );
  if (error) return res.status(500).json({ error: error.message });

  await logAuditEvent(supabaseAdmin, {
    actorId: adminId,
    action: "admin.subscription_overridden",
    resourceType: "subscription",
    resourceId: ownerId,
    metadata: { plan, status, reason },
  });

  return res.status(200).json({ ok: true });
}
