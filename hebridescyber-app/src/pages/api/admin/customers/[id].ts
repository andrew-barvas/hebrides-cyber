// Admin: read-only customer detail for support — profile, subscription and
// recent scans in one call. Logged as admin.customer_viewed on every read,
// since this surfaces another customer's account data to an admin.
//
// This is deliberately NOT session impersonation: the admin's own Supabase
// session is untouched, and every read here goes through the service-role
// client rather than borrowing the customer's RLS-scoped session. Minting a
// real session as another user (or threading a "viewing as" identity through
// every RLS-gated client-side query across the dashboard) was considered and
// rejected as unnecessary risk for what support actually needs: a consolidated,
// read-only view of one customer's account.
import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { logAuditEvent } from "@/lib/audit";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  if (req.method !== "GET") return res.status(405).end();

  const ownerId = typeof req.query.id === "string" ? req.query.id : null;
  if (!ownerId) return res.status(400).json({ error: "id is required" });

  const [userRes, subRes, scansRes, scanCountRes] = await Promise.all([
    supabaseAdmin.from("users").select("id, email, company_name, is_admin, created_at").eq("id", ownerId).maybeSingle(),
    supabaseAdmin
      .from("subscriptions")
      .select("plan, status, source, granted_by, grant_reason, stripe_customer_id, updated_at")
      .eq("owner", ownerId)
      .maybeSingle(),
    supabaseAdmin
      .from("scans")
      .select("id, target_url, status, created_at, scan_results(score)")
      .eq("owner", ownerId)
      .order("created_at", { ascending: false })
      .limit(20),
    supabaseAdmin.from("scans").select("id", { count: "exact", head: true }).eq("owner", ownerId),
  ]);

  if (userRes.error) return res.status(500).json({ error: userRes.error.message });
  if (!userRes.data) return res.status(404).json({ error: "Customer not found" });
  if (subRes.error) return res.status(500).json({ error: subRes.error.message });
  if (scansRes.error) return res.status(500).json({ error: scansRes.error.message });

  const scans = (scansRes.data ?? []).map((s) => {
    const result = Array.isArray(s.scan_results) ? s.scan_results[0] : s.scan_results;
    return {
      id: s.id,
      targetUrl: s.target_url,
      status: s.status,
      score: result?.score ?? null,
      createdAt: s.created_at,
    };
  });

  await logAuditEvent(supabaseAdmin, {
    actorId: adminId,
    action: "admin.customer_viewed",
    resourceType: "user",
    resourceId: ownerId,
  });

  return res.status(200).json({
    user: userRes.data,
    subscription: subRes.data ?? null,
    scans,
    scanCount: scanCountRes.count ?? 0,
  });
}
