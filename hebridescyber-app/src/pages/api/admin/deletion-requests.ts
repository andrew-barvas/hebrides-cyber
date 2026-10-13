// Admin: GDPR erasure queue. Read-only view of pending deletion requests
// (/privacy promises erasure within 30 days — migration 048's
// deletion_requests table tracks the deadline). Deliberately read-only: the
// erasure itself stays a deliberate operator step (src/scripts/erase-user-data.ts
// → accountErasure.ts), not a one-click web button, because it is
// irreversible and cross-table. This view is the "what's owed, and how
// urgently" that the daily reminder email also covers, now visible on demand.
import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { summarizeDeletionQueue, type DeletionRequestRow } from "@/lib/accountErasure";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  const { data, error } = await supabaseAdmin
    .from("deletion_requests")
    .select("id, owner, status, requested_at, due_at, reminded_at")
    .eq("status", "pending");
  if (error) return res.status(500).json({ error: error.message });

  const { overdueCount, pending } = summarizeDeletionQueue((data as DeletionRequestRow[]) ?? [], new Date());

  // Attach each owner's email so support can identify the account. owner
  // references auth.users, so this is a separate lookup against public.users
  // (no PostgREST embed path), and a now-dangling owner (already erased but
  // somehow still pending) simply shows no email rather than failing.
  const owners = [...new Set(pending.map((p) => p.owner))];
  const emailByOwner = new Map<string, string>();
  if (owners.length > 0) {
    const { data: users } = await supabaseAdmin.from("users").select("id, email").in("id", owners);
    for (const u of (users as { id: string; email: string | null }[] | null) ?? []) {
      if (u.email) emailByOwner.set(u.id, u.email);
    }
  }

  return res.status(200).json({
    overdueCount,
    requests: pending.map((p) => ({ ...p, email: emailByOwner.get(p.owner) ?? null })),
  });
}
