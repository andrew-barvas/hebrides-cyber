// Admin: email deliverability. Summarises recent email_events (migration
// 056) — a send count and failure rate over a trailing window, plus the
// latest failures — so a spell of bouncing/rejected mail is visible instead
// of only living in console logs. Read-only.
import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { summarizeEmailHealth, type EmailEventRow } from "@/lib/emailEvents";

const WINDOW_HOURS = 24;

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  const sinceIso = new Date(Date.now() - WINDOW_HOURS * 3_600_000).toISOString();
  const { data, error } = await supabaseAdmin
    .from("email_events")
    .select("status, subject, recipient_domain, error, created_at")
    .gte("created_at", sinceIso)
    .order("created_at", { ascending: false })
    .limit(1000);
  if (error) return res.status(500).json({ error: error.message });

  return res.status(200).json(summarizeEmailHealth((data as EmailEventRow[]) ?? [], new Date(), WINDOW_HOURS));
}
