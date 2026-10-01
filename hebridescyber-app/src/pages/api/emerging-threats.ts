// GET /api/emerging-threats — the caller's emerging-threat alerts: newly
// exploited CVEs (CISA KEV) that matched a technology and version their
// latest scan saw. Rows are written only by the scheduled job
// (src/scripts/check-emerging-threats.ts); this route only reads.
//
// Before migration 045 it returns an empty list with `available: false`
// rather than failing, so the dashboard panel can stay quiet.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { isMissingSchemaError } from "@/lib/dbErrors";

const MAX_ROWS = 100;
const SELECT = "id, target_host, cve_id, confidence, product, detected_version, kev_date_added, scan_id, matched_at, notified_at";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });

  const { data, error } = await supabaseAdmin
    .from("emerging_threat_alerts")
    .select(SELECT)
    .eq("owner", caller.ownerId)
    .order("matched_at", { ascending: false })
    .limit(MAX_ROWS);

  if (error) {
    if (isMissingSchemaError(error)) {
      return res.status(200).json({
        available: false,
        alerts: [],
        note: "Emerging-threat alerts aren't enabled on this server yet (database migration 045 pending).",
      });
    }
    return res.status(500).json({ error: "Could not load emerging-threat alerts" });
  }
  return res.status(200).json({ available: true, alerts: data ?? [] });
}
