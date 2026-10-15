// GET /api/dmarc/reports — the caller's stored DMARC aggregate reports (E-66).
// Rows are written only by the ingest route (/api/dmarc/ingest) with the
// service role; this route only reads the owner's own. Before migration 060 it
// returns an empty list with available:false so the dashboard panel stays quiet.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { isMissingSchemaError } from "@/lib/dbErrors";

const MAX_ROWS = 100;
const SELECT =
  "id, domain, org_name, report_id, date_begin, date_end, total_messages, passing_messages, failing_messages, rows, received_at";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });

  const { data, error } = await supabaseAdmin
    .from("dmarc_reports")
    .select(SELECT)
    .eq("owner", caller.ownerId)
    .order("received_at", { ascending: false })
    .limit(MAX_ROWS);

  if (error) {
    if (isMissingSchemaError(error)) {
      return res.status(200).json({
        available: false,
        reports: [],
        note: "DMARC aggregate-report processing isn't enabled on this server yet (database migration 060 pending).",
      });
    }
    return res.status(500).json({ error: "Could not load DMARC reports" });
  }
  return res.status(200).json({ available: true, reports: data ?? [] });
}
