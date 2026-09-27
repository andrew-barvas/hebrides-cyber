// Public report viewing — GET /api/reports/{token}. No auth: the token
// itself is the credential, the same trust model as a Google Docs "anyone
// with the link" share. Mirrors src/pages/api/badge/[scanId].ts's approach —
// service-role client, explicit validity check, never a public RLS policy
// (see sql/migrations/006_report_shares.sql for why that would leak tokens).
import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/supabaseAdmin";
import { buildScanReport, findPreviousFindings, pendingScanReport } from "@/lib/scanReport";
import { isExpired } from "@/lib/reportShares";
import { logAuditEvent } from "@/lib/audit";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";

// Per viewer IP. Plenty for someone reading a report someone shared with
// them; also caps how fast any one client can probe for valid tokens.
const SHARED_REPORT_RATE_LIMIT = { max: 120, windowSeconds: 60 * 60 };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const limit = await checkRateLimit(getClientIp(req), "shared-report", SHARED_REPORT_RATE_LIMIT);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many requests — try again later." });
  }

  const token = req.query.token as string;

  let share: { id: string; scan_id: string; expires_at: string | null; revoked_at: string | null; view_count: number } | null = null;
  try {
    const { data } = await supabaseAdmin
      .from("report_shares")
      .select("id, scan_id, expires_at, revoked_at, view_count")
      .eq("token", token)
      .maybeSingle();
    share = data;
  } catch {
    return res.status(404).json({ error: "This share link is invalid or has expired." });
  }

  if (!share || share.revoked_at || isExpired(share.expires_at)) {
    return res.status(404).json({ error: "This share link is invalid or has expired." });
  }

  // Best-effort, fire-and-forget — a failed view-count write must never turn
  // a valid share link into a 500 for the person trying to view it. A stray
  // simultaneous view landing on the same pre-increment count is an
  // acceptable miss for a "how many times has this been opened" counter, not
  // something worth a database function/transaction to make exact.
  // .then(), not `void`: a PostgREST builder only sends its request from
  // then(), so `void builder` never ran and view_count never moved.
  supabaseAdmin
    .from("report_shares")
    .update({ view_count: share.view_count + 1 })
    .eq("id", share.id)
    .then(undefined, () => {});

  // No authenticated actor for a public link — actorId stays null. Logged
  // per-view rather than folded into view_count's aggregate counter because
  // this is the one audit-worthy action in the whole app with no
  // authenticated actor at all: knowing *when* an externally-reachable
  // report was opened is what an incident review would actually want.
  void logAuditEvent(supabaseAdmin, {
    action: "share_link.viewed",
    resourceType: "scan",
    resourceId: share.scan_id,
    metadata: { share_id: share.id },
  });

  const { data: scan } = await supabaseAdmin
    .from("scans")
    .select("id, owner, target_url, status, created_at")
    .eq("id", share.scan_id)
    .maybeSingle();

  if (!scan) return res.status(404).json({ error: "This share link is invalid or has expired." });

  const { data: result } = await supabaseAdmin
    .from("scan_results")
    .select("results, summary, score, created_at")
    .eq("scan_id", scan.id)
    .maybeSingle();

  if (!result) return res.status(200).json(pendingScanReport(scan));

  const previous = await findPreviousFindings(supabaseAdmin, scan.owner, scan.id, scan.target_url, scan.created_at);
  return res.status(200).json(buildScanReport(scan, result, previous));
}
