// /api/lookout/reports/<id> — one of the signed-in customer's reports.
//   GET  → { report, items, galleryScanId } (included items only, in priority
//          order; galleryScanId = the scan whose screenshots form the gallery)
//   POST { action: "acknowledge" } → records "I've read this report" once.
// Drafts and other customers' reports answer 404, so their existence isn't
// revealed. Acknowledging is not acceptance of any risk (OT-35 wording).
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { logAuditEvent } from "@/lib/audit";
import { parseBody } from "@/lib/validate";
import { canTransition, type ReportStatus } from "@/lib/lookoutReports";

const ackSchema = z.object({ action: z.literal("acknowledge") });

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  const id = String(req.query.id ?? "");

  const { data: report, error } = await supabaseAdmin
    .from("lookout_reports")
    .select("id, customer, period_start, period_end, status, summary, published_at, acknowledged_at")
    .eq("id", id)
    .maybeSingle();
  if (error) return respondInternalError(res, "lookout/reports/id", error);
  const row = report as { customer: string; status: ReportStatus } | null;
  if (!row || row.customer !== caller.ownerId || row.status === "draft") return res.status(404).json({ error: "Report not found" });

  if (req.method === "GET") {
    const { data: items, error: itemsError } = await supabaseAdmin
      .from("lookout_report_items")
      .select("id, host, check_id, severity, title, priority, analyst_note, business_impact, fix_owner")
      .eq("report_id", id)
      .eq("included", true)
      .order("priority", { ascending: true });
    if (itemsError) return respondInternalError(res, "lookout/reports/id", itemsError);
    const { customer: _customer, ...publicReport } = report as Record<string, unknown>;
    void _customer;
    // The scan whose host screenshots show as the report's estate gallery:
    // the latest completed one by the period's end (lookoutReportPdf.ts).
    const periodEnd = (report as { period_end: string }).period_end;
    const { data: scan } = await supabaseAdmin
      .from("scans")
      .select("id")
      .eq("owner", caller.ownerId)
      .eq("status", "completed")
      .lte("created_at", `${periodEnd}T23:59:59Z`)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    return res.status(200).json({ report: publicReport, items: items ?? [], galleryScanId: (scan as { id: string } | null)?.id ?? null });
  }

  if (req.method === "POST") {
    if (caller.via !== "session") return res.status(403).json({ error: "Reports are acknowledged from a logged-in session." });
    const body = parseBody(ackSchema, req.body, res);
    if (!body) return;
    if (row.status === "acknowledged") return res.status(200).json({ acknowledged: true });
    if (!canTransition(row.status, "acknowledged", "customer")) return res.status(409).json({ error: "This report can't be acknowledged." });
    const now = new Date().toISOString();
    const { error: ackError } = await supabaseAdmin.from("lookout_reports").update({ status: "acknowledged", acknowledged_at: now, acknowledged_by: caller.ownerId }).eq("id", id).eq("status", "published");
    if (ackError) return respondInternalError(res, "lookout/reports/id", ackError);
    await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "lookout_report.acknowledged", resourceType: "lookout_report", resourceId: id, metadata: {} });
    return res.status(200).json({ acknowledged: true, acknowledged_at: now });
  }

  res.setHeader("Allow", "GET, POST");
  return res.status(405).json({ error: "Method not allowed" });
}
