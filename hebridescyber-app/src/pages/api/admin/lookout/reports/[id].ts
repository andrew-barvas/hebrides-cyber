// /api/admin/lookout/reports/<id> — read and edit one report (migration 075).
//   GET   → { report, items }
//   PATCH { summary?, items?: [{ id, included?, priority?, analyst_note?,
//           business_impact?, fix_owner? }], status?: "published" | "draft" }
// A published report can go back to draft (to correct it) until the customer
// has acknowledged it; after that it is frozen. Admins only.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { logAuditEvent } from "@/lib/audit";
import { parseBody } from "@/lib/validate";
import { canTransition, FIX_OWNERS, type ReportStatus } from "@/lib/lookoutReports";

const itemSchema = z.object({
  id: z.string().uuid(),
  included: z.boolean().optional(),
  priority: z.number().int().min(1).max(1000).optional(),
  analyst_note: z.string().max(5000).optional(),
  business_impact: z.string().max(2000).optional(),
  fix_owner: z.enum(FIX_OWNERS).optional(),
});
const patchSchema = z.object({
  summary: z.string().max(20000).optional(),
  items: z.array(itemSchema).max(200).optional(),
  status: z.enum(["published", "draft"]).optional(),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });
  const id = String(req.query.id ?? "");

  const { data: report, error } = await supabaseAdmin.from("lookout_reports").select("*").eq("id", id).maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  if (!report) return res.status(404).json({ error: "Report not found" });
  const current = (report as { status: ReportStatus }).status;

  if (req.method === "GET") {
    const { data: items, error: itemsError } = await supabaseAdmin.from("lookout_report_items").select("*").eq("report_id", id).order("priority", { ascending: true });
    if (itemsError) return res.status(500).json({ error: itemsError.message });
    return res.status(200).json({ report, items: items ?? [] });
  }

  if (req.method === "PATCH") {
    const body = parseBody(patchSchema, req.body, res);
    if (!body) return;
    if (current === "acknowledged") return res.status(409).json({ error: "The customer has acknowledged this report, so it can't be changed. Start a new one." });
    if (body.status && body.status !== current && !canTransition(current, body.status, "admin")) {
      return res.status(409).json({ error: `A ${current} report can't move to ${body.status}.` });
    }
    for (const item of body.items ?? []) {
      const { id: itemId, ...changes } = item;
      if (Object.keys(changes).length === 0) continue;
      const { error: itemError } = await supabaseAdmin.from("lookout_report_items").update(changes).eq("id", itemId).eq("report_id", id);
      if (itemError) return res.status(500).json({ error: itemError.message });
    }
    const update: Record<string, unknown> = { updated_at: new Date().toISOString() };
    if (body.summary !== undefined) update.summary = body.summary;
    if (body.status && body.status !== current) {
      update.status = body.status;
      update.published_at = body.status === "published" ? new Date().toISOString() : null;
    }
    const { data: saved, error: saveError } = await supabaseAdmin.from("lookout_reports").update(update).eq("id", id).select("*").single();
    if (saveError) return res.status(500).json({ error: saveError.message });
    if (body.status && body.status !== current) {
      await logAuditEvent(supabaseAdmin, { actorId: adminId, action: body.status === "published" ? "lookout_report.published" : "lookout_report.unpublished", resourceType: "lookout_report", resourceId: id, metadata: { customer: (report as { customer: string }).customer } });
    }
    return res.status(200).json({ report: saved });
  }

  res.setHeader("Allow", "GET, PATCH");
  return res.status(405).json({ error: "Method not allowed" });
}
