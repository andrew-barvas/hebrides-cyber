// /api/admin/lookout/reports — Lookout analyst reports (migration 075).
//   GET  ?customer=<email or id>   → { reports } (newest first), each with
//        customer_email for display
//   POST { customer, period_days }  → { report } a draft, pre-filled from the
//        customer's ranking and the period's drift (lookoutReports.ts).
//        `customer` is their sign-up email or user id (lookoutCustomer.ts).
// Admins only (requireAdmin). Admin routes keep raw error text on purpose
// (CLAUDE.md rule 31).
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { logAuditEvent } from "@/lib/audit";
import { parseBody } from "@/lib/validate";
import { loadDraftInputs } from "@/lib/lookoutReports";
import { customerEmails, resolveLookoutCustomer } from "@/lib/lookoutCustomer";

const createSchema = z.object({
  customer: z.string().trim().min(3).max(320),
  period_days: z.union([z.literal(7), z.literal(30), z.literal(90)]).default(30),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  if (req.method === "GET") {
    const input = String(req.query.customer ?? "").trim();
    let query = supabaseAdmin.from("lookout_reports").select("id, customer, period_start, period_end, status, published_at, acknowledged_at, created_at").order("created_at", { ascending: false }).limit(100);
    if (input) {
      const found = await resolveLookoutCustomer(supabaseAdmin, input);
      if (!found.ok) return found.status === 404 ? res.status(200).json({ reports: [] }) : res.status(found.status).json({ error: found.error });
      query = query.eq("customer", found.customer.id);
    }
    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    const rows = (data ?? []) as Array<{ customer: string }>;
    const emails = await customerEmails(supabaseAdmin, rows.map((r) => r.customer));
    return res.status(200).json({ reports: rows.map((r) => ({ ...r, customer_email: emails.get(r.customer) ?? null })) });
  }

  if (req.method === "POST") {
    const body = parseBody(createSchema, req.body, res);
    if (!body) return;
    const found = await resolveLookoutCustomer(supabaseAdmin, body.customer);
    if (!found.ok) return res.status(found.status).json({ error: found.error });
    const customer = found.customer.id;
    const end = new Date();
    const start = new Date(end.getTime() - body.period_days * 86_400_000);
    const { items, summary } = await loadDraftInputs(supabaseAdmin, customer, body.period_days);
    const { data: report, error } = await supabaseAdmin
      .from("lookout_reports")
      .insert({ customer, period_start: start.toISOString().slice(0, 10), period_end: end.toISOString().slice(0, 10), summary, created_by: adminId })
      .select("id, customer, period_start, period_end, status, summary")
      .single();
    if (error || !report) return res.status(500).json({ error: error?.message ?? "Could not create the report" });
    if (items.length > 0) {
      const { error: itemsError } = await supabaseAdmin.from("lookout_report_items").insert(items.map((i) => ({ ...i, report_id: (report as { id: string }).id })));
      if (itemsError) return res.status(500).json({ error: itemsError.message });
    }
    await logAuditEvent(supabaseAdmin, { actorId: adminId, action: "lookout_report.created", resourceType: "lookout_report", resourceId: (report as { id: string }).id, metadata: { customer, items: items.length } });
    return res.status(201).json({ report, items: items.length });
  }

  res.setHeader("Allow", "GET, POST");
  return res.status(405).json({ error: "Method not allowed" });
}
