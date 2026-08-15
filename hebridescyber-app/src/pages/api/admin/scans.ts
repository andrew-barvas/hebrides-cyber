import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  // GET  /api/admin/scans?status=&search=&page=
  if (req.method === "GET") {
    const status = typeof req.query.status === "string" ? req.query.status : undefined;
    const search = typeof req.query.search === "string" ? req.query.search.trim() : "";
    const page = Math.max(1, parseInt(typeof req.query.page === "string" ? req.query.page : "1", 10));
    const pageSize = 50;
    const offset = (page - 1) * pageSize;

    let query = supabaseAdmin
      .from("scans")
      .select("id, owner, target_url, status, created_at, owner_verified, job_id, scan_results(score, summary)")
      .order("created_at", { ascending: false })
      .range(offset, offset + pageSize - 1);

    if (status) query = query.eq("status", status);
    if (search) query = query.ilike("target_url", `%${search}%`);

    const { data: scans, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    // Resolve owner emails in one batch query.
    const ownerIds = [...new Set((scans ?? []).map((s) => s.owner))];
    const { data: users } = await supabaseAdmin
      .from("users")
      .select("id, email, company_name")
      .in("id", ownerIds);
    const userMap = new Map((users ?? []).map((u) => [u.id, u]));

    const enriched = (scans ?? []).map((s) => {
      const user = userMap.get(s.owner);
      const result = Array.isArray(s.scan_results) ? s.scan_results[0] : s.scan_results;
      return {
        id: s.id,
        ownerEmail: user?.email ?? s.owner,
        ownerCompany: user?.company_name ?? null,
        targetUrl: s.target_url,
        status: s.status,
        score: result?.score ?? null,
        summary: result?.summary ?? null,
        ownerVerified: s.owner_verified,
        jobId: s.job_id ?? null,
        createdAt: s.created_at,
      };
    });

    return res.status(200).json({ scans: enriched, page, pageSize });
  }

  // PATCH /api/admin/scans — retry or cancel a scan
  if (req.method === "PATCH") {
    const { scanId, action } = req.body as { scanId?: string; action?: "cancel" | "retry" };
    if (!scanId || !action) return res.status(400).json({ error: "scanId and action required" });
    if (action === "cancel") {
      await supabaseAdmin.from("scans").update({ status: "failed" }).eq("id", scanId);
      return res.status(200).json({ ok: true });
    }
    if (action === "retry") {
      await supabaseAdmin.from("scans").update({ status: "pending" }).eq("id", scanId);
      return res.status(200).json({ ok: true });
    }
    return res.status(400).json({ error: "Unknown action" });
  }

  return res.status(405).end();
}
