import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { logAuditEvent } from "@/lib/audit";
import { triggerOnDemandWorkflow } from "@/lib/onDemandScanTrigger";
import { parseBody } from "@/lib/validate";

const patchSchema = z.object({
  scanId: z.string().min(1, "scanId is required"),
  action: z.enum(["cancel", "retry"]),
});

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
    const parsed = parseBody(patchSchema, req.body, res);
    if (!parsed) return;
    const { scanId, action } = parsed;

    // Jobs link to scans via scan_jobs.scan_id. (scans.job_id is a leftover
    // from the deleted BullMQ worker — nothing writes it, so keying on it
    // meant cancel/retry never reached the job at all.)
    if (action === "cancel") {
      await supabaseAdmin.from("scans").update({ status: "failed" }).eq("id", scanId);
      await supabaseAdmin
        .from("scan_jobs")
        .update({ status: "failed", last_error: "Cancelled by admin" })
        .eq("scan_id", scanId)
        .in("status", ["pending", "running"]);
      await logAuditEvent(supabaseAdmin, {
        actorId: adminId,
        action: "admin.scan_cancelled",
        resourceType: "scan",
        resourceId: scanId,
      });
      return res.status(200).json({ ok: true });
    }
    if (action === "retry") {
      await supabaseAdmin.from("scans").update({ status: "queued" }).eq("id", scanId);
      const { data: resetJobs } = await supabaseAdmin
        .from("scan_jobs")
        .update({ status: "pending", claimed_at: null, claimed_by: null, last_error: null })
        .eq("scan_id", scanId)
        .select("id");
      // A scan that failed before it was ever enqueued has no job to reset —
      // queue a fresh one, exactly as run-scan.ts does, or it would sit at
      // "queued" forever.
      if (!resetJobs?.length) {
        const { data: scanRow } = await supabaseAdmin.from("scans").select("owner, target_url").eq("id", scanId).maybeSingle();
        if (scanRow) {
          await supabaseAdmin.from("scan_jobs").insert({ owner: scanRow.owner, target_url: scanRow.target_url, scan_id: scanId, status: "pending" });
        }
      }
      // Pick it up now rather than at the next daily cron.
      await triggerOnDemandWorkflow();
      await logAuditEvent(supabaseAdmin, {
        actorId: adminId,
        action: "admin.scan_retried",
        resourceType: "scan",
        resourceId: scanId,
      });
      return res.status(200).json({ ok: true });
    }
    return res.status(400).json({ error: "Unknown action" });
  }

  return res.status(405).end();
}
