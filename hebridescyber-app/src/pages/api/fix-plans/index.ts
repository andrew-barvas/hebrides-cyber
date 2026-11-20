// /api/fix-plans — shared fix plans the owner manages (src/lib/fixPlans.ts,
// migration 083). Agency plan and above.
//   GET  ?host=<host>  → { plans: [{ id, title, host, createdAt, expiresAt, revokedAt, progress }] }
//   POST { scanId, checkIds, title?, expiresInDays? } → { id, url, expiresAt }
//        The link is returned once; only its hash is kept.
// A team admin or developer can act for the owner (teamAccess.ts), as with
// retest; the plan always belongs to the scan's owner.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { logAuditEvent } from "@/lib/audit";
import { hostOf } from "@/lib/findingLifecycle";
import { planGate } from "@/lib/planAccess";
import { callerCanActFor } from "@/lib/teamAccess";
import { parseBody } from "@/lib/validate";
import type { Finding } from "@/lib/scanners";
import {
  PLAN_MAX_ITEMS,
  PLAN_TTL_DAYS_DEFAULT,
  PLAN_TTL_DAYS_MAX,
  REMEDIATION_MAX,
  buildPublicPlan,
  loadResolutions,
  newPlanToken,
  planUrl,
  type PlanItemRow,
  type PlanRow,
} from "@/lib/fixPlans";

const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

const createSchema = z.object({
  scanId: z.string().uuid(),
  checkIds: z.array(z.string().min(1).max(300)).min(1).max(PLAN_MAX_ITEMS),
  title: z.string().trim().max(200).optional(),
  expiresInDays: z.number().int().min(1).max(PLAN_TTL_DAYS_MAX).optional(),
});

async function agencyGate(res: NextApiResponse, owner: string): Promise<boolean> {
  const gate = await planGate(supabaseAdmin, owner, "agency");
  if (gate === "error") {
    respondInternalError(res, "fix-plans", new Error("plan lookup failed"));
    return false;
  }
  if (gate === "denied") {
    res.status(403).json({ error: "Shared fix plans are on the Agency plan." });
    return false;
  }
  return true;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  if (req.method === "GET") {
    if (!(await agencyGate(res, caller.ownerId))) return;
    const host = typeof req.query.host === "string" ? req.query.host.toLowerCase() : null;
    let query = supabaseAdmin
      .from("fix_plans")
      .select("id, owner, target_host, title, created_at, expires_at, revoked_at")
      .eq("owner", caller.ownerId)
      .order("created_at", { ascending: false })
      .limit(50);
    if (host) query = query.eq("target_host", host);
    const { data: plans, error } = await query;
    if (error) return respondInternalError(res, "fix-plans", error);

    const rows = (plans ?? []) as PlanRow[];
    const out = [];
    for (const plan of rows) {
      const { data: items } = await supabaseAdmin
        .from("fix_plan_items")
        .select("check_id, position, severity, title, remediation, client_done_at, client_note")
        .eq("plan_id", plan.id);
      const list = (items ?? []) as PlanItemRow[];
      const resolved = await loadResolutions(supabaseAdmin, plan.owner, plan.target_host, list.map((i) => i.check_id));
      const view = buildPublicPlan(plan, list, resolved);
      out.push({ id: plan.id, title: view.title, host: plan.target_host, createdAt: plan.created_at, expiresAt: plan.expires_at, revokedAt: plan.revoked_at, progress: view.progress });
    }
    return res.status(200).json({ plans: out });
  }

  if (req.method === "POST") {
    const body = parseBody(createSchema, req.body, res);
    if (!body) return;

    const { data: scan, error: scanError } = await supabaseAdmin.from("scans").select("id, owner, target_url").eq("id", body.scanId).maybeSingle();
    if (scanError) return respondInternalError(res, "fix-plans", scanError);
    if (!scan) return res.status(404).json({ error: "Scan not found" });
    if (scan.owner !== caller.ownerId && !(await callerCanActFor(supabaseAdmin, caller.ownerId, scan.owner))) return res.status(403).json({ error: "Forbidden" });
    if (!(await agencyGate(res, scan.owner))) return;

    const host = hostOf(scan.target_url);
    if (!host) return res.status(400).json({ error: "This scan has no site to plan for." });

    const { data: result, error: resultError } = await supabaseAdmin.from("scan_results").select("results").eq("scan_id", scan.id).order("created_at", { ascending: false }).limit(1).maybeSingle();
    if (resultError) return respondInternalError(res, "fix-plans", resultError);
    const findings = (((result?.results as { findings?: Finding[] } | null)?.findings ?? []) as Finding[]).filter((f) => f.checkId);
    const byId = new Map(findings.map((f) => [f.checkId as string, f]));

    const ids = [...new Set(body.checkIds)];
    const missing = ids.filter((id) => !byId.has(id));
    if (missing.length) return res.status(400).json({ error: `Not on this scan: ${missing.slice(0, 5).join(", ")}` });

    const { token, hash } = newPlanToken();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + (body.expiresInDays ?? PLAN_TTL_DAYS_DEFAULT) * 24 * 60 * 60 * 1000).toISOString();
    const { data: plan, error: planError } = await supabaseAdmin
      .from("fix_plans")
      .insert({ owner: scan.owner, target_host: host, source_scan_id: scan.id, title: body.title ?? "", token_hash: hash, created_by: caller.ownerId, expires_at: expiresAt })
      .select("id")
      .single();
    if (planError || !plan) return respondInternalError(res, "fix-plans", planError ?? new Error("no plan row"), { publicMessage: "Couldn't create the plan." });

    const items = ids.map((id, i) => {
      const f = byId.get(id) as Finding;
      return {
        plan_id: (plan as { id: string }).id,
        check_id: id,
        position: i + 1,
        severity: SEVERITIES.has(f.severity) ? f.severity : "info",
        title: (f.title ?? id).slice(0, 500),
        remediation: typeof f.remediation === "string" ? f.remediation.slice(0, REMEDIATION_MAX) : "",
      };
    });
    const { error: itemsError } = await supabaseAdmin.from("fix_plan_items").insert(items);
    if (itemsError) {
      await supabaseAdmin.from("fix_plans").delete().eq("id", (plan as { id: string }).id);
      return respondInternalError(res, "fix-plans", itemsError, { publicMessage: "Couldn't create the plan." });
    }

    await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "fix_plan.created", resourceType: "fix_plan", resourceId: (plan as { id: string }).id, metadata: { host, items: items.length } });
    return res.status(201).json({ id: (plan as { id: string }).id, url: planUrl(token), expiresAt });
  }

  res.setHeader("Allow", "GET, POST");
  return res.status(405).json({ error: "Method not allowed" });
}
