// GET/PUT /api/account/sla — remediation SLAs (Agency; admins exempt).
//
// GET: the account's policy plus where every open finding stands against it,
// and time-to-fix over findings resolved in the last 90 days — computed by
// slaMonitoring.ts from finding_lifecycle, which the scan worker maintains.
// PUT: replace the policy (targets per severity, warning window, alerts).
//
// Before migration 043 GET reports `available: false` rather than failing,
// so the page can say what's missing; PUT returns 503.
//
// Findings with an active triage (accepted risk / false positive / snooze,
// findingTriage.ts) are out of SLA tracking and counted in summary.triaged
// instead. Before migration 046 nothing is triaged.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { clientParam, resolveClientScope } from "@/lib/clientScope";
import { buildTriageIndex, loadTriageForOwner } from "@/lib/findingTriage";
import { hasSlaAccess } from "@/lib/slaAlerts";
import { DEFAULT_SLA_POLICY, buildSlaSummary, policyFromRow, type LifecycleRow, type SlaPolicyRow } from "@/lib/slaMonitoring";
import { parseBody } from "@/lib/validate";

const RESOLVED_WINDOW_DAYS = 90;
/** Enough for any real portfolio; keeps one pathological account's payload bounded. */
const MAX_ITEMS = 500;

const days = z.number().int().min(1, "must be at least 1 day").max(365, "must be 365 days or fewer");
const putSchema = z.object({
  days: z.object({ critical: days, high: days, medium: days, low: days }),
  warnDays: z.number().int().min(0).max(30),
  alertsEnabled: z.boolean(),
});

const LIFECYCLE_SELECT = "id, target_host, check_id, severity, title, first_seen_at, last_seen_at, resolved_at";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "PUT") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });

  if (!(await hasSlaAccess(supabaseAdmin, caller.ownerId))) {
    if (req.method === "PUT") return res.status(403).json({ error: "Remediation SLAs are part of the Agency plan." });
    return res.status(200).json({ access: false, available: true, policy: DEFAULT_SLA_POLICY, summary: null });
  }

  if (req.method === "PUT") {
    const parsed = parseBody(putSchema, req.body, res);
    if (!parsed) return;
    const row = {
      owner: caller.ownerId,
      critical_days: parsed.days.critical,
      high_days: parsed.days.high,
      medium_days: parsed.days.medium,
      low_days: parsed.days.low,
      warn_days: parsed.warnDays,
      alerts_enabled: parsed.alertsEnabled,
      updated_at: new Date().toISOString(),
    };
    const { error } = await supabaseAdmin.from("sla_policies").upsert(row, { onConflict: "owner" });
    if (error) {
      if (isMissingSchemaError(error)) {
        return res.status(503).json({ error: "SLA tracking isn't enabled on this server yet (database migration 043 pending)." });
      }
      return res.status(500).json({ error: "Could not save the SLA policy" });
    }
    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "sla_policy.updated",
      resourceType: "sla_policy",
      resourceId: caller.ownerId,
      metadata: { days: parsed.days, warn_days: parsed.warnDays, alerts_enabled: parsed.alertsEnabled },
    });
    return res.status(200).json({ policy: policyFromRow(row) });
  }

  const since = new Date(Date.now() - RESOLVED_WINDOW_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const [policyResult, openResult, resolvedResult, triage] = await Promise.all([
    supabaseAdmin
      .from("sla_policies")
      .select("critical_days, high_days, medium_days, low_days, warn_days, alerts_enabled")
      .eq("owner", caller.ownerId)
      .maybeSingle(),
    supabaseAdmin.from("finding_lifecycle").select(LIFECYCLE_SELECT).eq("owner", caller.ownerId).is("resolved_at", null),
    supabaseAdmin.from("finding_lifecycle").select(LIFECYCLE_SELECT).eq("owner", caller.ownerId).gte("resolved_at", since),
    loadTriageForOwner(supabaseAdmin, caller.ownerId),
  ]);

  const error = policyResult.error ?? openResult.error ?? resolvedResult.error;
  if (error) {
    if (isMissingSchemaError(error)) {
      return res.status(200).json({ access: true, available: false, policy: DEFAULT_SLA_POLICY, summary: null });
    }
    return res.status(500).json({ error: "Could not load SLA status" });
  }
  // Unlike a missing table, a failed triage read can't be shown as "nothing
  // triaged": that would report accepted findings as breaching.
  if (triage.error) return res.status(500).json({ error: "Could not load SLA status" });

  const policy = policyFromRow(policyResult.data as SlaPolicyRow | null);
  let rows = [...(openResult.data ?? []), ...(resolvedResult.data ?? [])] as LifecycleRow[];
  // Optional ?client= scope: the policy stays account-wide, only the findings are narrowed.
  const client = clientParam(req.query.client);
  if (client) {
    const scope = await resolveClientScope(supabaseAdmin, caller.ownerId, client);
    if (!scope.ok) return res.status(scope.status).json({ error: scope.error });
    rows = rows.filter((r) => scope.hosts.has(r.target_host));
  }
  const now = new Date();
  const summary = buildSlaSummary(rows, policy, now, buildTriageIndex(triage.rows, now));
  return res.status(200).json({
    access: true,
    available: true,
    policy,
    resolvedWindowDays: RESOLVED_WINDOW_DAYS,
    summary: { ...summary, items: summary.items.slice(0, MAX_ITEMS), truncated: summary.items.length > MAX_ITEMS },
  });
}
