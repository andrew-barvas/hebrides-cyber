// GET/PUT/DELETE /api/findings/triage — finding triage (E-64): mark a
// finding as an accepted risk (or, for a third-party script, authorised), a
// false positive, or snoozed until a date, always with a reason; and Undo.
// Session or API key. What each state does is decided in
// src/lib/findingTriage.ts, not here.
//
// A finding is addressed by (site, checkId) — the identity scans, SLAs and
// ticketing already share — so a decision made from one scan's report holds
// for every later scan of that site. Name the site either as `targetHost`
// (on your own account) or as `scanId` (the scan's owner and site; a team
// admin/developer may triage on the owner's scans, as with retest and
// create-ticket). checkId is deliberately not checked against any scan's
// findings: triaging ahead of time is allowed, and any checkId works.
//
//   GET    ?host=<host> | ?scanId=<id> | neither (the whole account)
//   PUT    { targetHost|scanId, checkId, state, reason, expiresAt? }
//          or { items: [ ...up to 200 of those ] }
//   DELETE { targetHost|scanId, checkId } or { items: [...] }, or the same
//          as query parameters (host|scanId, checkId)
//
// Rows are written with the service role only (the table has an owner-
// SELECT policy and nothing else) and every write is audited. Before
// migration 046, GET answers { available: false, items: [] } and writes 503.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin, type ApiCaller } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { hostOf } from "@/lib/findingLifecycle";
import {
  TRIAGE_BULK_MAX,
  TRIAGE_COLUMNS,
  TRIAGE_REASON_MAX,
  TRIAGE_REASON_MIN,
  TRIAGE_STATES,
  expiryProblem,
  isTriageActive,
  loadTriageForHost,
  loadTriageForOwner,
  normaliseTriageHost,
  reasonLength,
  type TriageDbRow,
  type TriageRecord,
} from "@/lib/findingTriage";
import { callerCanActFor } from "@/lib/teamAccess";
import { parseBody } from "@/lib/validate";

const MIGRATION_PENDING = "Finding triage isn't enabled on this server yet (database migration 046 pending).";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const targetFields = {
  targetHost: z.string().max(2048).optional(),
  scanId: z.string().regex(UUID, "must be a scan id").optional(),
  checkId: z.string().trim().min(1, "is required").max(500),
};

type TargetInput = { targetHost?: string; scanId?: string; checkId: string };

function checkTarget(v: TargetInput, ctx: z.RefinementCtx) {
  if (Boolean(v.targetHost) === Boolean(v.scanId)) {
    ctx.addIssue({ code: "custom", path: ["targetHost"], message: "give exactly one of targetHost or scanId" });
  } else if (v.targetHost && !normaliseTriageHost(v.targetHost)) {
    ctx.addIssue({ code: "custom", path: ["targetHost"], message: "is not a valid host name" });
  }
}

const targetItem = z.object(targetFields).superRefine(checkTarget);

const triageItem = z
  .object({
    ...targetFields,
    state: z.enum(TRIAGE_STATES),
    reason: z.string().trim(),
    expiresAt: z.string().nullable().optional(),
  })
  .superRefine((v, ctx) => {
    checkTarget(v, ctx);
    const length = reasonLength(v.reason);
    if (length < TRIAGE_REASON_MIN) {
      ctx.addIssue({ code: "custom", path: ["reason"], message: `must be at least ${TRIAGE_REASON_MIN} characters` });
    } else if (length > TRIAGE_REASON_MAX) {
      ctx.addIssue({ code: "custom", path: ["reason"], message: `must be ${TRIAGE_REASON_MAX} characters or fewer` });
    }
    const problem = expiryProblem(v.state, v.expiresAt, new Date());
    if (problem) ctx.addIssue({ code: "custom", path: ["expiresAt"], message: problem });
  });

const bulk = <T extends z.ZodTypeAny>(item: T) =>
  z.object({
    items: z
      .array(item)
      .min(1, "must not be empty")
      .max(TRIAGE_BULK_MAX, `at most ${TRIAGE_BULK_MAX} per request`),
  });

type TriageItem = z.infer<typeof triageItem>;

type Failure = { status: number; error: string };
type Resolved = { owner: string; host: string };

function isBulk(body: unknown): boolean {
  return Boolean(body && typeof body === "object" && "items" in (body as Record<string, unknown>));
}

/**
 * Who owns, and which site is, each item's target — checking the caller may
 * act there. A scan the caller can't act on is a 403 for the whole request,
 * same as a missing one is a 404: a bulk request is all-or-nothing.
 */
async function resolveTargets(caller: ApiCaller, items: TargetInput[]): Promise<Resolved[] | Failure> {
  const scanIds = [...new Set(items.map((i) => i.scanId).filter((id): id is string => Boolean(id)))];
  const scans = new Map<string, { owner: string; target_url: string }>();
  if (scanIds.length > 0) {
    const { data, error } = await supabaseAdmin.from("scans").select("id, owner, target_url").in("id", scanIds);
    if (error) return { status: 500, error: "Could not look up the scans" };
    for (const s of (data ?? []) as Array<{ id: string; owner: string; target_url: string }>) scans.set(s.id, s);
  }

  const allowed = new Map<string, boolean>([[caller.ownerId, true]]);
  const resolved: Resolved[] = [];
  for (const item of items) {
    if (!item.scanId) {
      resolved.push({ owner: caller.ownerId, host: normaliseTriageHost(item.targetHost ?? "") as string });
      continue;
    }
    const scan = scans.get(item.scanId);
    if (!scan) return { status: 404, error: `Scan ${item.scanId} not found` };
    if (!allowed.has(scan.owner)) allowed.set(scan.owner, await callerCanActFor(supabaseAdmin, caller.ownerId, scan.owner));
    if (!allowed.get(scan.owner)) return { status: 403, error: "Forbidden" };
    const host = hostOf(scan.target_url);
    if (!host) return { status: 400, error: `Scan ${item.scanId} has no usable target URL` };
    resolved.push({ owner: scan.owner, host });
  }
  return resolved;
}

async function emailsFor(userIds: Array<string | null>): Promise<Map<string, string>> {
  const ids = [...new Set(userIds.filter((id): id is string => Boolean(id)))];
  const emails = new Map<string, string>();
  if (ids.length === 0) return emails;
  const { data } = await supabaseAdmin.from("users").select("id, email").in("id", ids);
  for (const u of (data ?? []) as Array<{ id: string; email: string | null }>) if (u.email) emails.set(u.id, u.email);
  return emails;
}

async function toRecords(rows: TriageDbRow[], now: Date): Promise<TriageRecord[]> {
  const emails = await emailsFor(rows.map((r) => r.created_by));
  return rows.map((r) => ({
    targetHost: r.target_host,
    checkId: r.check_id,
    state: r.state,
    reason: r.reason,
    expiresAt: r.expires_at,
    active: isTriageActive(r, now),
    triagedAt: r.updated_at,
    createdAt: r.created_at,
    triagedBy: r.created_by,
    triagedByEmail: r.created_by ? emails.get(r.created_by) ?? null : null,
  }));
}

const auditSummary = (r: Resolved & { check_id: string; state?: string; reason?: string; expires_at?: string | null }) => ({
  owner: r.owner,
  host: r.host,
  check_id: r.check_id,
  ...(r.state ? { state: r.state } : {}),
  ...(r.reason ? { reason: r.reason.slice(0, 200) } : {}),
  ...(r.expires_at !== undefined ? { expires_at: r.expires_at } : {}),
});

async function handleGet(req: NextApiRequest, res: NextApiResponse, caller: ApiCaller) {
  const hostParam = typeof req.query.host === "string" ? req.query.host : undefined;
  const scanIdParam = typeof req.query.scanId === "string" ? req.query.scanId : undefined;
  if (hostParam && scanIdParam) return res.status(400).json({ error: "Give host or scanId, not both" });

  let owner = caller.ownerId;
  let host: string | null = null;
  if (scanIdParam) {
    if (!UUID.test(scanIdParam)) return res.status(400).json({ error: "scanId: must be a scan id" });
    const target = await resolveTargets(caller, [{ scanId: scanIdParam, checkId: "-" }]);
    if (!Array.isArray(target)) return res.status(target.status).json({ error: target.error });
    ({ owner, host } = target[0]);
  } else if (hostParam) {
    host = normaliseTriageHost(hostParam);
    if (!host) return res.status(400).json({ error: "host: is not a valid host name" });
  }

  const loaded = host ? await loadTriageForHost(supabaseAdmin, owner, host) : await loadTriageForOwner(supabaseAdmin, owner);
  if (!loaded.available) return res.status(200).json({ available: false, host, items: [] });
  if (loaded.error) return res.status(500).json({ error: "Could not load finding triage" });

  const rows = [...loaded.rows].sort((a, b) => b.updated_at.localeCompare(a.updated_at));
  return res.status(200).json({ available: true, host, items: await toRecords(rows, new Date()) });
}

async function handlePut(req: NextApiRequest, res: NextApiResponse, caller: ApiCaller) {
  const bulkRequest = isBulk(req.body);
  let items: TriageItem[];
  if (bulkRequest) {
    const parsed = parseBody(bulk(triageItem), req.body, res);
    if (!parsed) return;
    items = parsed.items;
  } else {
    const parsed = parseBody(triageItem, req.body, res);
    if (!parsed) return;
    items = [parsed];
  }

  const resolved = await resolveTargets(caller, items);
  if (!Array.isArray(resolved)) return res.status(resolved.status).json({ error: resolved.error });

  // One row per finding — the same finding twice in one upsert is an error
  // in Postgres ("cannot affect row a second time"). The last one wins.
  const now = new Date();
  const byKey = new Map<string, Omit<TriageDbRow, "id" | "created_at">>();
  items.forEach((item, i) => {
    const { owner, host } = resolved[i];
    byKey.set(`${owner} ${host} ${item.checkId}`, {
      owner,
      target_host: host,
      check_id: item.checkId,
      state: item.state,
      reason: item.reason,
      expires_at: item.expiresAt ? new Date(item.expiresAt).toISOString() : null,
      created_by: caller.ownerId,
      updated_at: now.toISOString(),
    });
  });
  const rows = [...byKey.values()];

  const { data, error } = await supabaseAdmin
    .from("finding_triage")
    .upsert(rows, { onConflict: "owner,target_host,check_id" })
    .select(TRIAGE_COLUMNS);
  if (error) {
    if (isMissingSchemaError(error)) return res.status(503).json({ error: MIGRATION_PENDING });
    console.error("[findings/triage] upsert failed:", error.message);
    return res.status(500).json({ error: "Could not save the triage" });
  }

  await logAuditEvent(supabaseAdmin, {
    actorId: caller.ownerId,
    action: "finding.triaged",
    resourceType: "finding",
    resourceId: rows.length === 1 ? `${rows[0].target_host}/${rows[0].check_id}` : null,
    metadata: {
      via: caller.via,
      count: rows.length,
      items: rows.map((r) => auditSummary({ owner: r.owner, host: r.target_host, check_id: r.check_id, state: r.state, reason: r.reason, expires_at: r.expires_at })),
    },
  });

  const records = await toRecords((data ?? []) as TriageDbRow[], now);
  if (bulkRequest) return res.status(200).json({ count: records.length, items: records });
  return res.status(200).json({ item: records[0] ?? null });
}

async function handleDelete(req: NextApiRequest, res: NextApiResponse, caller: ApiCaller) {
  const hasBody = req.body && typeof req.body === "object" && Object.keys(req.body).length > 0;
  const input = hasBody
    ? req.body
    : Object.fromEntries(
        Object.entries({ targetHost: req.query.host, scanId: req.query.scanId, checkId: req.query.checkId }).filter(
          ([, v]) => typeof v === "string"
        )
      );

  let items: TargetInput[];
  if (isBulk(input)) {
    const parsed = parseBody(bulk(targetItem), input, res);
    if (!parsed) return;
    items = parsed.items;
  } else {
    const parsed = parseBody(targetItem, input, res);
    if (!parsed) return;
    items = [parsed];
  }

  const resolved = await resolveTargets(caller, items);
  if (!Array.isArray(resolved)) return res.status(resolved.status).json({ error: resolved.error });

  // One delete per site, however many findings on it.
  const groups = new Map<string, Resolved & { checkIds: Set<string> }>();
  items.forEach((item, i) => {
    const { owner, host } = resolved[i];
    const key = `${owner} ${host}`;
    const group = groups.get(key) ?? { owner, host, checkIds: new Set<string>() };
    group.checkIds.add(item.checkId);
    groups.set(key, group);
  });

  const deleted: TriageDbRow[] = [];
  for (const group of groups.values()) {
    const { data, error } = await supabaseAdmin
      .from("finding_triage")
      .delete()
      .eq("owner", group.owner)
      .eq("target_host", group.host)
      .in("check_id", [...group.checkIds])
      .select(TRIAGE_COLUMNS);
    if (error) {
      if (isMissingSchemaError(error)) return res.status(503).json({ error: MIGRATION_PENDING });
      console.error("[findings/triage] delete failed:", error.message);
      return res.status(500).json({ error: "Could not remove the triage" });
    }
    deleted.push(...((data ?? []) as TriageDbRow[]));
  }

  if (deleted.length > 0) {
    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "finding.untriaged",
      resourceType: "finding",
      resourceId: deleted.length === 1 ? `${deleted[0].target_host}/${deleted[0].check_id}` : null,
      metadata: {
        via: caller.via,
        count: deleted.length,
        // What the decision was, since the row itself is gone.
        items: deleted.map((r) => auditSummary({ owner: r.owner, host: r.target_host, check_id: r.check_id, state: r.state, reason: r.reason, expires_at: r.expires_at })),
      },
    });
  }

  return res.status(200).json({
    deleted: deleted.length,
    items: deleted.map((r) => ({ targetHost: r.target_host, checkId: r.check_id })),
  });
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "PUT" && req.method !== "DELETE") {
    res.setHeader("Allow", "GET, PUT, DELETE");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });

  if (req.method === "GET") return handleGet(req, res, caller);
  if (req.method === "PUT") return handlePut(req, res, caller);
  return handleDelete(req, res, caller);
}
