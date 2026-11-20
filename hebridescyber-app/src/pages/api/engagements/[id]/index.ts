// PATCH /api/engagements/{id} — move an engagement on one state, and record its
// window, expiry, customer name, signed contract and signed rules of engagement.
// Admin session only. Stopping isn't here: `aborted` goes through /abort, the one
// path that also revokes authorisations.
//
// Moving to a state grants nothing by itself, and this route sends nothing to any
// target. Those details can only change before the engagement is authorised, so
// what was checked at that point is what stays on record.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { logAuditEvent } from "@/lib/audit";
import { checkTestingWindows, isEditableState, loadContacts, loadEngagement, loadIncludedHostFacts, loadTestingWindows, sendEngagementFailure, updateEngagement } from "@/lib/engagements";
import { checkTransition } from "@/lib/exploitability/scope/engagementState";
import { isUuid } from "@/lib/exploitabilityApi";
import { parseBody } from "@/lib/validate";

const ROUTE = "engagements/[id]";

const bodySchema = z
  .object({
    to: z.enum(["scoped", "authorised", "in_window", "reported", "closed"]).optional(),
    windowStart: z.string().datetime().optional(),
    windowEnd: z.string().datetime().optional(),
    expiresAt: z.string().datetime().optional(),
    customerName: z.string().trim().min(1).max(200).optional(),
    contract: z
      .object({
        signedAt: z.string().datetime(),
        signedByName: z.string().trim().min(1).max(200),
        signedByRole: z.string().trim().min(1).max(200),
        documentRef: z.string().trim().min(1).max(300).optional(),
      })
      .optional(),
    // A reference to the signed rules-of-engagement document (where it is filed,
    // and its version), never the document itself. The hash, when given, pins the
    // exact file that was signed.
    roe: z
      .object({
        documentRef: z.string().trim().min(1).max(300),
        documentSha256: z.string().regex(/^[0-9a-f]{64}$/).optional(),
        signedAt: z.string().datetime(),
        signedByName: z.string().trim().min(1).max(200),
        signedByRole: z.string().trim().min(1).max(200),
      })
      .optional(),
  })
  .refine((b) => b.to || b.windowStart || b.windowEnd || b.expiresAt || b.customerName || b.contract || b.roe, { message: "Nothing to change." });

const CONFLICT = "The engagement changed while this request was running. Reload and try again.";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "PATCH") {
    res.setHeader("Allow", "PATCH");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Forbidden" });

  const body = parseBody(bodySchema, req.body, res);
  if (!body) return;

  const id = req.query.id;
  if (!isUuid(id)) return sendEngagementFailure(res, ROUTE, { status: "not_found" });

  const loaded = await loadEngagement(supabaseAdmin, id);
  if (loaded.status !== "ok") return sendEngagementFailure(res, ROUTE, loaded);
  const engagement = loaded.data;

  const changes: Record<string, unknown> = {};
  const detailFields: string[] = [];
  if (body.windowStart || body.windowEnd || body.expiresAt || body.customerName || body.contract || body.roe) {
    if (!isEditableState(engagement.state)) {
      return res.status(409).json({ error: "The engagement's details can't change once it is authorised.", state: engagement.state });
    }
    if (body.windowStart) changes.window_start = body.windowStart;
    if (body.windowEnd) changes.window_end = body.windowEnd;
    if (body.windowStart || body.windowEnd) detailFields.push("window");
    if (body.expiresAt) {
      changes.expires_at = body.expiresAt;
      detailFields.push("expiry");
    }
    if (body.customerName) {
      changes.customer_name = body.customerName;
      detailFields.push("customer");
    }
    if (body.contract) {
      changes.contract_signed_at = body.contract.signedAt;
      changes.contract_signed_by_name = body.contract.signedByName;
      changes.contract_signed_by_role = body.contract.signedByRole;
      if (body.contract.documentRef) changes.contract_document_ref = body.contract.documentRef;
      detailFields.push("contract");
    }
    if (body.roe) {
      changes.roe_document_ref = body.roe.documentRef;
      changes.roe_document_sha256 = body.roe.documentSha256 ?? null;
      changes.roe_signed_at = body.roe.signedAt;
      changes.roe_signed_by_name = body.roe.signedByName;
      changes.roe_signed_by_role = body.roe.signedByRole;
      detailFields.push("rules_of_engagement");
    }
  }

  const windowStart = body.windowStart ?? engagement.window_start;
  const windowEnd = body.windowEnd ?? engagement.window_end;
  const expiresAt = body.expiresAt ?? engagement.expires_at;
  if (windowStart && windowEnd && Date.parse(windowEnd) <= Date.parse(windowStart)) {
    return res.status(400).json({ error: "windowEnd must be after windowStart" });
  }
  if (expiresAt && windowEnd && Date.parse(expiresAt) < Date.parse(windowEnd)) {
    return res.status(400).json({ error: "expiresAt can't be before windowEnd" });
  }
  // Moving the overall window must not strand a testing window outside it.
  if (body.windowStart || body.windowEnd) {
    const slots = await loadTestingWindows(supabaseAdmin, id);
    if (slots.status !== "ok") return sendEngagementFailure(res, ROUTE, slots);
    const problem = checkTestingWindows({ window_start: windowStart, window_end: windowEnd }, slots.data.map((w) => ({ startsAt: w.starts_at, endsAt: w.ends_at })));
    if (problem) return res.status(409).json({ error: "A testing window would fall outside the new engagement window. Change the testing windows first.", reason: problem.problem });
  }

  const now = new Date();
  if (body.to) {
    let includedHosts: Parameters<typeof checkTransition>[2]["includedHosts"] = [];
    let emergencyContacts = 0;
    if (body.to === "authorised") {
      const facts = await loadIncludedHostFacts(supabaseAdmin, engagement, now);
      if (facts.status !== "ok") return sendEngagementFailure(res, ROUTE, facts);
      includedHosts = facts.data;
      const contacts = await loadContacts(supabaseAdmin, id);
      if (contacts.status !== "ok") return sendEngagementFailure(res, ROUTE, contacts);
      emergencyContacts = contacts.data.filter((c) => c.kind === "emergency").length;
    }
    const decision = checkTransition(
      engagement.state,
      body.to,
      {
        contractSignedAt: body.contract?.signedAt ?? engagement.contract_signed_at,
        windowStart,
        windowEnd,
        roeSignedAt: body.roe?.signedAt ?? engagement.roe_signed_at,
        roeDocumentRef: body.roe?.documentRef ?? engagement.roe_document_ref,
        expiresAt,
        emergencyContacts,
        includedHosts,
      },
      now,
    );
    if (!decision.ok) {
      return res.status(409).json({ error: "The engagement can't move to that state.", reason: decision.reason, host: decision.host, state: engagement.state });
    }
    changes.state = body.to;
    if (body.to === "closed") changes.closed_at = now.toISOString();
  }

  const updated = await updateEngagement(supabaseAdmin, id, engagement.state, changes);
  if (updated.status !== "ok") return sendEngagementFailure(res, ROUTE, updated);
  if (!updated.data) return res.status(409).json({ error: CONFLICT });

  if (detailFields.length > 0) {
    await logAuditEvent(supabaseAdmin, { actorId: adminId, action: "engagement.updated", resourceType: "engagement", resourceId: id, metadata: { fields: detailFields } });
  }
  if (body.to) {
    await logAuditEvent(supabaseAdmin, { actorId: adminId, action: "engagement.state_changed", resourceType: "engagement", resourceId: id, metadata: { from: engagement.state, to: body.to } });
  }
  return res.status(200).json({ engagement: updated.data });
}
