// GET/PUT /api/findings/assign — who a finding is assigned to (migration 078).
// Session or API key, always on the caller's own account, like GET
// /api/findings.
//
//   GET → { available, assignees: [{ id, email, role }] }: the owner, then
//         team members — the only people a finding can be assigned to
//   PUT { items: [{ targetHost, checkId }, ...up to 200], assigneeId }
//       assigneeId null unassigns. An assignee who isn't the owner or a
//       current team member is a 400. Someone other than the caller gets one
//       email listing what was assigned to them (best-effort).
//
// Every write is audited (finding.assigned / finding.unassigned).
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { respondInternalError } from "@/lib/apiError";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { escapeHtml, sendEmail } from "@/lib/email";
import { normaliseTriageHost } from "@/lib/findingTriage";
import { ASSIGN_BULK_MAX, loadAssignees } from "@/lib/findingAssignments";
import { parseBody } from "@/lib/validate";

const MIGRATION_PENDING = "Assigning findings isn't enabled on this server yet.";
const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";

const putSchema = z.object({
  items: z
    .array(z.object({ targetHost: z.string().min(1).max(253), checkId: z.string().min(1).max(500) }))
    .min(1)
    .max(ASSIGN_BULK_MAX, `at most ${ASSIGN_BULK_MAX} per request`),
  assigneeId: z.string().uuid().nullable(),
  /** Optional titles, only used to make the assignee's email readable. */
  titles: z.array(z.string().max(300)).max(ASSIGN_BULK_MAX).optional(),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "PUT") return res.status(405).json({ error: "Method not allowed" });
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });
  const ownerId = caller.ownerId;

  const people = await loadAssignees(supabaseAdmin, ownerId);
  if (!people.ok) return respondInternalError(res, "findings/assign", new Error("could not load assignees"));

  if (req.method === "GET") {
    const { error } = await supabaseAdmin.from("finding_assignments").select("id").eq("owner", ownerId).limit(1);
    if (error && !isMissingSchemaError(error)) return respondInternalError(res, "findings/assign", error);
    return res.status(200).json({ available: !error, assignees: people.assignees });
  }

  const parsed = parseBody(putSchema, req.body, res);
  if (!parsed) return;
  const items: Array<{ host: string; checkId: string; title?: string }> = [];
  for (const [n, item] of parsed.items.entries()) {
    const host = normaliseTriageHost(item.targetHost);
    if (!host) return res.status(400).json({ error: `targetHost: ${item.targetHost.slice(0, 60)} is not a valid host name` });
    items.push({ host, checkId: item.checkId, title: parsed.titles?.[n] });
  }
  const unique = [...new Map(items.map((i) => [`${i.host} ${i.checkId}`, i])).values()];

  if (parsed.assigneeId === null) {
    for (const i of unique) {
      const { error } = await supabaseAdmin.from("finding_assignments").delete().eq("owner", ownerId).eq("target_host", i.host).eq("check_id", i.checkId);
      if (error) {
        if (isMissingSchemaError(error)) return res.status(503).json({ error: MIGRATION_PENDING });
        return respondInternalError(res, "findings/assign", error);
      }
    }
    await logAuditEvent(supabaseAdmin, { actorId: ownerId, action: "finding.unassigned", resourceType: "finding", metadata: { via: caller.via, count: unique.length } });
    return res.status(200).json({ count: unique.length, assignee: null });
  }

  const assignee = people.assignees.find((a) => a.id === parsed.assigneeId);
  if (!assignee) return res.status(400).json({ error: "assigneeId: findings can only be assigned to you or a member of your team" });

  const now = new Date().toISOString();
  const { error } = await supabaseAdmin
    .from("finding_assignments")
    .upsert(
      unique.map((i) => ({ owner: ownerId, target_host: i.host, check_id: i.checkId, assignee: assignee.id, assigned_by: ownerId, assigned_at: now })),
      { onConflict: "owner,target_host,check_id" }
    );
  if (error) {
    if (isMissingSchemaError(error)) return res.status(503).json({ error: MIGRATION_PENDING });
    return respondInternalError(res, "findings/assign", error);
  }
  await logAuditEvent(supabaseAdmin, {
    actorId: ownerId,
    action: "finding.assigned",
    resourceType: "finding",
    resourceId: unique.length === 1 ? `${unique[0].host}/${unique[0].checkId}` : null,
    metadata: { via: caller.via, count: unique.length, assignee: assignee.id },
  });

  if (assignee.id !== ownerId && assignee.email) {
    const lines = unique.slice(0, 20).map((i) => `<li>${escapeHtml(i.title ?? i.checkId)} <span style="color:#64748b">(${escapeHtml(i.host)})</span></li>`);
    const more = unique.length > 20 ? `<p>…and ${unique.length - 20} more.</p>` : "";
    await sendEmail({
      to: assignee.email,
      subject: `${unique.length} security finding${unique.length === 1 ? "" : "s"} assigned to you`,
      html: `<p>You've been asked to look at ${unique.length === 1 ? "this finding" : "these findings"} on Hebrides Cyber:</p><ul>${lines.join("")}</ul>${more}<p><a href="${SITE_URL}/dashboard">Open Hebrides Cyber</a></p>`,
    }).catch(() => undefined);
  }

  return res.status(200).json({ count: unique.length, assignee });
}
