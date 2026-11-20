// PUT /api/engagements/{id}/contacts — set an engagement's authorised contacts:
// who approved the test (authoriser), who the tester talks to (technical) and who
// can be reached to stop it (emergency). Replaces the whole list, while the
// engagement is still booked or scoped. Admin session only. Moving to
// `authorised` needs at least one emergency contact.
//
// The audit records counts per kind, never names or contact details.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { logAuditEvent } from "@/lib/audit";
import { CONTACT_KINDS, isEditableState, loadEngagement, replaceContacts, sendEngagementFailure } from "@/lib/engagements";
import { isUuid } from "@/lib/exploitabilityApi";
import { parseBody } from "@/lib/validate";

const ROUTE = "engagements/[id]/contacts";

const contactSchema = z
  .object({
    kind: z.enum(CONTACT_KINDS),
    name: z.string().trim().min(1).max(200),
    role: z.string().trim().min(1).max(200).optional(),
    email: z.string().trim().email().max(320).optional(),
    phone: z.string().trim().regex(/^\+?[0-9 ()-]{6,30}$/).optional(),
  })
  .refine((c) => c.email || c.phone, { message: "Each contact needs an email address or a phone number." });

const bodySchema = z.object({ contacts: z.array(contactSchema).max(20) });

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "PUT") {
    res.setHeader("Allow", "PUT");
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
  if (!isEditableState(loaded.data.state)) {
    return res.status(409).json({ error: "Contacts can't change once an engagement is authorised.", state: loaded.data.state });
  }

  const result = await replaceContacts(supabaseAdmin, loaded.data, adminId, body.contacts);
  if (result.status !== "ok") return sendEngagementFailure(res, ROUTE, result);

  const counts = Object.fromEntries(CONTACT_KINDS.map((k) => [k, result.data.filter((c) => c.kind === k).length]));
  await logAuditEvent(supabaseAdmin, { actorId: adminId, action: "engagement.contacts_updated", resourceType: "engagement", resourceId: id, metadata: counts });
  return res.status(200).json({ contacts: result.data });
}
