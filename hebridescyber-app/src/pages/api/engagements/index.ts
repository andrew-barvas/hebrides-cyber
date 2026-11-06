// POST /api/engagements — create a booked engagement for an account. Admin session
// only: engagements are never self-serve (docs/EXPLOITABILITY-ENGINE.md §7.1), and
// requireAdmin refuses an API key. A database write only: nothing is sent to any target.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { logAuditEvent } from "@/lib/audit";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { ENGAGEMENT_COLUMNS, accountExists, sendEngagementFailure } from "@/lib/engagements";
import { parseBody } from "@/lib/validate";

const ROUTE = "engagements";

const bodySchema = z
  .object({
    owner: z.string().uuid(),
    reference: z.string().trim().min(1).max(200),
    scanProfile: z.enum(["safe", "exposure", "offensive"]).default("exposure"),
    windowStart: z.string().datetime().optional(),
    windowEnd: z.string().datetime().optional(),
  })
  .refine((b) => !b.windowStart || !b.windowEnd || Date.parse(b.windowEnd) > Date.parse(b.windowStart), { message: "windowEnd must be after windowStart" });

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Forbidden" });

  const body = parseBody(bodySchema, req.body, res);
  if (!body) return;

  // No foreign key to auth.users (the record outlives erasure), so check here.
  const account = await accountExists(supabaseAdmin, body.owner);
  if (account.status !== "ok") return sendEngagementFailure(res, ROUTE, account);
  if (!account.data) return res.status(400).json({ error: "No account with that id." });

  const { data, error } = await supabaseAdmin
    .from("engagements")
    .insert({
      owner: body.owner,
      reference: body.reference,
      scan_profile: body.scanProfile,
      window_start: body.windowStart ?? null,
      window_end: body.windowEnd ?? null,
      created_by: adminId,
    })
    .select(ENGAGEMENT_COLUMNS)
    .single();
  if (error) {
    if (error.code === "23505") return res.status(409).json({ error: "This account already has an engagement with that reference." });
    return sendEngagementFailure(res, ROUTE, isMissingSchemaError(error) ? { status: "unavailable" } : { status: "error", error });
  }

  const engagement = data as unknown as { id: string };
  await logAuditEvent(supabaseAdmin, {
    actorId: adminId,
    action: "engagement.created",
    resourceType: "engagement",
    resourceId: engagement.id,
    metadata: { reference: body.reference, owner: body.owner },
  });
  return res.status(201).json({ engagement: data });
}
