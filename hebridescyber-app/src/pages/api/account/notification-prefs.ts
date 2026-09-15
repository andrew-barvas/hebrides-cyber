// GET/PATCH /api/account/notification-prefs — E-50/E-51 notification
// preferences. Reads/updates the notify_* columns on subscriptions.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { parseBody } from "@/lib/validate";

const patchSchema = z.object({
  notify_email: z.boolean().optional(),
  notify_score_threshold: z.number().int().min(0).max(100).nullable().optional(),
  notify_severity_min: z.enum(["info", "low", "medium", "high", "critical"]).nullable().optional(),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "PATCH") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const auth = await authenticateApiRequest(req);
  if (!auth) return res.status(401).json({ error: "Unauthorized" });

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin
      .from("subscriptions")
      .select("notify_email, notify_score_threshold, notify_severity_min")
      .eq("owner", auth.ownerId)
      .maybeSingle();

    if (error) return res.status(500).json({ error: "Could not load preferences" });
    return res.json({
      notify_email: data?.notify_email ?? true,
      notify_score_threshold: data?.notify_score_threshold ?? null,
      notify_severity_min: data?.notify_severity_min ?? null,
    });
  }

  const parsed = parseBody(patchSchema, req.body, res);
  if (!parsed) return;

  const updates: Record<string, unknown> = {};
  if (parsed.notify_email !== undefined) updates.notify_email = parsed.notify_email;
  if (parsed.notify_score_threshold !== undefined) updates.notify_score_threshold = parsed.notify_score_threshold;
  if (parsed.notify_severity_min !== undefined) updates.notify_severity_min = parsed.notify_severity_min;

  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: "No fields to update" });
  }

  const { error } = await supabaseAdmin
    .from("subscriptions")
    .update(updates)
    .eq("owner", auth.ownerId);

  if (error) return res.status(500).json({ error: "Could not save preferences" });
  return res.json({ ok: true, ...updates });
}
