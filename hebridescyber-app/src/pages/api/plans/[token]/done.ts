// POST /api/plans/<token>/done { checkId, done, note? } — the person with a
// fix plan link marks an item done (or not). It records who-said-what only:
// "fixed" still comes from the owner's scans. Marking done emails the owner
// (best-effort) so they can confirm with "Check it's fixed". The link never
// starts a scan. Rate-limited per IP.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { supabaseAdmin } from "@/lib/supabaseAdmin";
import { respondInternalError } from "@/lib/apiError";
import { logAuditEvent } from "@/lib/audit";
import { escapeHtml, sendEmail } from "@/lib/email";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";
import { parseBody } from "@/lib/validate";
import { isPlanToken, loadPlanByToken, planUnavailable } from "@/lib/fixPlans";

const PLAN_DONE_RATE_LIMIT = { max: 60, windowSeconds: 60 * 60 };

const bodySchema = z.object({
  checkId: z.string().min(1).max(300),
  done: z.boolean(),
  note: z.string().trim().max(1000).optional(),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const limit = await checkRateLimit(getClientIp(req), "fix-plan-done", PLAN_DONE_RATE_LIMIT);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many requests — try again later." });
  }

  const token = req.query.token;
  const invalid = planUnavailable(null, new Date()) as string;
  if (!isPlanToken(token)) return res.status(404).json({ error: invalid });
  const body = parseBody(bodySchema, req.body, res);
  if (!body) return;

  let loaded;
  try {
    loaded = await loadPlanByToken(supabaseAdmin, token);
  } catch (err) {
    return respondInternalError(res, "plans/token/done", err as Error);
  }
  if (!loaded || planUnavailable(loaded.plan, new Date())) return res.status(404).json({ error: invalid });
  const item = loaded.items.find((i) => i.check_id === body.checkId);
  if (!item) return res.status(404).json({ error: "That item isn't in this plan." });

  const now = new Date().toISOString();
  const { error } = await supabaseAdmin
    .from("fix_plan_items")
    .update({ client_done_at: body.done ? now : null, client_note: body.done ? (body.note ?? "") : "" })
    .eq("plan_id", loaded.plan.id)
    .eq("check_id", body.checkId);
  if (error) return respondInternalError(res, "plans/token/done", error);

  // Audited under the owner, as the action happened on their plan.
  await logAuditEvent(supabaseAdmin, { actorId: loaded.plan.owner, action: body.done ? "fix_plan.item_marked_done" : "fix_plan.item_reopened", resourceType: "fix_plan", resourceId: loaded.plan.id, metadata: { checkId: body.checkId } });

  if (body.done && !item.client_done_at) {
    try {
      const { data: user } = await supabaseAdmin.from("users").select("email").eq("id", loaded.plan.owner).maybeSingle();
      const to = (user as { email?: string } | null)?.email;
      if (to) {
        const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
        const e = escapeHtml;
        await sendEmail({
          to,
          subject: `Marked done on ${loaded.plan.target_host}: ${item.title}`.slice(0, 150),
          html: `<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:600px;margin:0 auto;color:#111827;">
            <h2 style="margin:0 0 8px;font-size:18px;">An item in your fix plan was marked done</h2>
            <p style="font-size:14px;line-height:1.5;"><b>${e(item.title)}</b> on ${e(loaded.plan.target_host)}${loaded.plan.title ? ` (${e(loaded.plan.title)})` : ""}.</p>
            ${body.note ? `<p style="font-size:14px;line-height:1.5;"><b>Their note:</b> ${e(body.note)}</p>` : ""}
            <p style="font-size:14px;line-height:1.5;">Confirm it: open the site's latest report and use "Check it's fixed" on that finding. The plan shows it as fixed once a scan confirms it.</p>
            <p style="font-size:13px;"><a href="${siteUrl}/dashboard/findings">Open your findings</a></p>
          </div>`,
        });
      }
    } catch {
      /* best-effort */
    }
  }
  return res.status(200).json({ ok: true, markedDoneAt: body.done ? now : null });
}
