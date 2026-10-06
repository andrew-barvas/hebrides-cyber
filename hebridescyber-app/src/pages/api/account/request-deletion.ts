// POST /api/account/request-deletion — customer-facing half of the GDPR
// erasure commitment (/privacy: actioned within 30 days). Records the request
// in deletion_requests (migration 048, via accountErasure.ts) so the deadline
// is tracked and the daily reminder job sees it, logs it to audit_logs (the
// admin Audit tab), and emails the operator.
//
// Deliberately does NOT delete anything itself — an irreversible full
// account delete has no place behind a single unconfirmed POST. Actual
// erasure is a separate, human-run step: src/scripts/erase-user-data.ts.
//
// Session only: an API key (which might sit in a CI system) must not be able
// to ask for the whole account to be erased. A repeat request while one is
// pending returns the same deadline and sends no second email. Before
// migration 048 it falls back to the audit row and email alone.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { sendEmail, escapeHtml } from "@/lib/email";
import { recordDeletionRequest } from "@/lib/accountErasure";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Account deletion can only be requested from a signed-in session, not with an API key." });
  }

  let recorded: Awaited<ReturnType<typeof recordDeletionRequest>>;
  try {
    recorded = await recordDeletionRequest(supabaseAdmin, caller.ownerId);
  } catch (err) {
    console.error("[request-deletion] could not record the request:", (err as Error).message);
    return res.status(500).json({ error: "We couldn't record your request. Please try again, or email us." });
  }

  if (recorded?.alreadyPending) {
    return res.status(200).json({ ok: true, requestedAt: recorded.requestedAt, dueAt: recorded.dueAt, alreadyRequested: true });
  }

  const { data: user } = await supabaseAdmin
    .from("users")
    .select("email, full_name")
    .eq("id", caller.ownerId)
    .maybeSingle();

  const email = (user?.email as string | undefined) ?? null;
  const fullName = (user?.full_name as string | null | undefined) ?? null;

  await logAuditEvent(supabaseAdmin, {
    actorId: caller.ownerId,
    actorEmail: email,
    action: "account.deletion_requested",
    resourceType: "user",
    resourceId: caller.ownerId,
  });

  const notifyEmail = process.env.CONTACT_EMAIL || "hello@hebridescyber.co.uk";
  const result = await sendEmail({
    to: notifyEmail,
    subject: `Account deletion request — ${email ?? caller.ownerId}`,
    html: [
      `<p>A customer has requested deletion of their account and data. /privacy promises this is actioned within 30 days.</p>`,
      `<p><strong>Email:</strong> ${escapeHtml(email ?? "unknown")}</p>`,
      fullName ? `<p><strong>Name:</strong> ${escapeHtml(fullName)}</p>` : "",
      `<p><strong>User ID:</strong> ${escapeHtml(caller.ownerId)}</p>`,
      recorded ? `<p><strong>Due by:</strong> ${escapeHtml(recorded.dueAt.slice(0, 10))}</p>` : "",
      `<p>Check what will be deleted with <code>npm run account:erase -- ${escapeHtml(caller.ownerId)}</code>, then add <code>--confirm</code> to action it.</p>`,
    ].join(""),
  });
  if (!result.ok && result.error !== "RESEND_API_KEY not configured") {
    // Non-fatal: the request is already recorded; the daily reminder job will chase it.
    console.error("[request-deletion] notification email failed:", result.error);
  }

  return res.status(200).json({ ok: true, requestedAt: recorded?.requestedAt ?? null, dueAt: recorded?.dueAt ?? null, alreadyRequested: false });
}
