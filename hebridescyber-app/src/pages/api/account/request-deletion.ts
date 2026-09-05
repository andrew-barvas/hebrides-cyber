// POST /api/account/request-deletion — customer-facing half of E-10's GDPR
// erasure commitment (docs/ENHANCEMENTS.md, /privacy §7's 30-day response
// promise). Records the request (audit_logs, so it shows up in the existing
// admin Audit tab) and emails the owner so it actually gets actioned within
// the promised window.
//
// Deliberately does NOT delete anything itself — an irreversible full
// account delete has no place behind a single unconfirmed POST. Actual
// erasure is a separate, human-run step: src/scripts/erase-user-data.ts.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { sendEmail, escapeHtml } from "@/lib/email";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

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

  const notifyEmail = process.env.CONTACT_EMAIL ?? "hello@hebridescyber.co.uk";
  const result = await sendEmail({
    to: notifyEmail,
    subject: `Account deletion request — ${email ?? caller.ownerId}`,
    html: [
      `<p>A customer has requested deletion of their account and data, per /privacy §7's 30-day response commitment.</p>`,
      `<p><strong>Email:</strong> ${escapeHtml(email ?? "unknown")}</p>`,
      fullName ? `<p><strong>Name:</strong> ${escapeHtml(fullName)}</p>` : "",
      `<p><strong>User ID:</strong> ${escapeHtml(caller.ownerId)}</p>`,
      `<p>Run <code>npm run account:erase -- ${escapeHtml(email ?? caller.ownerId)} --confirm</code> once ready to action this.</p>`,
    ].join(""),
  });
  if (!result.ok && result.error !== "RESEND_API_KEY not configured") {
    // Non-fatal: the request is already logged to audit_logs; log but don't fail the request.
    console.error("[request-deletion] notification email failed:", result.error);
  }

  return res.status(200).json({ ok: true });
}
