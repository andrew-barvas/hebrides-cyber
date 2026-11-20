// POST /api/profile/<slug>/documents/<id>/request { name, email, company?, reason? }
// — a profile visitor asks for an on-request document. Records the request
// and emails the site's owner, who approves or declines it on their
// dashboard. Nothing is released here.
//
// Abuse controls: rate-limited per IP; a cap on pending requests per
// document; a repeat request from the same address while one is pending is
// accepted silently without a second email; and the answer is the same
// "request sent" for every outcome, so the form can't be used to learn
// anything about the owner or other requesters.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { supabaseAdmin } from "@/lib/supabaseAdmin";
import { respondInternalError } from "@/lib/apiError";
import { logAuditEvent } from "@/lib/audit";
import { escapeHtml, sendEmail } from "@/lib/email";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";
import { loadProfileBySlug } from "@/lib/securityProfile";
import { parseBody } from "@/lib/validate";
import { MAX_PENDING_PER_DOCUMENT, NOT_AVAILABLE, loadProfileDocument } from "@/lib/trustDocuments";

const REQUEST_RATE_LIMIT = { max: 5, windowSeconds: 60 * 60 };
const SENT = { ok: true, message: "Request sent. If the owner approves it, you'll get an email with a download link." };

const bodySchema = z.object({
  name: z.string().trim().min(1).max(120),
  email: z.string().trim().toLowerCase().email().max(254),
  company: z.string().trim().max(120).optional(),
  reason: z.string().trim().max(1000).optional(),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const limit = await checkRateLimit(getClientIp(req), "trust-document-request", REQUEST_RATE_LIMIT);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many requests — try again later." });
  }
  const body = parseBody(bodySchema, req.body, res);
  if (!body) return;

  const profile = await loadProfileBySlug(supabaseAdmin, String(req.query.slug ?? ""));
  if (!profile) return res.status(404).json({ error: NOT_AVAILABLE });
  let doc;
  try {
    doc = await loadProfileDocument(supabaseAdmin, profile, String(req.query.id ?? ""));
  } catch (err) {
    return respondInternalError(res, "profile/documents/id/request", err as Error);
  }
  if (!doc || doc.visibility !== "on_request") return res.status(404).json({ error: NOT_AVAILABLE });

  const { data: pending, error: pendingError } = await supabaseAdmin.from("trust_document_requests").select("requester_email").eq("document_id", doc.id).eq("status", "pending").limit(MAX_PENDING_PER_DOCUMENT + 1);
  if (pendingError) return respondInternalError(res, "profile/documents/id/request", pendingError);
  const list = (pending ?? []) as Array<{ requester_email: string }>;
  if (list.some((p) => p.requester_email === body.email) || list.length >= MAX_PENDING_PER_DOCUMENT) return res.status(200).json(SENT);

  const { error } = await supabaseAdmin.from("trust_document_requests").insert({
    document_id: doc.id,
    requester_name: body.name,
    requester_email: body.email,
    requester_company: body.company ?? "",
    reason: body.reason ?? "",
  });
  if (error) return respondInternalError(res, "profile/documents/id/request", error);
  await logAuditEvent(supabaseAdmin, { actorId: doc.owner, action: "trust_document_request.received", resourceType: "trust_document", resourceId: doc.id, metadata: {} });

  try {
    const { data: owner } = await supabaseAdmin.from("users").select("email").eq("id", doc.owner).maybeSingle();
    const to = (owner as { email?: string } | null)?.email;
    if (to) {
      const e = escapeHtml;
      const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
      await sendEmail({
        to,
        subject: `Document request on ${doc.target_host}: ${doc.title}`.slice(0, 150),
        html: `<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:600px;margin:0 auto;color:#111827;font-size:14px;line-height:1.5;">
          <h2 style="margin:0 0 8px;font-size:18px;">Someone asked for a document on your security profile</h2>
          <p><b>${e(doc.title)}</b> on ${e(doc.target_host)}</p>
          <p>${e(body.name)}${body.company ? `, ${e(body.company)}` : ""} &lt;${e(body.email)}&gt;</p>
          ${body.reason ? `<p><b>Why:</b> ${e(body.reason)}</p>` : ""}
          <p>Nothing has been shared yet. Approve or decline it on the site's report page, under the profile's documents.</p>
          <p style="font-size:13px;"><a href="${siteUrl}/dashboard/scans">Open your scans</a></p>
        </div>`,
      });
    }
  } catch {
    /* best-effort: the request is recorded and shows on the dashboard */
  }
  return res.status(200).json(SENT);
}
