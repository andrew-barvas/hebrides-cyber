// POST /api/trust-documents/requests/<id> { decision: "approve" | "decline" }
// — the owner decides a request for an on-request profile document. Approval
// emails the requester a download link that works for DOWNLOAD_TTL_DAYS and
// MAX_DOWNLOADS downloads (only its hash is stored). Declining sends a short,
// neutral note. Session only; each decision is audited.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { logAuditEvent } from "@/lib/audit";
import { escapeHtml, sendEmail } from "@/lib/email";
import { parseBody } from "@/lib/validate";
import { DOWNLOAD_TTL_DAYS, MAX_DOWNLOADS, downloadUrl, newDownloadToken } from "@/lib/trustDocuments";

const bodySchema = z.object({ decision: z.enum(["approve", "decline"]) });

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") return res.status(403).json({ error: "Requests are decided from a logged-in session." });
  const id = String(req.query.id ?? "");
  if (!/^[0-9a-f-]{36}$/i.test(id)) return res.status(404).json({ error: "Request not found" });
  const body = parseBody(bodySchema, req.body, res);
  if (!body) return;

  const { data: request, error } = await supabaseAdmin
    .from("trust_document_requests")
    .select("id, document_id, requester_name, requester_email, status")
    .eq("id", id)
    .maybeSingle();
  if (error) return respondInternalError(res, "trust-documents/requests/id", error);
  const r = request as { id: string; document_id: string; requester_name: string; requester_email: string; status: string } | null;
  if (!r) return res.status(404).json({ error: "Request not found" });
  const { data: doc, error: docError } = await supabaseAdmin.from("trust_documents").select("id, owner, title, target_host").eq("id", r.document_id).is("deleted_at", null).maybeSingle();
  if (docError) return respondInternalError(res, "trust-documents/requests/id", docError);
  const d = doc as { id: string; owner: string; title: string; target_host: string } | null;
  // Someone else's request answers 404, like a missing one.
  if (!d || d.owner !== caller.ownerId) return res.status(404).json({ error: "Request not found" });
  if (r.status !== "pending") return res.status(409).json({ error: "This request has already been decided." });

  const now = new Date();
  const e = escapeHtml;
  const wrap = (inner: string) => `<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:600px;margin:0 auto;color:#111827;font-size:14px;line-height:1.5;">${inner}</div>`;

  if (body.decision === "approve") {
    const { token, hash } = newDownloadToken();
    const expiresAt = new Date(now.getTime() + DOWNLOAD_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();
    const { error: updateError } = await supabaseAdmin
      .from("trust_document_requests")
      .update({ status: "approved", token_hash: hash, decided_at: now.toISOString(), decided_by: caller.ownerId, expires_at: expiresAt })
      .eq("id", id)
      .eq("status", "pending");
    if (updateError) return respondInternalError(res, "trust-documents/requests/id", updateError);
    const sent = await sendEmail({
      to: r.requester_email,
      subject: `Your requested document from ${d.target_host}`.slice(0, 150),
      html: wrap(`<p>Hello ${e(r.requester_name)},</p>
        <p>The owner of ${e(d.target_host)} has approved your request for <b>${e(d.title)}</b>.</p>
        <p><a href="${downloadUrl(token)}" style="display:inline-block;background:#0b3d5b;color:#ffffff;text-decoration:none;padding:10px 16px;border-radius:6px;">Download the document</a></p>
        <p style="color:#4b5563;">The link works for ${DOWNLOAD_TTL_DAYS} days and up to ${MAX_DOWNLOADS} downloads. Please don't forward it.</p>
        <p style="color:#6b7280;font-size:12px;">Sent by Hebrides Cyber on behalf of ${e(d.target_host)}. You're receiving this because you asked for the document on its security profile.</p>`),
    });
    await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "trust_document_request.approved", resourceType: "trust_document", resourceId: d.id, metadata: { requestId: id, emailed: sent.ok } });
    return res.status(200).json({ status: "approved", expiresAt, emailed: sent.ok });
  }

  const { error: declineError } = await supabaseAdmin.from("trust_document_requests").update({ status: "declined", decided_at: now.toISOString(), decided_by: caller.ownerId }).eq("id", id).eq("status", "pending");
  if (declineError) return respondInternalError(res, "trust-documents/requests/id", declineError);
  const sent = await sendEmail({
    to: r.requester_email,
    subject: `Your document request to ${d.target_host}`.slice(0, 150),
    html: wrap(`<p>Hello ${e(r.requester_name)},</p><p>The owner of ${e(d.target_host)} isn't able to share <b>${e(d.title)}</b> through this request. You may want to contact them directly.</p><p style="color:#6b7280;font-size:12px;">Sent by Hebrides Cyber on behalf of ${e(d.target_host)}.</p>`),
  });
  await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "trust_document_request.declined", resourceType: "trust_document", resourceId: d.id, metadata: { requestId: id, emailed: sent.ok } });
  return res.status(200).json({ status: "declined", emailed: sent.ok });
}
