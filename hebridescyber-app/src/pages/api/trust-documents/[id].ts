// /api/trust-documents/<id> — change or remove one of the owner's profile
// documents. Session only.
//   PATCH  { title?, visibility? } → { ok: true }
//   DELETE → { removed: true }  The file is deleted from storage, the row is
//            kept (marked deleted) so past requests stay in the audit trail,
//            and every outstanding download link stops working.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { logAuditEvent } from "@/lib/audit";
import { parseBody } from "@/lib/validate";
import { TRUST_BUCKET } from "@/lib/trustDocuments";

const patchSchema = z
  .object({ title: z.string().trim().min(1).max(120).optional(), visibility: z.enum(["public", "on_request"]).optional() })
  .refine((b) => b.title !== undefined || b.visibility !== undefined, { message: "Nothing to change" });

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "PATCH" && req.method !== "DELETE") {
    res.setHeader("Allow", "PATCH, DELETE");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") return res.status(403).json({ error: "Profile documents can only be managed from a logged-in session." });
  const id = String(req.query.id ?? "");
  if (!/^[0-9a-f-]{36}$/i.test(id)) return res.status(404).json({ error: "Document not found" });

  const { data: doc, error } = await supabaseAdmin.from("trust_documents").select("id, object_key").eq("id", id).eq("owner", caller.ownerId).is("deleted_at", null).maybeSingle();
  if (error) return respondInternalError(res, "trust-documents/id", error);
  if (!doc) return res.status(404).json({ error: "Document not found" });

  if (req.method === "PATCH") {
    const body = parseBody(patchSchema, req.body, res);
    if (!body) return;
    const { error: updateError } = await supabaseAdmin.from("trust_documents").update(body).eq("id", id).eq("owner", caller.ownerId);
    if (updateError) return respondInternalError(res, "trust-documents/id", updateError);
    await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "trust_document.updated", resourceType: "trust_document", resourceId: id, metadata: body });
    return res.status(200).json({ ok: true });
  }

  const now = new Date().toISOString();
  const { error: deleteError } = await supabaseAdmin.from("trust_documents").update({ deleted_at: now }).eq("id", id).eq("owner", caller.ownerId);
  if (deleteError) return respondInternalError(res, "trust-documents/id", deleteError);
  // Expire every outstanding link at once, then remove the file (best-effort:
  // the row is already marked deleted, so nothing can serve it either way).
  await supabaseAdmin.from("trust_document_requests").update({ expires_at: now }).eq("document_id", id).eq("status", "approved");
  await supabaseAdmin.storage.from(TRUST_BUCKET).remove([(doc as { object_key: string }).object_key]).then(() => undefined, () => undefined);
  await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "trust_document.deleted", resourceType: "trust_document", resourceId: id, metadata: {} });
  return res.status(200).json({ removed: true });
}
