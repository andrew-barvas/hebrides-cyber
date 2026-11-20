// /api/trust-documents — the owner's documents for one site's public security
// profile (src/lib/trustDocuments.ts, migration 087). Pro plan and above,
// session only (a published document is a deliberate, visible choice, like
// the profile itself).
//   GET  ?targetUrl=…  → { documents, requests }  (requests: newest first, up to 100)
//   POST { targetUrl, title, kind, visibility, dataUrl } → { document }
// Uploading needs the domain verified, so nobody can attach documents to a
// site they don't control.
import type { NextApiRequest, NextApiResponse } from "next";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { logAuditEvent } from "@/lib/audit";
import { hostOf } from "@/lib/findingLifecycle";
import { isDomainVerified } from "@/lib/ownership";
import { planGate } from "@/lib/planAccess";
import { parseBody } from "@/lib/validate";
import { DOCUMENT_KINDS, MAX_DOCS_PER_SITE, loadSiteDocuments, objectKey, parsePdfDataUrl, publicDocuments, trustStore, type RequestRow } from "@/lib/trustDocuments";

export const config = { api: { bodyParser: { sizeLimit: "7mb" } } };

const uploadSchema = z.object({
  targetUrl: z.string().url(),
  title: z.string().trim().min(1).max(120),
  kind: z.enum(DOCUMENT_KINDS),
  visibility: z.enum(["public", "on_request"]),
  dataUrl: z.string().min(1),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") return res.status(403).json({ error: "Profile documents can only be managed from a logged-in session." });

  const gate = await planGate(supabaseAdmin, caller.ownerId, "pro");
  if (gate === "error") return respondInternalError(res, "trust-documents", new Error("plan lookup failed"));
  if (gate === "denied") return res.status(403).json({ error: "Profile documents are on the Pro plan and above." });

  if (req.method === "GET") {
    const host = hostOf(String(req.query.targetUrl ?? ""));
    if (!host) return res.status(400).json({ error: "targetUrl must be a website address" });
    const docs = await loadSiteDocuments(supabaseAdmin, caller.ownerId, host);
    let requests: RequestRow[] = [];
    if (docs.length) {
      const { data, error } = await supabaseAdmin
        .from("trust_document_requests")
        .select("id, document_id, requester_name, requester_email, requester_company, reason, status, created_at, decided_at, expires_at, download_count")
        .in("document_id", docs.map((d) => d.id))
        .order("created_at", { ascending: false })
        .limit(100);
      if (error) return respondInternalError(res, "trust-documents", error);
      requests = (data ?? []) as RequestRow[];
    }
    return res.status(200).json({ documents: publicDocuments(docs), requests });
  }

  const body = parseBody(uploadSchema, req.body, res);
  if (!body) return;
  const host = hostOf(body.targetUrl);
  if (!host) return res.status(400).json({ error: "targetUrl must be a website address" });
  if (!(await isDomainVerified(supabaseAdmin, caller.ownerId, body.targetUrl))) {
    return res.status(403).json({ error: "Verify you own this domain before adding documents to its profile." });
  }
  const pdf = parsePdfDataUrl(body.dataUrl);
  if (!pdf.ok) return res.status(400).json({ error: pdf.error });

  const existing = await loadSiteDocuments(supabaseAdmin, caller.ownerId, host);
  if (existing.length >= MAX_DOCS_PER_SITE) return res.status(409).json({ error: `A profile can hold up to ${MAX_DOCS_PER_SITE} documents. Remove one first.` });

  const id = randomUUID();
  const key = objectKey(caller.ownerId, host, id);
  try {
    await trustStore(supabaseAdmin).put(key, pdf.bytes, "application/pdf");
  } catch (err) {
    return respondInternalError(res, "trust-documents", err as Error, { publicMessage: "Couldn't store the file. Try again." });
  }
  const row = { id, owner: caller.ownerId, target_host: host, title: body.title, kind: body.kind, visibility: body.visibility, object_key: key, size_bytes: pdf.bytes.length, sha256: pdf.sha256, uploaded_by: caller.ownerId };
  const { error } = await supabaseAdmin.from("trust_documents").insert(row);
  if (error) {
    await supabaseAdmin.storage.from("trust-documents").remove([key]).then(() => undefined, () => undefined);
    return respondInternalError(res, "trust-documents", error, { publicMessage: "Couldn't save the document. Try again." });
  }
  await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "trust_document.uploaded", resourceType: "trust_document", resourceId: id, metadata: { host, kind: body.kind, visibility: body.visibility, sizeBytes: pdf.bytes.length } });
  const [document] = publicDocuments([{ ...row, uploaded_at: new Date().toISOString(), deleted_at: null }]);
  return res.status(201).json({ document });
}
