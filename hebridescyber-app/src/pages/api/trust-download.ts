// GET /api/trust-download?token=… — download an on-request profile document
// with the link an owner's approval emailed (src/lib/trustDocuments.ts). The
// token is looked up by its SHA-256. The link works for DOWNLOAD_TTL_DAYS and
// MAX_DOWNLOADS downloads, stops when the document is deleted, and every
// download is counted and audited under the owner. Rate-limited per IP.
import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/supabaseAdmin";
import { respondInternalError } from "@/lib/apiError";
import { logAuditEvent } from "@/lib/audit";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";
import { downloadProblem, hashDownloadToken, isDownloadToken, pdfHeaders, trustStore, type RequestRow } from "@/lib/trustDocuments";

const DOWNLOAD_RATE_LIMIT = { max: 30, windowSeconds: 60 * 60 };

function refuse(res: NextApiResponse, message: string) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(404).send(message);
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const limit = await checkRateLimit(getClientIp(req), "trust-download", DOWNLOAD_RATE_LIMIT);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).send("Too many requests — try again later.");
  }
  const invalid = downloadProblem(null, new Date()) as string;
  const token = req.query.token;
  if (!isDownloadToken(token)) return refuse(res, invalid);

  const { data, error } = await supabaseAdmin
    .from("trust_document_requests")
    .select("id, document_id, status, expires_at, download_count")
    .eq("token_hash", hashDownloadToken(token))
    .maybeSingle();
  if (error) return respondInternalError(res, "trust-download", error);
  const request = data as (Pick<RequestRow, "id" | "document_id" | "status" | "expires_at" | "download_count">) | null;
  const problem = downloadProblem(request, new Date());
  if (!request || problem) return refuse(res, problem ?? invalid);

  const { data: doc, error: docError } = await supabaseAdmin.from("trust_documents").select("id, owner, title, object_key").eq("id", request.document_id).is("deleted_at", null).maybeSingle();
  if (docError) return respondInternalError(res, "trust-download", docError);
  const d = doc as { id: string; owner: string; title: string; object_key: string } | null;
  if (!d) return refuse(res, invalid);

  let bytes: Buffer | null;
  try {
    bytes = await trustStore(supabaseAdmin).get(d.object_key);
  } catch (err) {
    return respondInternalError(res, "trust-download", err as Error, { publicMessage: "Couldn't fetch the document. Try again." });
  }
  if (!bytes) return refuse(res, invalid);

  // Count before sending; the guard on the old count stops two concurrent
  // downloads both using the last allowance.
  const { data: counted, error: countError } = await supabaseAdmin
    .from("trust_document_requests")
    .update({ download_count: request.download_count + 1 })
    .eq("id", request.id)
    .eq("download_count", request.download_count)
    .select("id");
  if (countError) return respondInternalError(res, "trust-download", countError);
  if (!counted || (counted as unknown[]).length === 0) return refuse(res, "This download link is busy. Try again in a moment.");
  await logAuditEvent(supabaseAdmin, { actorId: d.owner, action: "trust_document.downloaded", resourceType: "trust_document", resourceId: d.id, metadata: { requestId: request.id } });

  for (const [k, v] of Object.entries(pdfHeaders(d.title, bytes.length))) res.setHeader(k, v);
  return res.status(200).send(bytes);
}
