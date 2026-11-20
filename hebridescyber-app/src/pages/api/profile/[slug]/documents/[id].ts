// GET /api/profile/<slug>/documents/<id> — download a PUBLIC document from a
// published security profile (src/lib/trustDocuments.ts). On-request
// documents are never served here; they go through an approved link
// (/api/trust-download). Every missing, deleted, unpublished or on-request
// document gets the same 404. Always an attachment with nosniff. Rate-limited
// per IP.
import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/supabaseAdmin";
import { respondInternalError } from "@/lib/apiError";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";
import { loadProfileBySlug } from "@/lib/securityProfile";
import { NOT_AVAILABLE, loadProfileDocument, pdfHeaders, trustStore } from "@/lib/trustDocuments";

const DOWNLOAD_RATE_LIMIT = { max: 60, windowSeconds: 60 * 60 };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const limit = await checkRateLimit(getClientIp(req), "trust-document-download", DOWNLOAD_RATE_LIMIT);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many requests — try again later." });
  }

  const profile = await loadProfileBySlug(supabaseAdmin, String(req.query.slug ?? ""));
  if (!profile) return res.status(404).json({ error: NOT_AVAILABLE });
  let doc;
  try {
    doc = await loadProfileDocument(supabaseAdmin, profile, String(req.query.id ?? ""));
  } catch (err) {
    return respondInternalError(res, "profile/documents/id", err as Error);
  }
  if (!doc || doc.visibility !== "public") return res.status(404).json({ error: NOT_AVAILABLE });

  let bytes: Buffer | null;
  try {
    bytes = await trustStore(supabaseAdmin).get(doc.object_key);
  } catch (err) {
    return respondInternalError(res, "profile/documents/id", err as Error, { publicMessage: "Couldn't fetch the document. Try again." });
  }
  if (!bytes) return res.status(404).json({ error: NOT_AVAILABLE });
  for (const [k, v] of Object.entries(pdfHeaders(doc.title, bytes.length))) res.setHeader(k, v);
  return res.status(200).send(bytes);
}
