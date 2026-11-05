// GET /api/v1/findings — the public-API name for GET /api/findings: every
// open finding across the caller's sites, with the same query parameters.
// `?sort=priority` returns the estate "fix this first" list (P1-2,
// estatePriority.ts), each row carrying its rank and a plain-English reason.
// API key or session auth; always the caller's own account. The list itself
// is /api/findings' respondWithFindings, so the two paths can't drift —
// docs/API.md documents both.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest } from "@/lib/apiAuth";
import { respondWithFindings } from "../findings";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) {
    return res.status(401).json({ error: "Missing or invalid Authorization header. Use: Authorization: Bearer <api-key>" });
  }
  return respondWithFindings(req, res, caller.ownerId);
}
