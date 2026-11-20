// GET /api/account/evidence-pack — the security evidence pack PDF
// (src/lib/evidencePack.ts): Cyber Essentials readiness, common insurance
// and supplier questionnaire answers with where each comes from, and what to
// fix first. Pro and above (planAccess.ts), session or API key, the caller's
// own account. Rate-limited because each call launches Chromium.
// ?format=html returns the HTML instead.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { loadEvidencePack, renderEvidencePackHtml } from "@/lib/evidencePack";
import { planGate } from "@/lib/planAccess";
import { checkRateLimit } from "@/lib/rateLimit";
import { htmlToPdf } from "@/lib/reportPdf";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const gate = await planGate(supabaseAdmin, caller.ownerId, "pro");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan. Try again." });
  if (gate === "denied") return res.status(403).json({ error: "The evidence pack is on the Pro plan and above.", code: "plan_required" });

  const limit = await checkRateLimit(caller.ownerId, "evidence-pack");
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Rate limit exceeded — try again later", retryAfterSeconds: limit.retryAfterSeconds });
  }

  let html: string;
  let date: string;
  try {
    const pack = await loadEvidencePack(supabaseAdmin, caller.ownerId);
    html = renderEvidencePackHtml(pack);
    date = pack.generatedAt.slice(0, 10);
  } catch (err) {
    return respondInternalError(res, "account/evidence-pack", err as Error, { publicMessage: "Could not build your evidence pack. Try again." });
  }
  res.setHeader("Cache-Control", "no-store");
  if (req.query.format === "html") {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(html);
  }
  try {
    const pdf = await htmlToPdf(html);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="security-evidence-pack-${date}.pdf"`);
    return res.status(200).send(pdf);
  } catch (err) {
    return respondInternalError(res, "account/evidence-pack", err as Error, { publicMessage: "Could not produce the PDF. Try again." });
  }
}
