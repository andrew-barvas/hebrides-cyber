// GET /api/account/evidence-pack — the security evidence pack PDF
// (src/lib/evidencePack.ts): Cyber Essentials readiness, common insurance
// and supplier questionnaire answers with where each comes from, and what to
// fix first. Pro and above (planAccess.ts), session or API key, the caller's
// own account. Rate-limited.
// ?format=html returns the HTML instead.
//
// The PDF is drawn by evidencePackPdf.ts (pdf-lib), not reportPdf.ts's
// headless Chromium: this route runs as an Azure Static Web Apps managed
// Function, which has no Chromium, so every download used to answer 500.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { loadEvidencePack, renderEvidencePackHtml, type EvidencePack } from "@/lib/evidencePack";
import { renderEvidencePackPdf } from "@/lib/evidencePackPdf";
import { planGate } from "@/lib/planAccess";
import { checkRateLimit } from "@/lib/rateLimit";

const ROUTE = "account/evidence-pack";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const gate = await planGate(supabaseAdmin, caller.ownerId, "pro");
  if (gate === "error") return respondInternalError(res, ROUTE, { message: "plan check failed" }, { publicMessage: "Could not check your plan. Try again." });
  if (gate === "denied") return res.status(403).json({ error: "The evidence pack is on the Pro plan and above.", code: "plan_required" });

  const limit = await checkRateLimit(caller.ownerId, "evidence-pack");
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Rate limit exceeded — try again later", retryAfterSeconds: limit.retryAfterSeconds });
  }

  let pack: EvidencePack;
  try {
    pack = await loadEvidencePack(supabaseAdmin, caller.ownerId);
  } catch (err) {
    return respondInternalError(res, ROUTE, err as Error, { publicMessage: "Could not build your evidence pack. Try again." });
  }
  res.setHeader("Cache-Control", "no-store");

  if (req.query.format === "html") {
    let html: string;
    try {
      html = renderEvidencePackHtml(pack);
    } catch (err) {
      return respondInternalError(res, ROUTE, err as Error, { publicMessage: "Could not build your evidence pack. Try again." });
    }
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(html);
  }

  let pdf: Uint8Array;
  try {
    pdf = await renderEvidencePackPdf(pack);
  } catch (err) {
    return respondInternalError(res, ROUTE, err as Error, { publicMessage: "Could not produce the PDF. Try again." });
  }
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="security-evidence-pack-${pack.generatedAt.slice(0, 10)}.pdf"`);
  return res.status(200).send(Buffer.from(pdf));
}
