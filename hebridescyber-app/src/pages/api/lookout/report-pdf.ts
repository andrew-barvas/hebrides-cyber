// GET /api/lookout/report-pdf?id=<report id> — the signed-in customer's
// published Lookout report as a dated PDF, with the estate gallery
// (lookoutReportPdf.ts). Drafts and other customers' reports answer 404, as
// /api/lookout/reports/<id> does. Rate-limited because each call launches
// Chromium. ?format=html returns the HTML instead (for checking the layout).
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { checkRateLimit } from "@/lib/rateLimit";
import { htmlToPdf } from "@/lib/reportPdf";
import { loadReportLookalikes } from "@/lib/lookoutLookalikes";
import { loadReportBreaches } from "@/lib/lookoutBreaches";
import { loadEstateGallery, loadReportForPdf, lookoutPdfFileName, renderLookoutReportHtml } from "@/lib/lookoutReportPdf";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  const id = String(req.query.id ?? "");
  if (!/^[0-9a-f-]{36}$/i.test(id)) return res.status(404).json({ error: "Report not found" });

  let loaded;
  try {
    loaded = await loadReportForPdf(supabaseAdmin, id);
  } catch (err) {
    return respondInternalError(res, "lookout/report-pdf", err as Error);
  }
  if (!loaded || loaded.customer !== caller.ownerId || loaded.report.status === "draft") return res.status(404).json({ error: "Report not found" });

  const limit = await checkRateLimit(caller.ownerId, "lookout-report-pdf");
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Rate limit exceeded — try again later", retryAfterSeconds: limit.retryAfterSeconds });
  }

  const [gallery, lookalikes, breaches] = await Promise.all([
    loadEstateGallery(supabaseAdmin, loaded.customer, loaded.report.period_end),
    loadReportLookalikes(supabaseAdmin, loaded.customer, loaded.report.period_start, loaded.report.period_end),
    loadReportBreaches(supabaseAdmin, loaded.customer, loaded.report.period_end),
  ]);
  const html = renderLookoutReportHtml({ report: loaded.report, items: loaded.items, gallery, lookalikes, breaches });
  res.setHeader("Cache-Control", "no-store");
  if (req.query.format === "html") {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(html);
  }
  try {
    const pdf = await htmlToPdf(html);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${lookoutPdfFileName(loaded.report)}"`);
    return res.status(200).send(pdf);
  } catch (err) {
    return respondInternalError(res, "lookout/report-pdf", err as Error, { publicMessage: "Could not produce the PDF. Try again." });
  }
}
