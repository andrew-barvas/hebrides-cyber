// GET /api/admin/lookout/report-pdf?id=<report id> — an admin's preview of
// any Lookout report as the customer will get it, drafts included (marked
// DRAFT). Same renderer as /api/lookout/report-pdf.
import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { htmlToPdf } from "@/lib/reportPdf";
import { loadEstateGallery, loadReportForPdf, lookoutPdfFileName, renderLookoutReportHtml } from "@/lib/lookoutReportPdf";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });
  const id = String(req.query.id ?? "");

  let loaded;
  try {
    loaded = await loadReportForPdf(supabaseAdmin, id);
  } catch (err) {
    return res.status(500).json({ error: (err as Error).message });
  }
  if (!loaded) return res.status(404).json({ error: "Report not found" });

  const gallery = await loadEstateGallery(supabaseAdmin, loaded.customer, loaded.report.period_end);
  const html = renderLookoutReportHtml({ report: loaded.report, items: loaded.items, gallery });
  res.setHeader("Cache-Control", "no-store");
  if (req.query.format === "html") {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(html);
  }
  try {
    const pdf = await htmlToPdf(html);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${loaded.report.status === "draft" ? "draft-" : ""}${lookoutPdfFileName(loaded.report)}"`);
    return res.status(200).send(pdf);
  } catch (err) {
    return res.status(500).json({ error: `PDF render failed: ${(err as Error).message}` });
  }
}
