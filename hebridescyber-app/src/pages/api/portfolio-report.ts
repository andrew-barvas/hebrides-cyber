// GET /api/portfolio-report — every site the account monitors, in one
// client-ready PDF (src/lib/portfolioReport.ts): worst site first, issues
// shared across sites, top priorities per site, white-labelled with the
// Agency's branding. `?format=html` returns the same report as HTML.
//
// Agency plan (planAccess.ts), session or API key (agencies automate their
// monthly client packs), rate-limited because each call launches Chromium.
// The PDF is streamed and never stored, so there is nothing to expire or to
// erase with the account.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { planGate } from "@/lib/planAccess";
import { checkRateLimit } from "@/lib/rateLimit";
import { loadPortfolioInput } from "@/lib/portfolioData";
import { renderPortfolioReportHtml } from "@/lib/portfolioReport";
import { htmlToPdf } from "@/lib/reportPdf";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const gate = await planGate(supabaseAdmin, caller.ownerId, "agency");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan — try again." });
  if (gate === "denied") return res.status(403).json({ error: "The portfolio report is part of the Agency plan.", code: "plan_required" });

  const limit = await checkRateLimit(caller.ownerId, "portfolio-report");
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Rate limit exceeded — try again later", retryAfterSeconds: limit.retryAfterSeconds });
  }

  let input;
  try {
    input = await loadPortfolioInput(supabaseAdmin, caller.ownerId);
  } catch (err) {
    console.error("[portfolio-report]", (err as Error).message);
    return res.status(500).json({ error: "Could not load your sites — try again." });
  }
  if (input.sites.length === 0) {
    return res.status(404).json({ error: "No monitored sites yet. Add sites under Assets first.", code: "no_sites" });
  }

  const html = renderPortfolioReportHtml(input);
  if (req.query.format === "html") {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(html);
  }

  const pdf = await htmlToPdf(html);
  const date = (input.now ?? new Date()).toISOString().slice(0, 10);
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="${input.branding ? "security" : "hebridescyber"}-portfolio-${date}.pdf"`);
  return res.status(200).send(pdf);
}
