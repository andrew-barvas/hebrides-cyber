// HTML → PDF with headless Chromium, for scheduled reports only
// (send-scheduled-reports.ts), which run in GitHub Actions where Chromium is
// installed. Never import this from an API route: those run as Azure Static
// Web Apps managed Functions, which have no Chromium, so every call failed
// with a 500. API routes use htmlPdf.ts (pdf-lib, no browser) instead. The
// report templates are self-contained HTML; the only thing a render may fetch
// is an Agency's https logo (executiveReport.ts's safeLogoUrl).
import { chromium } from "playwright";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

export async function htmlToPdf(html: string): Promise<Buffer> {
  // Unique directory per call so concurrent renders never collide; removed whatever happens.
  const dir = await mkdtemp(path.join(tmpdir(), "hebridescyber-report-"));
  const out = path.join(dir, "report.pdf");
  try {
    const browser = await chromium.launch();
    try {
      const page = await browser.newPage();
      await page.setContent(html, { waitUntil: "networkidle" });
      await page.pdf({ path: out, format: "A4", printBackground: true });
    } finally {
      await browser.close();
    }
    return await readFile(out);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
