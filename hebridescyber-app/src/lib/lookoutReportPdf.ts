// The Lookout report as a dated PDF (NEXT-BUILDS-DESIGN-2026-11.md task 5:
// "publishes a dated PDF and portal page"), with the estate gallery from the
// per-host screenshots (#241). The HTML is self-contained, as reportPdf.ts
// requires: the only images are JPEG data URIs, so a render fetches nothing.
import type { SupabaseClient } from "@supabase/supabase-js";
import { escapeHtml, REPORT_MUTED, REPORT_TEXT } from "./executiveReport";
import { isScreenshotFileName, SCREENSHOT_CONTAINER } from "./estateScreenshots";
import type { ReportStatus } from "./lookoutReports";
import type { ReportLookalikes } from "./lookoutLookalikes";
import type { ReportBreaches } from "./lookoutBreaches";

export const GALLERY_MAX = 12;
const GALLERY_SCANS = 5;
const MAX_IMAGE_BYTES = 250 * 1024;

export type LookoutPdfReport = {
  period_start: string;
  period_end: string;
  status: ReportStatus;
  summary: string;
  published_at: string | null;
  acknowledged_at: string | null;
};
export type LookoutPdfItem = { host: string; severity: string; title: string; priority: number; analyst_note: string; business_impact: string; fix_owner: string | null };
export type GalleryImage = { host: string; dataUri: string };
export type LookoutPdfInput = { report: LookoutPdfReport; items: LookoutPdfItem[]; gallery: GalleryImage[]; lookalikes?: ReportLookalikes; breaches?: ReportBreaches; now?: Date };

const SEVERITY_COLOUR: Record<string, string> = { critical: "#7f1d1d", high: "#b91c1c", medium: "#b45309", low: "#1d4ed8", info: "#475569" };
const FIX_OWNER_LABEL: Record<string, string> = { customer: "You", it_supplier: "Your IT supplier", hosting_provider: "Your hosting provider", unknown: "To be agreed" };
const JPEG_DATA_URI = /^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/;

/** Pure. */
export function renderLookoutReportHtml(input: LookoutPdfInput): string {
  const e = escapeHtml;
  const { report } = input;
  const generated = (input.now ?? new Date()).toISOString().slice(0, 10);
  const items = [...input.items].sort((a, b) => a.priority - b.priority);
  const gallery = input.gallery.filter((g) => JPEG_DATA_URI.test(g.dataUri)).slice(0, GALLERY_MAX);
  const paragraphs = report.summary
    .split(/\r?\n\s*\r?\n/)
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => `<p>${e(p).replace(/\r?\n/g, "<br>")}</p>`)
    .join("");

  const rows = items
    .map(
      (it, n) => `<div class="item">
      <h3>${n + 1}. <span class="sev" style="background:${SEVERITY_COLOUR[it.severity] ?? SEVERITY_COLOUR.info}">${e(it.severity)}</span> ${e(it.title)}</h3>
      <div class="muted">${e(it.host)}${it.fix_owner ? ` · Who fixes it: ${e(FIX_OWNER_LABEL[it.fix_owner] ?? it.fix_owner)}` : ""}</div>
      ${it.business_impact.trim() ? `<p><b>Why it matters:</b> ${e(it.business_impact.trim())}</p>` : ""}
      ${it.analyst_note.trim() ? `<p><b>Engineer's note:</b> ${e(it.analyst_note.trim())}</p>` : ""}
    </div>`
    )
    .join("");

  const galleryHtml = gallery.length
    ? `<h2>Your sites at a glance</h2>
       <p class="muted">What each live website showed when we last looked. Anything you don't recognise is worth asking about.</p>
       <div class="gallery">${gallery.map((g) => `<figure><img src="${g.dataUri}" alt="" /><figcaption>${e(g.host)}</figcaption></figure>`).join("")}</div>`
    : "";

  const lookalikes = input.lookalikes;
  const lookalikeHtml =
    lookalikes?.available && lookalikes.newInPeriod.length > 0
      ? `<h2>Lookalike domains</h2>
       <p class="muted">Registered domains one character away from yours, with a certificate already issued: a common setup for phishing your customers or staff. They may be unrelated to you; it's worth checking who owns them and what they show.</p>
       <table><thead><tr><th>Domain</th><th>How it differs</th><th>Spotted</th></tr></thead><tbody>${lookalikes.newInPeriod
         .map((l) => `<tr><td><b>${e(l.domain)}</b> <span class="muted">(looks like ${e(l.targetDomain)})</span></td><td>${e(l.how)}</td><td>${e(l.spottedAt.slice(0, 10))}</td></tr>`)
         .join("")}</tbody></table>
       <p class="muted">${lookalikes.totalKnown} lookalike domain${lookalikes.totalKnown === 1 ? "" : "s"} known in all.</p>`
      : lookalikes?.available
        ? `<h2>Lookalike domains</h2><p class="muted">No new lookalike domains of yours were spotted this period${lookalikes.totalKnown ? ` (${lookalikes.totalKnown} known from before)` : ""}.</p>`
        : "";

  const breachHtml = input.breaches?.available
    ? `<h2>Email addresses in known data breaches</h2>
       <p class="muted">From the Have I Been Pwned breach database. Anyone listed should change that password (and anywhere it was reused) and turn on multi-factor sign-in. We never see or store the addresses themselves.</p>
       ${input.breaches.sites
         .map((s) =>
           s.status === "not_verified"
             ? `<p><b>${e(s.host)}</b>: <span class="muted">not enabled yet. The domain needs verifying with Have I Been Pwned; your engineer can arrange this.</span></p>`
             : s.breaches.length === 0
               ? `<p><b>${e(s.host)}</b>: no addresses found in known breaches.</p>`
               : `<p><b>${e(s.host)}</b>: ${s.affectedAliasCount} address${s.affectedAliasCount === 1 ? "" : "es"} found.</p>
                  <table><thead><tr><th>Breach</th><th>When</th><th>Addresses</th><th>What leaked</th></tr></thead><tbody>${s.breaches
                    .map((b) => `<tr><td>${e(b.title)}</td><td>${e(b.breachDate ?? "")}</td><td>${b.affectedAliasCount}</td><td>${e(b.dataClasses.slice(0, 5).join(", "))}</td></tr>`)
                    .join("")}</tbody></table>`
         )
         .join("")}`
    : "";

  const state =
    report.status === "draft"
      ? '<div class="draft">DRAFT — not yet published to the customer</div>'
      : report.acknowledged_at
        ? `<div class="muted">Read and acknowledged ${e(report.acknowledged_at.slice(0, 10))}</div>`
        : "";

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><title>Hebrides Cyber Lookout report ${e(report.period_start)} to ${e(report.period_end)}</title>
<style>
  @page { size: A4; margin: 18mm 16mm; }
  body { font-family: Arial, Helvetica, sans-serif; color: ${REPORT_TEXT}; font-size: 12px; line-height: 1.45; }
  h1 { font-size: 22px; margin: 0; color: #0b3d5b; } h2 { font-size: 15px; margin: 22px 0 8px; color: #0b3d5b; border-bottom: 1px solid #d5dde5; padding-bottom: 4px; }
  h3 { font-size: 13px; margin: 0 0 2px; }
  .head { border-bottom: 3px solid #0b3d5b; padding-bottom: 12px; }
  .muted { color: ${REPORT_MUTED}; }
  .draft { margin-top: 8px; color: #b45309; font-weight: bold; letter-spacing: 0.04em; }
  .sev { display: inline-block; color: #fff; text-transform: uppercase; font-size: 9px; font-weight: bold; padding: 2px 6px; border-radius: 4px; vertical-align: middle; }
  table { width: 100%; border-collapse: collapse; } th, td { text-align: left; padding: 5px 6px; border-bottom: 1px solid #e4e9ee; vertical-align: top; }
  th { font-size: 10px; text-transform: uppercase; color: ${REPORT_MUTED}; }
  .item { page-break-inside: avoid; border-bottom: 1px solid #e4e9ee; padding: 10px 0; } .item p { margin: 4px 0 0; }
  .gallery { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
  figure { margin: 0; page-break-inside: avoid; } figure img { width: 100%; border: 1px solid #d5dde5; border-radius: 4px; }
  figcaption { font-size: 10px; color: ${REPORT_MUTED}; margin-top: 2px; word-break: break-all; }
  .foot { margin-top: 26px; border-top: 1px solid #d5dde5; padding-top: 8px; font-size: 10px; color: ${REPORT_MUTED}; }
</style></head>
<body>
  <div class="head"><h1>Lookout report</h1>
    <div class="muted">${e(report.period_start)} to ${e(report.period_end)}${report.published_at ? ` · published ${e(report.published_at.slice(0, 10))}` : ""} · generated ${e(generated)}</div>
    ${state}
  </div>

  <h2>Summary</h2>
  ${paragraphs || '<p class="muted">No summary was written for this period.</p>'}

  <h2>What to fix, in order</h2>
  ${rows || '<p class="muted">Nothing needs fixing from this period.</p>'}

  ${lookalikeHtml}

  ${breachHtml}

  ${galleryHtml}

  <div class="foot">Prepared by a Hebrides Cyber engineer from automated external checks of what is reachable from the internet. It is an indicator, not a certification or a penetration test. Acknowledging this report records that you've read it; it isn't acceptance of any risk.</div>
</body></html>`;
}

/**
 * Up to GALLERY_MAX screenshots from the customer's most recent scan, on or
 * before the period's end, that has any. Empty when storage isn't configured
 * or nothing was captured: the report is still complete without it.
 */
export async function loadEstateGallery(supabaseAdmin: SupabaseClient, customer: string, periodEnd: string): Promise<GalleryImage[]> {
  const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;
  if (!connectionString) return [];
  const until = new Date(`${periodEnd}T23:59:59Z`).toISOString();
  const { data: scans } = await supabaseAdmin
    .from("scans")
    .select("id")
    .eq("owner", customer)
    .eq("status", "completed")
    .lte("created_at", until)
    .order("created_at", { ascending: false })
    .limit(GALLERY_SCANS);
  if (!scans?.length) return [];
  try {
    const { BlobServiceClient } = await import("@azure/storage-blob");
    const container = BlobServiceClient.fromConnectionString(connectionString).getContainerClient(SCREENSHOT_CONTAINER);
    if (!(await container.exists())) return [];
    for (const scan of scans as Array<{ id: string }>) {
      const prefix = `${customer}/${scan.id}/`;
      const names: string[] = [];
      for await (const blob of container.listBlobsFlat({ prefix })) {
        const file = blob.name.slice(prefix.length);
        if (isScreenshotFileName(file) && (blob.properties.contentLength ?? 0) <= MAX_IMAGE_BYTES) names.push(file);
      }
      if (names.length === 0) continue;
      const images: GalleryImage[] = [];
      for (const file of names.sort().slice(0, GALLERY_MAX)) {
        const buffer = await container.getBlockBlobClient(prefix + file).downloadToBuffer();
        images.push({ host: file.replace(/\.jpg$/, ""), dataUri: `data:image/jpeg;base64,${buffer.toString("base64")}` });
      }
      return images;
    }
  } catch (err) {
    console.error("[lookout-pdf] gallery unavailable:", (err as Error).message);
  }
  return [];
}

export type ReportForPdf = { customer: string; report: LookoutPdfReport; items: LookoutPdfItem[] };

/** The report and its included items; null when there's no such report. Throws on a read error. */
export async function loadReportForPdf(supabaseAdmin: SupabaseClient, id: string): Promise<ReportForPdf | null> {
  const { data, error } = await supabaseAdmin
    .from("lookout_reports")
    .select("customer, period_start, period_end, status, summary, published_at, acknowledged_at")
    .eq("id", id)
    .maybeSingle();
  if (error) throw new Error(error.message);
  if (!data) return null;
  const { data: items, error: itemsError } = await supabaseAdmin
    .from("lookout_report_items")
    .select("host, severity, title, priority, analyst_note, business_impact, fix_owner")
    .eq("report_id", id)
    .eq("included", true)
    .order("priority", { ascending: true });
  if (itemsError) throw new Error(itemsError.message);
  const { customer, ...report } = data as LookoutPdfReport & { customer: string };
  return { customer, report, items: (items ?? []) as LookoutPdfItem[] };
}

export function lookoutPdfFileName(report: Pick<LookoutPdfReport, "period_end">): string {
  return `lookout-report-${report.period_end}.pdf`;
}
