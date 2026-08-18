// GET /api/generate-report?scan_id=... — renders the scan's findings as HTML
// and converts to PDF with Playwright. Two response modes:
//   - AZURE_STORAGE_CONNECTION_STRING set -> upload to Blob Storage, return
//     a short-lived (1h) SAS URL instead of the binary.
//   - Not set (local dev) -> return the PDF bytes directly.
//
// Rebuilt as a Next.js API route alongside run-scan — see that file's header
// for why. Fixed a real gap while porting: the original standalone Function
// (src/functions/generate-report) had NO auth check at all — any caller who
// knew or guessed a scan_id could download any customer's full report,
// findings included. This version requires the caller to own the scan (or
// be an admin), matching every other scan-scoped route in this codebase.
import type { NextApiRequest, NextApiResponse } from "next";
import { chromium } from "playwright";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";

const storageConnectionString = process.env.AZURE_STORAGE_CONNECTION_STRING ?? "";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const scanId = req.query.scan_id as string | undefined;
  if (!scanId) return res.status(400).json({ error: "scan_id query param is required" });

  const { data: scanResult, error } = await supabaseAdmin
    .from("scan_results")
    .select("*, scans(owner, target_url, created_at)")
    .eq("scan_id", scanId)
    .maybeSingle();

  if (error || !scanResult) return res.status(404).json({ error: error?.message ?? "Scan result not found" });

  const owner = (scanResult.scans as { owner?: string } | null)?.owner;
  if (owner !== caller.ownerId) {
    const { data: user } = await supabaseAdmin.from("users").select("is_admin").eq("id", caller.ownerId).maybeSingle();
    if (!user?.is_admin) return res.status(403).json({ error: "You do not own this scan" });
  }

  // Branded on the SCAN OWNER's plan, not the caller's — an admin viewing
  // someone else's report should see that owner's branding, not their own
  // (or lack thereof). Falls back to the default template unless the owner
  // is genuinely Agency-plan AND has actually set a logo/name — an Agency
  // account that hasn't configured anything yet must render identically to
  // today, not show a half-branded page.
  const { data: ownerSub } = await supabaseAdmin
    .from("subscriptions")
    .select("plan, brand_logo_url, brand_name")
    .eq("owner", owner)
    .maybeSingle();

  const branding =
    ownerSub?.plan === "agency" && (ownerSub.brand_logo_url || ownerSub.brand_name)
      ? { logoUrl: ownerSub.brand_logo_url ?? undefined, name: ownerSub.brand_name ?? undefined }
      : undefined;

  const html = renderReportHtml(scanResult, branding);

  // Unique temp directory per invocation so concurrent requests never
  // collide, cleaned up in `finally` regardless of success/failure.
  const tempDir = await mkdtemp(path.join(tmpdir(), "hebridescyber-report-"));
  const pdfPath = path.join(tempDir, `report-${scanId}.pdf`);

  try {
    // TODO: in production, run Playwright with no network egress beyond what's
    // needed to render local HTML, to avoid SSRF risk from the report template.
    // No longer strictly zero-network as of Agency branding: a configured
    // brand_logo_url is fetched during render. Narrow in practice (an
    // Azure Blob URL we control, not attacker-supplied), but worth knowing
    // if this TODO is ever actually addressed.
    const browser = await chromium.launch();
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "networkidle" });
    await page.pdf({ path: pdfPath, format: "A4", printBackground: true });
    await browser.close();

    const pdfBuffer = await readFile(pdfPath);

    if (storageConnectionString) {
      const url = await uploadToBlobStorage(pdfBuffer, `report-${scanId}.pdf`);
      return res.status(200).json({ url, expiresInSeconds: 3600 });
    }

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="hebridescyber-report-${scanId}.pdf"`);
    return res.status(200).send(pdfBuffer);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

/**
 * Uploads the PDF to Azure Blob Storage (container "reports", created if
 * missing) and returns a 1-hour, read-only SAS URL.
 *
 * TODO: retention (see docs/security.md — 90-day default) is not enforced
 * here — add a lifecycle management policy on the storage account (or a
 * scheduled cleanup job) rather than relying on this code path to delete old
 * reports.
 */
async function uploadToBlobStorage(pdfBuffer: Buffer, blobName: string): Promise<string> {
  const { BlobServiceClient, generateBlobSASQueryParameters, BlobSASPermissions, StorageSharedKeyCredential } =
    await import("@azure/storage-blob");

  const blobService = BlobServiceClient.fromConnectionString(storageConnectionString);
  const container = blobService.getContainerClient("reports");
  await container.createIfNotExists();

  const blockBlob = container.getBlockBlobClient(blobName);
  await blockBlob.uploadData(pdfBuffer, { blobHTTPHeaders: { blobContentType: "application/pdf" } });

  // fromConnectionString gives us a client whose credential may or may not
  // support generateSasUrl() directly depending on how it authenticated —
  // build the shared-key credential explicitly from the connection string
  // so SAS generation is reliable regardless.
  const accountNameMatch = storageConnectionString.match(/AccountName=([^;]+)/);
  const accountKeyMatch = storageConnectionString.match(/AccountKey=([^;]+)/);
  if (!accountNameMatch || !accountKeyMatch) {
    throw new Error("AZURE_STORAGE_CONNECTION_STRING is missing AccountName/AccountKey — cannot generate a SAS URL.");
  }
  const credential = new StorageSharedKeyCredential(accountNameMatch[1], accountKeyMatch[1]);

  const sas = generateBlobSASQueryParameters(
    {
      containerName: "reports",
      blobName,
      permissions: BlobSASPermissions.parse("r"),
      expiresOn: new Date(Date.now() + 60 * 60 * 1000),
    },
    credential
  ).toString();

  return `${blockBlob.url}?${sas}`;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function renderReportHtml(scanResult: Record<string, any>, branding?: { logoUrl?: string; name?: string }): string {
  // Minimal inline template. See marketing/04-security-score-template.md for
  // the full report structure this should eventually match (executive
  // summary, top 5 findings, risk breakdown, action plan, appendix).
  const targetUrl = scanResult.scans?.target_url ?? "unknown";
  const summary: string = scanResult.summary ?? scanResult.results?.ai_summary ?? "No summary available.";
  const score: number | undefined = scanResult.score;
  const findings: Array<{ severity: string; title: string; detail: string }> = scanResult.results?.findings ?? [];

  // Swapped in only when branding is actually set — see the caller's gate
  // (Agency plan AND a configured logo/name). No branding means this
  // renders byte-for-byte the same fixed header as before this feature.
  const headerHtml = branding
    ? `<div style="display:flex;align-items:center;gap:12px;">
         ${branding.logoUrl ? `<img src="${escapeHtml(branding.logoUrl)}" alt="${escapeHtml(branding.name ?? "Logo")}" style="height:40px;max-width:160px;object-fit:contain;" />` : ""}
         <h1 style="margin:0;">${escapeHtml(branding.name ?? "Security Score Report")}</h1>
       </div>`
    : `<h1>Hebrides Cyber — Security Score Report</h1>`;

  const findingsRows = findings
    .map(
      (f) => `
        <tr>
          <td style="text-transform: uppercase; font-weight: bold;">${escapeHtml(f.severity)}</td>
          <td>${escapeHtml(f.title)}</td>
          <td>${escapeHtml(f.detail)}</td>
        </tr>`
    )
    .join("");

  return `
    <html>
      <head>
        <meta charset="utf-8" />
        <style>
          body { font-family: Arial, sans-serif; color: #2F3A44; padding: 40px; }
          h1 { color: #0B3D5B; }
          table { width: 100%; border-collapse: collapse; margin-top: 16px; }
          td, th { border-bottom: 1px solid #ddd; padding: 8px; text-align: left; font-size: 13px; }
        </style>
      </head>
      <body>
        ${headerHtml}
        <p><strong>Target:</strong> ${escapeHtml(targetUrl)}</p>
        <p><strong>Generated:</strong> ${new Date().toISOString()}</p>
        ${score !== undefined ? `<p><strong>Score:</strong> ${score} / 100</p>` : ""}
        <h2>Executive Summary</h2>
        <p>${escapeHtml(summary)}</p>
        <h2>Findings</h2>
        <table>
          <thead><tr><th>Severity</th><th>Issue</th><th>Detail</th></tr></thead>
          <tbody>${findingsRows || "<tr><td colspan=\"3\">No findings recorded.</td></tr>"}</tbody>
        </table>
        <h2>Raw Results (Appendix)</h2>
        <pre style="white-space: pre-wrap; font-size: 11px;">${escapeHtml(JSON.stringify(scanResult.results, null, 2))}</pre>
      </body>
    </html>
  `;
}

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
