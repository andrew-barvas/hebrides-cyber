// Azure Function (HTTP trigger): generate-report
//
// Fetches scan results from Supabase, renders an HTML report, and converts
// it to PDF with Playwright. Uses safe temp file handling: everything
// happens in the OS temp dir under a unique subfolder, and the folder is
// removed in a `finally` block regardless of success/failure.
//
// Two response modes:
//   - AZURE_STORAGE_CONNECTION_STRING is set → upload the PDF to Blob
//     Storage and return a short-lived SAS URL (does not hold the binary
//     in the HTTP response).
//   - Not set (local dev) → return the PDF bytes directly with
//     Content-Type: application/pdf.

import { createClient } from "@supabase/supabase-js";
import { chromium } from "playwright"; // TODO: add "playwright" to package.json when wiring this up in the real Functions app
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

type HttpRequest = { query: { scan_id?: string } };
type HttpResponseInit = { status: number; body?: Buffer; headers?: Record<string, string>; jsonBody?: unknown };

const supabaseUrl = process.env.SUPABASE_URL ?? "";
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey);
const storageConnectionString = process.env.AZURE_STORAGE_CONNECTION_STRING ?? "";

export default async function generateReport(req: HttpRequest): Promise<HttpResponseInit> {
  const scanId = req.query.scan_id;
  if (!scanId) {
    return { status: 400, jsonBody: { error: "scan_id query param is required" } };
  }

  const { data: scanResult, error } = await supabaseAdmin
    .from("scan_results")
    .select("*, scans(target_url, created_at)")
    .eq("scan_id", scanId)
    .maybeSingle();

  if (error || !scanResult) {
    return { status: 404, jsonBody: { error: error?.message ?? "Scan result not found" } };
  }

  const html = renderReportHtml(scanResult);

  // --- Safe temp file handling -----------------------------------------
  // Create a unique temp directory per invocation so concurrent requests
  // never collide, and always clean up afterwards.
  const tempDir = await mkdtemp(path.join(tmpdir(), "hebridescyber-report-"));
  const pdfPath = path.join(tempDir, `report-${scanId}.pdf`);

  try {
    // TODO: in production, run Playwright in a container with no network
    // egress beyond what's needed to render local HTML, to avoid SSRF risk
    // from the report template.
    const browser = await chromium.launch();
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "networkidle" });
    await page.pdf({ path: pdfPath, format: "A4", printBackground: true });
    await browser.close();

    const pdfBuffer = await readFile(pdfPath);

    if (storageConnectionString) {
      const url = await uploadToBlobStorage(pdfBuffer, `report-${scanId}.pdf`);
      return { status: 200, jsonBody: { url, expiresInSeconds: 3600 } };
    }

    return {
      status: 200,
      body: pdfBuffer,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="hebridescyber-report-${scanId}.pdf"`,
      },
    };
  } finally {
    // Always clean up the temp directory, even if PDF generation failed.
    await rm(tempDir, { recursive: true, force: true });
  }
}

/**
 * Uploads the PDF to Azure Blob Storage (container "reports", created if
 * missing) and returns a 1-hour, read-only SAS URL.
 *
 * TODO: retention (see docs/security.md — 90-day default) is not enforced
 * here — add a lifecycle management policy on the storage account (or a
 * scheduled cleanup Function) rather than relying on this code path to
 * delete old reports. SAS expiry of 1 hour is a conservative default;
 * revisit if customers need to share report links for longer.
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
      expiresOn: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
    },
    credential
  ).toString();

  return `${blockBlob.url}?${sas}`;
}

function renderReportHtml(scanResult: Record<string, any>): string {
  // Minimal inline template. See marketing/04-security-score-template.md
  // for the full report structure this should eventually match (executive
  // summary, top 5 findings, risk breakdown, action plan, appendix).
  // TODO: extract this into a proper templating approach (e.g. a .html
  // file with placeholders, or a small JSX-to-string renderer) once the
  // report format is finalised.
  const targetUrl = scanResult.scans?.target_url ?? "unknown";
  const summary: string = scanResult.summary ?? scanResult.results?.ai_summary ?? "No summary available.";
  const score: number | undefined = scanResult.score;
  const findings: Array<{ severity: string; title: string; detail: string }> = scanResult.results?.findings ?? [];

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
        <h1>Hebrides Cyber — Security Score Report</h1>
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
