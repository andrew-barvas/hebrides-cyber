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
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { subscriptionGrants } from "@/lib/planAccess";
import { checkRateLimit } from "@/lib/rateLimit";
import { renderExecutiveReportHtml } from "@/lib/executiveReport";
import { htmlToPdf } from "@/lib/reportPdf";
import { loadTriageIndexForTarget } from "@/lib/findingTriage";
import type { Finding } from "@/lib/scanners";

const storageConnectionString = process.env.AZURE_STORAGE_CONNECTION_STRING ?? "";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  // E-12 (docs/ENHANCEMENTS.md): launches a headless Chromium per call,
  // uncapped before this.
  const limit = await checkRateLimit(caller.ownerId, "generate-report");
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Rate limit exceeded — try again later", retryAfterSeconds: limit.retryAfterSeconds });
  }

  const scanId = req.query.scan_id as string | undefined;
  if (!scanId) return res.status(400).json({ error: "scan_id query param is required" });

  const { data: scanResult, error } = await supabaseAdmin
    .from("scan_results")
    .select("*, scans(owner, target_url, created_at)")
    .eq("scan_id", scanId)
    .order("created_at", { ascending: false })
    .limit(1)
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
    .select("plan, status, brand_logo_url, brand_name")
    .eq("owner", owner)
    .maybeSingle();

  const branding =
    subscriptionGrants(ownerSub, "agency") && ownerSub && (ownerSub.brand_logo_url || ownerSub.brand_name)
      ? { logoUrl: ownerSub.brand_logo_url ?? undefined, name: ownerSub.brand_name ?? undefined }
      : undefined;

  // The customer's triage decisions are respected: false positives are left out
  // of a client-facing report, accepted/snoozed risks are listed separately.
  const targetUrl: string = scanResult.scans?.target_url ?? "unknown";
  const { index: triage } = await loadTriageIndexForTarget(supabaseAdmin, owner as string, targetUrl);
  const results = (scanResult.results ?? null) as Record<string, unknown> | null;

  const html = renderExecutiveReportHtml({
    targetUrl,
    scannedAt: (scanResult.scans as { created_at?: string } | null)?.created_at ?? scanResult.created_at ?? null,
    score: typeof scanResult.score === "number" ? scanResult.score : null,
    summary: scanResult.summary ?? (results?.ai_summary as string | undefined) ?? null,
    findings: ((results?.findings as Finding[] | undefined) ?? []),
    results,
    triage,
    branding,
  });

  // A configured brand_logo_url is fetched during render — an https URL we
  // store (Agency branding), checked by safeLogoUrl; nothing else is.
  const pdfBuffer = await htmlToPdf(html);

  if (storageConnectionString) {
    const url = await uploadToBlobStorage(pdfBuffer, `report-${scanId}.pdf`);
    return res.status(200).json({ url, expiresInSeconds: 3600 });
  }

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="${branding ? "security" : "hebridescyber"}-report-${scanId}.pdf"`);
  return res.status(200).send(pdfBuffer);
}

/**
 * Uploads the PDF to Azure Blob Storage (container "reports", created if
 * missing) and returns a 1-hour, read-only SAS URL.
 *
 * Retention (90 days, docs/security.md) is enforced separately by
 * src/scripts/cleanup-retention.ts, run nightly — not by this code path.
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
