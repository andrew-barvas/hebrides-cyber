// Estate screenshots: one viewport JPEG of each live web host httpx found
// (the scanned page itself is captured inline by playwright.ts, #230), so the
// owner and a Lookout analyst can spot a forgotten test site, a default
// server page or an exposed login at a glance.
//
// Traffic: one page load per live host, the same as any visitor, and only
// when httpx ran (full, osint and Lookout's exposure profile). Covered by
// "load pages from your websites" in the Lookout traffic disclosure.
//
// Storage: a private Azure Blob container, like report PDFs, at
// <owner>/<scanId>/<host>.jpg. Nothing is public: the owner reads them through
// /api/scans/<id>/screenshots, which checks the scan is theirs. Deleted after
// RETENTION_DAYS by cleanup-retention.ts. Without
// AZURE_STORAGE_CONNECTION_STRING the step is skipped ("not_configured").
//
// Best-effort and post-completion: it never changes the scan's findings or
// score, and a failure is logged, not raised.
import type { HttpProbeRecord } from "./scanners/hostProbe";

/** ⚑ Owner decision (OT-42): hosts captured per scan. One constant for every plan for now. */
export const SCREENSHOT_HOST_CAP = 25;
export const SCREENSHOT_CONTAINER = "host-screenshots";
export const SCREENSHOT_RETENTION_DAYS = 90;
const PAGE_TIMEOUT_MS = 15_000;
const MAX_BYTES = 250_000;

/** Pure: which live hosts to capture, one URL per host, the target's own host excluded, capped. */
export function selectScreenshotTargets(records: HttpProbeRecord[], targetUrl: string, cap = SCREENSHOT_HOST_CAP): Array<{ host: string; url: string }> {
  let targetHost = "";
  try {
    targetHost = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    // an unparseable target excludes nothing
  }
  const byHost = new Map<string, string>();
  for (const r of records) {
    const host = (r.host ?? "").toLowerCase();
    if (!host || host === targetHost || byHost.has(host)) continue;
    if (r.statusCode < 200 || r.statusCode >= 400) continue;
    if (!/^https?:\/\//i.test(r.url)) continue;
    byHost.set(host, r.url);
  }
  return [...byHost.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(0, cap)
    .map(([host, url]) => ({ host, url }));
}

/** Pure: the blob name for one host's screenshot. The host is reduced to a safe file name. */
export function screenshotBlobName(owner: string, scanId: string, host: string): string {
  const safe = host.toLowerCase().replace(/[^a-z0-9.-]/g, "-").slice(0, 200);
  return `${owner}/${scanId}/${safe}.jpg`;
}

/** Pure: is this a file name the API may serve for a scan (no paths, our extension only)? */
export function isScreenshotFileName(value: unknown): value is string {
  return typeof value === "string" && /^[a-z0-9.-]{1,200}\.jpg$/.test(value) && !value.includes("..");
}

export type ScreenshotDeps = {
  /** Loads the URL and returns a JPEG, or throws. */
  capture: (url: string) => Promise<Buffer>;
  upload: (blobName: string, jpeg: Buffer) => Promise<void>;
};

/** Captures and uploads each target, one at a time; returns which hosts succeeded. */
export async function captureEstateScreenshots(
  owner: string,
  scanId: string,
  targets: Array<{ host: string; url: string }>,
  deps: ScreenshotDeps
): Promise<{ captured: string[]; failed: number }> {
  const captured: string[] = [];
  let failed = 0;
  for (const t of targets) {
    try {
      const jpeg = await deps.capture(t.url);
      if (jpeg.length === 0 || jpeg.length > MAX_BYTES) {
        failed++;
        continue;
      }
      await deps.upload(screenshotBlobName(owner, scanId, t.host), jpeg);
      captured.push(t.host);
    } catch {
      failed++;
    }
  }
  return { captured, failed };
}

export type EstateScreenshotsResult = { status: "completed"; captured: string[]; failed: number } | { status: "not_configured" } | { status: "error"; note: string };

/** The real run: Playwright Chromium and the Azure Blob container. */
export async function runEstateScreenshots(owner: string, scanId: string, targetUrl: string, records: HttpProbeRecord[]): Promise<EstateScreenshotsResult> {
  const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;
  if (!connectionString) return { status: "not_configured" };
  const targets = selectScreenshotTargets(records, targetUrl);
  if (targets.length === 0) return { status: "completed", captured: [], failed: 0 };

  const [{ chromium }, { BlobServiceClient }] = await Promise.all([import("playwright"), import("@azure/storage-blob")]);
  const container = BlobServiceClient.fromConnectionString(connectionString).getContainerClient(SCREENSHOT_CONTAINER);
  let browser: Awaited<ReturnType<typeof chromium.launch>> | null = null;
  try {
    await container.createIfNotExists(); // private: no public access level
    browser = await chromium.launch();
    const b = browser;
    const result = await captureEstateScreenshots(owner, scanId, targets, {
      capture: async (url) => {
        const page = await b.newPage({ viewport: { width: 1280, height: 720 } });
        try {
          await page.goto(url, { waitUntil: "load", timeout: PAGE_TIMEOUT_MS });
          return await page.screenshot({ type: "jpeg", quality: 45, timeout: 5_000 });
        } finally {
          await page.close().catch(() => undefined);
        }
      },
      upload: async (name, jpeg) => {
        await container.getBlockBlobClient(name).uploadData(jpeg, { blobHTTPHeaders: { blobContentType: "image/jpeg" } });
      },
    });
    return { status: "completed", ...result };
  } catch (err) {
    return { status: "error", note: `estate screenshots failed: ${(err as Error).message}` };
  } finally {
    await browser?.close().catch(() => undefined);
  }
}
