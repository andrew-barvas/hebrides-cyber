// GET /api/scans/<id>/screenshots/<file> — one estate screenshot (JPEG), for
// the scan's owner only. The blob path is built from the caller's own id and
// the scan id, never from the request beyond a validated file name, so one
// owner can't read another's images.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { SCREENSHOT_CONTAINER, isScreenshotFileName } from "@/lib/estateScreenshots";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const scanId = String(req.query.id ?? "");
  const file = req.query.file;
  if (!isScreenshotFileName(file)) return res.status(400).json({ error: "Invalid file name" });
  const { data: scan } = await supabaseAdmin.from("scans").select("id, owner").eq("id", scanId).maybeSingle();
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if ((scan as { owner: string }).owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;
  if (!connectionString) return res.status(404).json({ error: "Not found" });
  try {
    const { BlobServiceClient } = await import("@azure/storage-blob");
    const blob = BlobServiceClient.fromConnectionString(connectionString)
      .getContainerClient(SCREENSHOT_CONTAINER)
      .getBlockBlobClient(`${caller.ownerId}/${scanId}/${file}`);
    if (!(await blob.exists())) return res.status(404).json({ error: "Not found" });
    const jpeg = await blob.downloadToBuffer();
    res.setHeader("Content-Type", "image/jpeg");
    res.setHeader("Cache-Control", "private, max-age=3600");
    return res.status(200).send(jpeg);
  } catch (err) {
    return respondInternalError(res, "scans/screenshots/file", err as Error);
  }
}
