// GET /api/scans/<id>/screenshots — the estate screenshots stored for a scan
// (src/lib/estateScreenshots.ts): { available, items: [{ host, file }] }.
// The scan's owner only. Images are fetched one at a time from
// /api/scans/<id>/screenshots/<file>. Without Azure storage configured this
// answers { available: false }.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { SCREENSHOT_CONTAINER } from "@/lib/estateScreenshots";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const scanId = String(req.query.id ?? "");
  const { data: scan } = await supabaseAdmin.from("scans").select("id, owner").eq("id", scanId).maybeSingle();
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if ((scan as { owner: string }).owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;
  if (!connectionString) return res.status(200).json({ available: false, items: [] });
  try {
    const { BlobServiceClient } = await import("@azure/storage-blob");
    const container = BlobServiceClient.fromConnectionString(connectionString).getContainerClient(SCREENSHOT_CONTAINER);
    if (!(await container.exists())) return res.status(200).json({ available: true, items: [] });
    const prefix = `${caller.ownerId}/${scanId}/`;
    const items: Array<{ host: string; file: string }> = [];
    for await (const blob of container.listBlobsFlat({ prefix })) {
      const file = blob.name.slice(prefix.length);
      items.push({ host: file.replace(/\.jpg$/, ""), file });
    }
    items.sort((a, b) => a.host.localeCompare(b.host));
    return res.status(200).json({ available: true, items });
  } catch (err) {
    return respondInternalError(res, "scans/screenshots", err as Error);
  }
}
