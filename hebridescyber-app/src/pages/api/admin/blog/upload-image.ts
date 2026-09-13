import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { BlobServiceClient } from "@azure/storage-blob";
import { requireAdmin } from "@/lib/adminAuth";
import { randomUUID } from "node:crypto";
import { parseBody } from "@/lib/validate";

const bodySchema = z.object({
  dataUrl: z.string().min(1, "dataUrl is required"),
  filename: z.string().min(1, "filename is required"),
});

export const config = {
  api: { bodyParser: { sizeLimit: "5mb" } },
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;
  if (!connectionString) {
    return res.status(503).json({ error: "AZURE_STORAGE_CONNECTION_STRING not set" });
  }

  const parsed = parseBody(bodySchema, req.body, res);
  if (!parsed) return;
  const { dataUrl, filename } = parsed;

  // dataUrl must be a valid base64 data URI (image/* only).
  const match = /^data:(image\/[a-zA-Z+]+);base64,(.+)$/.exec(dataUrl);
  if (!match) {
    return res.status(400).json({ error: "Invalid image data URL" });
  }
  const [, mimeType, base64Data] = match;
  const buffer = Buffer.from(base64Data, "base64");
  if (buffer.byteLength > 5 * 1024 * 1024) {
    return res.status(400).json({ error: "Image must be under 5 MB" });
  }

  const ext = filename.split(".").pop()?.toLowerCase() ?? "jpg";
  const blobName = `blog/${randomUUID()}.${ext}`;

  try {
    const blobServiceClient = BlobServiceClient.fromConnectionString(connectionString);
    const containerClient = blobServiceClient.getContainerClient(
      process.env.AZURE_STORAGE_CONTAINER ?? "public"
    );

    // Ensure container exists with public read access.
    await containerClient.createIfNotExists({ access: "blob" });

    const blobClient = containerClient.getBlockBlobClient(blobName);
    await blobClient.uploadData(buffer, {
      blobHTTPHeaders: { blobContentType: mimeType },
    });

    const url = blobClient.url;
    return res.status(200).json({ url });
  } catch (err) {
    console.error("[upload-image]", err);
    return res.status(500).json({ error: (err as Error).message });
  }
}
