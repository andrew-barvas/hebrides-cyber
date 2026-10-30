// Agency-only white-label branding for PDF reports (see generate-report.ts,
// which is not wired up to read these fields yet — that swap is being made
// by hand elsewhere; this route only owns writing/reading the two columns).
//
// Upload logic mirrors src/pages/api/admin/blog/upload-image.ts exactly
// (base64 data-URL, image/* only, 5 MB cap, Azure Blob Storage), but:
//   - session-authenticated as the account owner, not requireAdmin — this is
//     the user branding their own reports, not a CMS action.
//   - gated server-side to Agency and up (planGate) by reading the caller's
//     own subscriptions row. Never trust a client-supplied plan claim.
//   - blobs land under `branding/` instead of `blog/`.
//
// Session-only (mirrors src/pages/api/webhooks.ts): this is an account-
// settings mutation driven from the dashboard UI, not something an API-key
// caller (CI, the Action, scripts) has a reason to do on its own.
//
// Also accepts a plain-text brandName in the same request so the UI can save
// logo and name from one form without two routes.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { BlobServiceClient } from "@azure/storage-blob";
import { randomUUID } from "node:crypto";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { planGate } from "@/lib/planAccess";
import { parseBody } from "@/lib/validate";

export const config = {
  api: { bodyParser: { sizeLimit: "5mb" } },
};

const MAX_BRAND_NAME_LENGTH = 80;

const bodySchema = z.object({
  dataUrl: z.string().optional(),
  filename: z.string().optional(),
  brandName: z.string().max(MAX_BRAND_NAME_LENGTH, `brandName must be ${MAX_BRAND_NAME_LENGTH} characters or fewer`).optional(),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  if (caller.via !== "session") {
    return res.status(403).json({ error: "Branding can only be managed from a logged-in session, not with an API key." });
  }

  const gate = await planGate(supabaseAdmin, caller.ownerId, "agency");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan — try again." });
  if (gate === "denied") {
    return res.status(403).json({ error: "White-label branding is an Agency-plan feature." });
  }

  const parsed = parseBody(bodySchema, req.body, res);
  if (!parsed) return;
  const { dataUrl, filename, brandName } = parsed;

  if (!dataUrl && brandName === undefined) {
    return res.status(400).json({ error: "Provide dataUrl (with filename) and/or brandName" });
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const update: Record<string, any> = {};

  if (dataUrl) {
    if (!filename) return res.status(400).json({ error: "filename is required when uploading a logo" });

    const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;
    if (!connectionString) {
      return res.status(503).json({ error: "AZURE_STORAGE_CONNECTION_STRING not set" });
    }

    // dataUrl must be a valid base64 data URI (image/* only).
    const match = /^data:(image\/[a-zA-Z+]+);base64,(.+)$/.exec(dataUrl);
    if (!match) {
      return res.status(400).json({ error: "Invalid image data URL" });
    }
    const [, mimeType, base64Data] = match;
    const buffer = Buffer.from(base64Data, "base64");
    if (buffer.byteLength > 5 * 1024 * 1024) {
      return res.status(400).json({ error: "Logo must be under 5 MB" });
    }

    const ext = filename.split(".").pop()?.toLowerCase() ?? "png";
    const blobName = `branding/${caller.ownerId}/${randomUUID()}.${ext}`;

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

      update.brand_logo_url = blobClient.url;
    } catch (err) {
      console.error("[branding-logo]", err);
      return res.status(500).json({ error: (err as Error).message });
    }
  }

  if (brandName !== undefined) {
    const trimmed = brandName.trim();
    // Empty string clears the field back to the default template name.
    update.brand_name = trimmed || null;
  }

  const { data, error } = await supabaseAdmin
    .from("subscriptions")
    .update(update)
    .eq("owner", caller.ownerId)
    .select("brand_logo_url, brand_name")
    .single();

  if (error) return res.status(500).json({ error: error.message });
  return res.status(200).json(data);
}
