import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { parseBody } from "@/lib/validate";

const bodySchema = z.object({
  targetUrl: z.string().url(),
  scanWindowStart: z.string().regex(/^\d{2}:\d{2}$/).nullable(),
  scanWindowEnd: z.string().regex(/^\d{2}:\d{2}$/).nullable(),
  scanWindowTz: z.string().default("UTC"),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const body = parseBody(bodySchema, req.body, res);
  if (!body) return;

  const { error } = await supabaseAdmin
    .from("monitored_targets")
    .update({
      scan_window_start: body.scanWindowStart,
      scan_window_end: body.scanWindowEnd,
      scan_window_tz: body.scanWindowTz,
    })
    .eq("owner", caller.ownerId)
    .eq("target_url", body.targetUrl);

  if (error) return res.status(500).json({ error: error.message });

  return res.status(200).json({ ok: true });
}
