// Share-link management for one scan — GET (list), POST (create), DELETE
// (revoke). Session-only, mirroring src/pages/api/keys.ts and
// src/pages/api/webhooks.ts: minting a public link to a scan report is a
// write to the account, not something an API key should be able to do on
// its own.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { generateShareToken } from "@/lib/reportShares";

const MAX_EXPIRY_DAYS = 365;

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  if (caller.via !== "session") {
    return res.status(403).json({ error: "Share links can only be managed from a logged-in session, not with an API key." });
  }

  const scanId = req.query.id as string;

  const { data: scan } = await supabaseAdmin
    .from("scans")
    .select("id, owner")
    .eq("id", scanId)
    .maybeSingle();

  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (scan.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin
      .from("report_shares")
      .select("id, token, expires_at, revoked_at, view_count, created_at")
      .eq("scan_id", scanId)
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ shares: (data ?? []).map(withShareUrl) });
  }

  if (req.method === "POST") {
    const { expires_in_days: expiresInDays } = req.body as { expires_in_days?: number };

    let expiresAt: string | null = null;
    if (expiresInDays !== undefined) {
      if (typeof expiresInDays !== "number" || expiresInDays <= 0 || expiresInDays > MAX_EXPIRY_DAYS) {
        return res.status(400).json({ error: `expires_in_days must be between 1 and ${MAX_EXPIRY_DAYS}` });
      }
      expiresAt = new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000).toISOString();
    }

    const { data: existing } = await supabaseAdmin
      .from("report_shares")
      .select("id")
      .eq("scan_id", scanId)
      .is("revoked_at", null);

    if ((existing?.length ?? 0) >= 10) {
      return res.status(400).json({ error: "Share link limit reached (10) for this scan. Revoke an unused one first." });
    }

    const token = generateShareToken();
    const { data, error } = await supabaseAdmin
      .from("report_shares")
      .insert({ scan_id: scanId, token, expires_at: expiresAt })
      .select("id, token, expires_at, revoked_at, view_count, created_at")
      .single();

    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json(withShareUrl(data));
  }

  if (req.method === "DELETE") {
    const { id } = req.body as { id?: string };
    if (!id) return res.status(400).json({ error: "id is required" });

    const { error } = await supabaseAdmin
      .from("report_shares")
      .delete()
      .eq("id", id)
      .eq("scan_id", scanId);

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: "Method not allowed" });
}

function withShareUrl<T extends { token: string }>(share: T): T & { share_url: string } {
  const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000";
  return { ...share, share_url: `${siteUrl}/share/${share.token}` };
}
