// GET/POST /api/account/dmarc-ingest-token — manage the per-owner DMARC
// aggregate-report ingest token (E-66). GET returns the current token (if any)
// and the ingest URL to point a mail/forwarding provider at; POST generates or
// rotates it. Session-only (not an API key — this is account configuration).
import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "node:crypto";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { isMissingSchemaError } from "@/lib/dbErrors";

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";

function ingestUrl(token: string): string {
  return `${SITE_URL}/api/dmarc/ingest?token=${token}`;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "The DMARC ingest token can only be managed from a logged-in session." });
  }

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin
      .from("dmarc_ingest_tokens")
      .select("token")
      .eq("owner", caller.ownerId)
      .maybeSingle();
    if (error && !isMissingSchemaError(error)) return res.status(500).json({ error: error.message });
    if (error) return res.status(200).json({ available: false, token: null });
    return res.status(200).json({
      available: true,
      token: data?.token ?? null,
      ingestUrl: data?.token ? ingestUrl(data.token) : null,
    });
  }

  // POST — generate or rotate.
  const token = `dmarc_${randomBytes(24).toString("base64url")}`;
  const { error } = await supabaseAdmin
    .from("dmarc_ingest_tokens")
    .upsert({ owner: caller.ownerId, token }, { onConflict: "owner" });
  if (error) {
    if (isMissingSchemaError(error)) {
      return res.status(503).json({ error: "DMARC report processing isn't available yet (migration 060 pending)." });
    }
    return res.status(500).json({ error: error.message });
  }
  return res.status(200).json({ token, ingestUrl: ingestUrl(token) });
}
