// GET /api/profile-badge/<slug> — the embeddable SVG badge for a published security
// profile (src/lib/securityProfile.ts). Public, cached for an hour.
// next.config.mjs lets this path be embedded on other sites
// (Cross-Origin-Resource-Policy: cross-origin); everything else stays same-origin.
// An unknown or unpublished slug gets a 404, never a placeholder grade.
import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/apiAuth";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";
import { ratingFor } from "@/lib/executiveReport";
import { buildPublicProfile, loadLatestScanForProfile, loadProfileBySlug, renderBadgeSvg } from "@/lib/securityProfile";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  // Public: generous per-IP limit (badges sit on busy pages, and the response is cached for an hour).
  const limit = await checkRateLimit(getClientIp(req), "profile-badge", { max: 300, windowSeconds: 60 });
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many requests" });
  }
  const slug = String(req.query.slug ?? "").replace(/\.svg$/, "");
  const row = await loadProfileBySlug(supabaseAdmin, slug);
  if (!row) return res.status(404).json({ error: "Not found" });
  const profile = buildPublicProfile({ host: row.target_host, scan: await loadLatestScanForProfile(supabaseAdmin, row) });
  res.setHeader("Content-Type", "image/svg+xml; charset=utf-8");
  res.setHeader("Cache-Control", "public, max-age=3600");
  return res.status(200).send(renderBadgeSvg(profile, ratingFor(profile.score)));
}
