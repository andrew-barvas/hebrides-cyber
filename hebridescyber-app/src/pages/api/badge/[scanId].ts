import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/supabaseAdmin";

// Embeddable Security Score badge: <img src="/api/badge/<scanId>.svg">.
// Uses the service role key deliberately — this is a *public* badge by
// design (that's the point, it's meant to be embedded on a customer's own
// site as a trust signal), so it intentionally bypasses the RLS that
// normally restricts scan_results to their owner. Only the score and
// target hostname are exposed, never the raw findings.

function colorForScore(score: number): string {
  if (score >= 90) return "#16a34a"; // green
  if (score >= 70) return "#7FD3C7"; // seafoam
  if (score >= 50) return "#f59e0b"; // amber
  return "#dc2626"; // red
}

function renderBadgeSvg(score: number | null): string {
  const label = score === null ? "no data" : `${score}/100`;
  const color = score === null ? "#94a3b8" : colorForScore(score);
  const labelWidth = 70;
  const valueWidth = 54;
  const totalWidth = labelWidth + valueWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="Security Score: ${label}">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${totalWidth}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#0B3D5B"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,sans-serif" font-size="11">
    <text x="${labelWidth / 2}" y="14">Security Score</text>
    <text x="${labelWidth + valueWidth / 2}" y="14">${label}</text>
  </g>
</svg>`;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const scanIdParam = req.query.scanId;
  const scanId = (Array.isArray(scanIdParam) ? scanIdParam[0] : scanIdParam)?.replace(/\.svg$/, "");

  let score: number | null = null;
  if (scanId) {
    // This is embedded as a live <img> on customer sites, so any failure —
    // including supabaseAdmin's lazy client failing to construct — must fall
    // through to the "no data" badge below, never a broken-image 500.
    try {
      const { data } = await supabaseAdmin.from("scan_results").select("score").eq("scan_id", scanId).maybeSingle();
      score = data?.score ?? null;
    } catch {
      score = null;
    }
  }

  res.setHeader("Content-Type", "image/svg+xml");
  // Short cache — scores change weekly at most, but shouldn't feel "stuck"
  // if a customer just re-ran a scan wanting the badge to update.
  res.setHeader("Cache-Control", "public, max-age=300");
  res.status(200).send(renderBadgeSvg(score));
}
