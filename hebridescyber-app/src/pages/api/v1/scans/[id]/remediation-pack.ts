// GET /api/v1/scans/{id}/remediation-pack — every actionable finding from the
// scan's latest result, grouped by category rather than a flat list, as a
// plain Markdown download. Sits beside compliance.ts and export.ts with the
// same owner-only access and API-key support, but needs no connected repo:
// unlike generate-fix-pr.ts (which opens a PR with the same fix content via
// buildRemediationMarkdown), this is available to every scan.
import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/apiAuth";
import { guardV1, setV1Headers } from "@/lib/v1Guard";
import type { Finding } from "@/lib/scanners";
import { buildRemediationPack } from "@/lib/remediation";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    setV1Headers(res);
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed", code: "method_not_allowed" });
  }

  const caller = await guardV1(req, res, "scans:read");
  if (!caller) return;

  const scanId = req.query.id as string;
  const { data: scan } = await supabaseAdmin.from("scans").select("id, owner, target_url").eq("id", scanId).maybeSingle();
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (scan.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  const { data: result } = await supabaseAdmin
    .from("scan_results")
    .select("score, results")
    .eq("scan_id", scanId)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (!result) return res.status(404).json({ error: "No results for this scan yet" });

  const findings = ((result.results as { findings?: Finding[] })?.findings ?? []) as Finding[];
  const markdown = buildRemediationPack(scan.target_url, findings, typeof result.score === "number" ? result.score : null);

  const filenameSafeHost = scan.target_url.replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]/gi, "-");
  res.setHeader("Content-Type", "text/markdown; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${filenameSafeHost}-remediation-pack.md"`);
  return res.status(200).send(markdown);
}
