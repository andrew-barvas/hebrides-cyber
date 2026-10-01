// GET /api/v1/scans/{id}/sbom — CycloneDX 1.5 JSON SBOM export.
// Generates a standards-compliant Software Bill of Materials from the scan's
// dependency manifest findings. Returns 404 if no dependency findings exist.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import type { Finding } from "@/lib/scanners";
import { generateCycloneDxBom } from "@/lib/sbomExport";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const scanId = req.query.id as string;

  const { data: scan } = await supabaseAdmin
    .from("scans")
    .select("id, owner, target_url")
    .eq("id", scanId)
    .maybeSingle();

  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (scan.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  const { data: result } = await supabaseAdmin
    .from("scan_results")
    .select("results")
    .eq("scan_id", scanId)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!result) return res.status(404).json({ error: "No results for this scan yet" });

  const findings = ((result.results as { findings?: Finding[] })?.findings ?? []) as Finding[];
  const depFindings = findings.filter((f) => f.checkId?.startsWith("dependency-manifest."));

  if (depFindings.length === 0) {
    return res.status(404).json({ error: "No dependency findings in this scan — SBOM requires a connected repository with dependency manifests" });
  }

  const bom = generateCycloneDxBom({
    targetUrl: scan.target_url,
    scanId,
    findings: depFindings,
  });

  const filenameSafeHost = scan.target_url.replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]/gi, "-");
  res.setHeader("Content-Type", "application/vnd.cyclonedx+json; version=1.5");
  res.setHeader("Content-Disposition", `attachment; filename="${filenameSafeHost}-sbom.cdx.json"`);
  return res.status(200).json(bom);
}
