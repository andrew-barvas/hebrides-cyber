// GET /api/v1/scans/{id}/sbom — CycloneDX 1.5 JSON SBOM export.
// Built from the dependency inventory dependencyManifest.ts stores with the
// scan (every package, with scope, graph and linked vulnerabilities). Scans
// stored before that inventory existed fall back to their dependency
// findings. 404 only when the scan has no dependency data at all.
import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/apiAuth";
import { guardV1, setV1Headers } from "@/lib/v1Guard";
import type { Finding } from "@/lib/scanners";
import { collectVexSignals, generateCycloneDxBom, generateCycloneDxBomFromInventory, isDependencyInventory } from "@/lib/sbomExport";
import { loadTriageIndexForTarget } from "@/lib/findingTriage";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    setV1Headers(res);
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed", code: "method_not_allowed" });
  }

  const caller = await guardV1(req, res, "scans:read");
  if (!caller) return;

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

  const results = (result.results ?? {}) as { findings?: Finding[]; extended?: { dependencyManifest?: { inventory?: unknown } } };
  const inventory = results.extended?.dependencyManifest?.inventory;

  let bom;
  if (isDependencyInventory(inventory)) {
    // VEX exploitability statements per vulnerability, from the scan's own
    // threat-intel-enriched findings (KEV/EPSS) plus any false-positive triage
    // the owner recorded. Triage read is best-effort — degrades to "nothing
    // triaged" on any failure (loadTriageIndexForTarget never throws), so the
    // SBOM still serialises with KEV/EPSS signals even if triage is down.
    const { host, index } = await loadTriageIndexForTarget(supabaseAdmin, scan.owner, scan.target_url);
    const vex = collectVexSignals(results.findings, (checkId) => index.get(host ?? "", checkId)?.state === "false_positive");
    bom = generateCycloneDxBomFromInventory({ targetUrl: scan.target_url, scanId, inventory, vex });
  } else {
    const depFindings = (results.findings ?? []).filter((f) => f.checkId?.startsWith("dependency-manifest."));
    if (depFindings.length === 0) {
      return res.status(404).json({ error: "No dependency data in this scan — SBOM requires a connected repository with a lockfile or dependency manifest" });
    }
    bom = generateCycloneDxBom({ targetUrl: scan.target_url, scanId, findings: depFindings });
  }

  const filenameSafeHost = scan.target_url.replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]/gi, "-");
  res.setHeader("Content-Type", "application/vnd.cyclonedx+json; version=1.5");
  res.setHeader("Content-Disposition", `attachment; filename="${filenameSafeHost}-sbom.cdx.json"`);
  return res.status(200).json(bom);
}
