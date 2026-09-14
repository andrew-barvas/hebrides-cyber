// GET /api/v1/scans/{id}/export?format=csv|json — bulk finding export for a
// single scan. Sits alongside GET /api/v1/scans/{id} (the full report with
// New/Fixed diffing) rather than replacing it: this route is deliberately
// flat and tabular — one row per finding, no diff status, no nested
// objects beyond a couple of joined string columns — for someone piping
// results into a spreadsheet or their own ticketing/reporting pipeline,
// not rendering a UI from it.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import type { Finding } from "@/lib/scanners";

function csvEscape(value: string): string {
  if (/[",\n]/.test(value)) return `"${value.replace(/"/g, '""')}"`;
  return value;
}

function findingsToCsv(findings: Finding[]): string {
  const header = ["severity", "title", "detail", "check_id", "cve_ids", "cvss_score", "cvss_vector", "compliance_refs"];
  const rows = findings.map((f) => [
    f.severity,
    f.title,
    f.detail,
    f.checkId ?? "",
    (f.cveIds ?? []).join("; "),
    f.cvssScore != null ? String(f.cvssScore) : "",
    f.cvssVector ?? "",
    (f.complianceRefs ?? []).map((r) => `${r.framework}: ${r.control}`).join("; "),
  ]);
  return [header, ...rows].map((row) => row.map((cell) => csvEscape(String(cell))).join(",")).join("\r\n");
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const scanId = req.query.id as string;
  const format = (req.query.format as string | undefined)?.toLowerCase() === "json" ? "json" : "csv";

  const { data: scan } = await supabaseAdmin.from("scans").select("id, owner, target_url").eq("id", scanId).maybeSingle();
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (scan.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  const { data: result } = await supabaseAdmin.from("scan_results").select("results").eq("scan_id", scanId).maybeSingle();
  if (!result) return res.status(404).json({ error: "No results for this scan yet" });

  const findings = ((result.results as { findings?: Finding[] })?.findings ?? []) as Finding[];
  const filenameSafeHost = scan.target_url.replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]/gi, "-");

  if (format === "json") {
    res.setHeader("Content-Disposition", `attachment; filename="${filenameSafeHost}-findings.json"`);
    return res.status(200).json({ scan_id: scanId, target_url: scan.target_url, findings });
  }

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${filenameSafeHost}-findings.csv"`);
  return res.status(200).send(findingsToCsv(findings));
}
