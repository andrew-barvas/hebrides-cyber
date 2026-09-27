// GET /api/v1/scans/{id}/compliance?format=md|csv|json — the scan's findings
// mapped to seven frameworks' controls, as a document a customer can hand to
// an auditor. Sits beside export.ts (flat findings) and sbom.ts, with the same
// owner-only access and API-key support. Every format carries
// COMPLIANCE_REPORT_DISCLAIMER — see complianceReport.ts for why the wording
// is "no issues found", never "pass".
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import type { Finding } from "@/lib/scanners";
import {
  formatComplianceReportCsv,
  formatComplianceReportMarkdown,
  generateComplianceReport,
  toComplianceExportJson,
  withComplianceRefs,
} from "@/lib/complianceReport";

const FORMATS = ["md", "csv", "json"] as const;
type Format = (typeof FORMATS)[number];

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const requested = ((req.query.format as string | undefined) ?? "md").toLowerCase();
  if (!(FORMATS as readonly string[]).includes(requested)) {
    return res.status(400).json({ error: `format must be one of: ${FORMATS.join(", ")}` });
  }
  const format = requested as Format;

  const scanId = req.query.id as string;
  const { data: scan } = await supabaseAdmin.from("scans").select("id, owner, target_url").eq("id", scanId).maybeSingle();
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (scan.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  const { data: result } = await supabaseAdmin.from("scan_results").select("results").eq("scan_id", scanId).maybeSingle();
  if (!result) return res.status(404).json({ error: "No results for this scan yet" });

  const findings = withComplianceRefs(((result.results as { findings?: Finding[] })?.findings ?? []) as Finding[]);
  const report = generateComplianceReport(scan.target_url, findings);
  const filenameSafeHost = scan.target_url.replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]/gi, "-");
  res.setHeader("Content-Disposition", `attachment; filename="${filenameSafeHost}-compliance.${format}"`);

  if (format === "json") return res.status(200).json(toComplianceExportJson(report));
  if (format === "csv") {
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    return res.status(200).send(formatComplianceReportCsv(report));
  }
  res.setHeader("Content-Type", "text/markdown; charset=utf-8");
  return res.status(200).send(formatComplianceReportMarkdown(report));
}
