// GET /api/v1/scans/{id}/export?format=csv|json|sarif — bulk finding export for a
// single scan. `sarif` is the SARIF 2.1.0 log GitHub code scanning reads (see
// lib/sarif.ts for how findings map to it). Sits alongside GET /api/v1/scans/{id} (the full report with
// New/Fixed diffing) rather than replacing it: this route is deliberately
// flat and tabular — one row per finding, no diff status, no nested
// objects beyond a couple of joined string columns — for someone piping
// results into a spreadsheet or their own ticketing/reporting pipeline,
// not rendering a UI from it.
//
// Triage (accept risk / false positive / snooze, findingTriage.ts) is as of
// export time, not scan time: the owner's current decision for each finding,
// as triage_* columns (CSV) or a `triage` object, null when untriaged (JSON).
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import type { Finding } from "@/lib/scanners";
import { csvCell } from "@/lib/csv";
import { evidenceSummary, readEvidence } from "@/lib/findingEvidence";
import { applyTriage, loadTriageIndexForTarget, type FindingTriage } from "@/lib/findingTriage";
import { buildSarif } from "@/lib/sarif";

function findingsToCsv(findings: Array<Finding & { triage: FindingTriage | null }>): string {
  const header = [
    "severity", "title", "detail", "check_id", "cve_ids", "cvss_score", "cvss_vector", "known_exploited", "epss", "compliance_refs",
    "triage_state", "triage_reason", "triage_expires_at", "corroborated_by", "evidence",
  ];
  const rows = findings.map((f) => [
    f.severity,
    f.title,
    f.detail,
    f.checkId ?? "",
    (f.cveIds ?? []).join("; "),
    f.cvssScore != null ? String(f.cvssScore) : "",
    f.cvssVector ?? "",
    // Blank = not looked up, which is different from "false".
    f.threatIntel ? String(f.threatIntel.knownExploited) : "",
    f.threatIntel?.epss != null ? String(f.threatIntel.epss) : "",
    (f.complianceRefs ?? []).map((r) => `${r.framework}: ${r.control}`).join("; "),
    f.triage?.state ?? "",
    f.triage?.reason ?? "",
    f.triage?.expiresAt ?? "",
    // "nuclei: <title>; ZAP: <title>" — other tools that reported the same issue.
    (f.corroboratedBy ?? []).map((c) => `${c.tool}: ${c.title}`).join("; "),
    // One line, "GET <url> → 200 (type); matched: …", redacted at capture.
    evidenceSummary(readEvidence(f.evidence)),
  ]);
  return [header, ...rows].map((row) => row.map((cell) => csvCell(String(cell))).join(",")).join("\r\n");
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const scanId = req.query.id as string;
  const requested = (req.query.format as string | undefined)?.toLowerCase();
  const format = requested === "json" || requested === "sarif" ? requested : "csv";

  const { data: scan } = await supabaseAdmin.from("scans").select("id, owner, target_url").eq("id", scanId).maybeSingle();
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (scan.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  const { data: result } = await supabaseAdmin.from("scan_results").select("results").eq("scan_id", scanId).order("created_at", { ascending: false }).limit(1).maybeSingle();
  if (!result) return res.status(404).json({ error: "No results for this scan yet" });

  const stored = ((result.results as { findings?: Finding[] })?.findings ?? []) as Finding[];
  const triage = await loadTriageIndexForTarget(supabaseAdmin, scan.owner, scan.target_url);
  const findings = applyTriage(stored, triage.host ?? "", triage.index);
  const filenameSafeHost = scan.target_url.replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]/gi, "-");

  if (format === "json") {
    res.setHeader("Content-Disposition", `attachment; filename="${filenameSafeHost}-findings.json"`);
    return res.status(200).json({ scan_id: scanId, target_url: scan.target_url, findings });
  }

  if (format === "sarif") {
    const log = buildSarif({ targetUrl: scan.target_url, scanId, findings, siteUrl: process.env.NEXT_PUBLIC_SITE_URL });
    res.setHeader("Content-Type", "application/sarif+json; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filenameSafeHost}-findings.sarif"`);
    return res.status(200).send(JSON.stringify(log));
  }

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${filenameSafeHost}-findings.csv"`);
  return res.status(200).send(findingsToCsv(findings));
}
