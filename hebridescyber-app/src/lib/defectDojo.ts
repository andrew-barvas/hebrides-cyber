// DefectDojo's Generic Findings Import (JSON), so a customer who already runs
// DefectDojo can load a scan's findings into it: GET
// /api/v1/scans/{id}/export?format=defectdojo, then import the file as
// "Generic Findings Import".
//
// Field names follow DefectDojo's own parser (dojo/tools/generic/json_parser.py,
// read 2026-11-14). It rejects any key it doesn't know, and requires title,
// severity and description, so every finding carries those three and nothing
// outside its allowed set.
//
//   - unique_id_from_tool is the finding's stable checkId, the key our own
//     findingsDiff matches on, so re-imports line up with earlier ones.
//   - Triage carries over: false positives and accepted risk become DefectDojo's
//     false_p and risk_accepted, and are marked inactive. Snoozed findings stay
//     active, since a snooze is a reminder, not a decision.
//   - Nothing here changes a finding's severity or text.
import type { Finding } from "./scanners";
import type { FindingTriage } from "./findingTriage";
import { evidenceSummary, readEvidence } from "./findingEvidence";
import { getAttackRefs, getCweIds } from "./scanners/attackMap";

const SEVERITY: Record<Finding["severity"], string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const TITLE_MAX = 511;

export type DefectDojoFinding = {
  title: string;
  severity: string;
  description: string;
  mitigation?: string;
  references?: string;
  cwe?: number;
  vulnerability_ids?: string[];
  cvssv3?: string;
  cvssv3_score?: number;
  unique_id_from_tool?: string;
  vuln_id_from_tool?: string;
  active: boolean;
  false_p: boolean;
  risk_accepted: boolean;
  known_exploited?: boolean;
  epss_score?: number;
  dynamic_finding: boolean;
  endpoints: string[];
  tags: string[];
};

export type DefectDojoReport = { type: string; name: string; description: string; findings: DefectDojoFinding[] };

export function buildDefectDojoReport(input: {
  targetUrl: string;
  scanId: string;
  findings: Array<Finding & { triage?: FindingTriage | null }>;
}): DefectDojoReport {
  return {
    type: "Hebrides Cyber",
    name: `Hebrides Cyber scan of ${input.targetUrl}`,
    description: `Scan ${input.scanId} of ${input.targetUrl}, exported from Hebrides Cyber.`,
    findings: input.findings.map((f) => toDefectDojoFinding(f, input.targetUrl)),
  };
}

function toDefectDojoFinding(f: Finding & { triage?: FindingTriage | null }, targetUrl: string): DefectDojoFinding {
  const evidence = evidenceSummary(readEvidence(f.evidence));
  const attack = (f.attackRefs ?? getAttackRefs(f.checkId)).map((r) => `MITRE ATT&CK ${r.id} ${r.name}`);
  const cwe = (f.cwe ?? getCweIds(f.checkId)).map((c) => Number(String(c).replace(/^CWE-/i, ""))).find((n) => Number.isInteger(n) && n > 0);
  const falsePositive = f.triage?.state === "false_positive";
  const accepted = f.triage?.state === "accepted_risk";

  const out: DefectDojoFinding = {
    title: f.title.length > TITLE_MAX ? `${f.title.slice(0, TITLE_MAX - 1)}…` : f.title,
    severity: SEVERITY[f.severity] ?? "Info",
    description: [f.detail, evidence ? `Evidence: ${evidence}` : "", f.triage?.reason ? `Owner's triage note: ${f.triage.reason}` : ""].filter(Boolean).join("\n\n") || f.title,
    active: !falsePositive && !accepted,
    false_p: falsePositive,
    risk_accepted: accepted,
    dynamic_finding: true,
    endpoints: [targetUrl],
    tags: ["hebrides-cyber", ...(f.checkId ? [f.checkId.split(".")[0]] : [])],
  };
  if (f.remediation) out.mitigation = f.remediation;
  if (attack.length > 0) out.references = attack.join("\n");
  if (cwe !== undefined) out.cwe = cwe;
  if (f.cveIds && f.cveIds.length > 0) out.vulnerability_ids = f.cveIds;
  // DefectDojo drops a vector that isn't CVSS 3.x, so only send those.
  if (f.cvssVector && /^CVSS:3\.[01]\//.test(f.cvssVector)) out.cvssv3 = f.cvssVector;
  if (typeof f.cvssScore === "number") out.cvssv3_score = f.cvssScore;
  if (f.checkId) {
    out.unique_id_from_tool = f.checkId;
    out.vuln_id_from_tool = f.checkId.split(":")[0];
  }
  if (f.threatIntel) out.known_exploited = f.threatIntel.knownExploited;
  if (typeof f.threatIntel?.epss === "number") out.epss_score = f.threatIntel.epss;
  return out;
}
