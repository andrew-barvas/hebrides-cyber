import { describe, it, expect } from "vitest";
import type { Finding } from "./scanners";
import { buildDefectDojoReport } from "./defectDojo";

// The keys DefectDojo's generic JSON parser accepts on a finding (it rejects any other).
const ALLOWED = new Set([
  "title", "severity", "description", "mitigation", "impact", "references", "cwe", "vulnerability_ids", "cvssv3", "cvssv3_score",
  "unique_id_from_tool", "vuln_id_from_tool", "active", "verified", "false_p", "risk_accepted", "out_of_scope", "known_exploited",
  "epss_score", "dynamic_finding", "static_finding", "endpoints", "tags", "file_path", "line", "component_name", "component_version",
]);

const base: Finding = { checkId: "headers.csp-absent", severity: "medium", title: "No Content-Security-Policy header", detail: "Scripts may load from anywhere.", remediation: "Add a CSP." };

describe("buildDefectDojoReport", () => {
  it("emits only keys DefectDojo accepts, with its required three always set", () => {
    const report = buildDefectDojoReport({ targetUrl: "https://example.com", scanId: "s1", findings: [base, { ...base, checkId: undefined, detail: "" }] });
    expect(report.type).toBe("Hebrides Cyber");
    for (const f of report.findings) {
      for (const key of Object.keys(f)) expect(ALLOWED.has(key), key).toBe(true);
      expect(f.title && f.severity && f.description).toBeTruthy();
    }
  });

  it("maps severity, CVEs, CVSS 3 vectors, KEV, EPSS, CWE and a stable unique id", () => {
    const [f] = buildDefectDojoReport({
      targetUrl: "https://example.com",
      scanId: "s1",
      findings: [{
        ...base,
        checkId: "network.service-cve:22/tcp",
        severity: "critical",
        cveIds: ["CVE-2024-6387"],
        cvssScore: 8.1,
        cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        threatIntel: { knownExploited: true, epss: 0.42 },
        cwe: ["CWE-362"],
      }],
    }).findings;
    expect(f).toMatchObject({
      severity: "Critical",
      vulnerability_ids: ["CVE-2024-6387"],
      cvssv3: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
      cvssv3_score: 8.1,
      known_exploited: true,
      epss_score: 0.42,
      cwe: 362,
      unique_id_from_tool: "network.service-cve:22/tcp",
      vuln_id_from_tool: "network.service-cve",
      endpoints: ["https://example.com"],
      mitigation: "Add a CSP.",
    });
  });

  it("drops a non-3.x CVSS vector, which DefectDojo would reject", () => {
    const [f] = buildDefectDojoReport({ targetUrl: "https://e.com", scanId: "s", findings: [{ ...base, cvssVector: "CVSS:4.0/AV:N" }] }).findings;
    expect(f.cvssv3).toBeUndefined();
  });

  it("carries triage: false positives and accepted risk are inactive, snoozed stays active", () => {
    const t = (state: "false_positive" | "accepted_risk" | "snoozed") => ({ state, reason: "why", expiresAt: null, triagedAt: "2026-11-01" });
    const fs = buildDefectDojoReport({ targetUrl: "https://e.com", scanId: "s", findings: [{ ...base, triage: t("false_positive") }, { ...base, triage: t("accepted_risk") }, { ...base, triage: t("snoozed") }] }).findings;
    expect(fs.map((f) => [f.active, f.false_p, f.risk_accepted])).toEqual([[false, true, false], [false, false, true], [true, false, false]]);
    expect(fs[0].description).toContain("Owner's triage note: why");
  });
});
