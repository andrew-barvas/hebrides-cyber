import { describe, it, expect } from "vitest";
import { buildScanReport } from "./scanReport";
import { buildTriageIndex, type TriageDbRow } from "./findingTriage";
import type { Finding } from "./scanners";

const NOW = new Date("2026-10-01T12:00:00Z");
const scan = { id: "s1", owner: "o1", target_url: "https://Shop.Example/", status: "completed", created_at: "2026-10-01T00:00:00Z" };
const findings: Finding[] = [
  { severity: "high", title: "No CSP", detail: "d", checkId: "headers.csp-absent" },
  { severity: "low", title: "No DMARC", detail: "d", checkId: "dns.dmarc-missing" },
  { severity: "info", title: "Untagged", detail: "d" },
];
const result = { results: { findings }, summary: null, score: 80, created_at: "2026-10-01T00:05:00Z" };

const row = (check_id: string, overrides: Partial<TriageDbRow> = {}): TriageDbRow => ({
  id: check_id, owner: "o1", target_host: "shop.example", check_id, state: "snoozed", reason: "Next sprint",
  expires_at: "2026-10-31T00:00:00.000Z", created_by: "o1", created_at: "2026-09-20T00:00:00Z", updated_at: "2026-09-21T00:00:00Z",
  ...overrides,
});

describe("buildScanReport triage", () => {
  it("gives every finding a triage field (or null) when built with triage — the public API and webhook shape", () => {
    const index = buildTriageIndex([row("headers.csp-absent"), row("dns.dmarc-missing", { expires_at: "2026-09-30T00:00:00Z" })], NOW);
    const report = buildScanReport(scan, result, null, index);
    expect(report.findings.map((f) => f.triage)).toEqual([
      { state: "snoozed", reason: "Next sprint", expires_at: "2026-10-31T00:00:00.000Z", triaged_at: "2026-09-21T00:00:00Z" },
      null,
      null,
    ]);
  });

  // The public share link builds without triage: an owner's reasons stay private.
  it("leaves the field out entirely when built without triage", () => {
    const report = buildScanReport(scan, result, null);
    for (const f of report.findings) expect("triage" in f).toBe(false);
  });
});

describe("buildScanReport fixed findings", () => {
  const previous: Finding[] = [
    { severity: "critical", title: "SQLi", detail: "d", checkId: "sqlmap.sqli:id" },
    { severity: "medium", title: "No HSTS", detail: "d", checkId: "headers.hsts" },
  ];

  it("a passive scan does not report an active-tool finding as fixed (nor fire ticket auto-close for it)", () => {
    const report = buildScanReport(scan, { ...result, results: { findings: [], headers: { status: "checked" } } }, previous);
    expect(report.fixed_findings!.map((f) => f.check_id)).toEqual(["headers.hsts"]);
    expect(report.fixed_finding_count).toBe(1);
  });

  it("a scan whose active tool completed does report it fixed", () => {
    const report = buildScanReport(scan, { ...result, results: { findings: [], extended: { sqlmap: { status: "completed" } } } }, previous);
    expect(report.fixed_findings!.map((f) => f.check_id)).toEqual(["sqlmap.sqli:id", "headers.hsts"]);
  });
});

describe("buildScanReport proof of exploit", () => {
  it("reports proof_of_exploit only on confirmed findings", () => {
    const proven: Finding = { severity: "high", title: "p", detail: "d", checkId: "headers.cors-reflected", metadata: { proofOfExploit: { confirmed: true, evidence: "e", validatedAt: "2026-10-05T00:00:00Z" } } };
    const plain: Finding = { severity: "low", title: "q", detail: "d", checkId: "dns.x" };
    const unvalidated: Finding = { severity: "low", title: "r", detail: "d", checkId: "dns.y", metadata: { proofOfExploit: { confirmed: true, evidence: "e2" } } };
    const report = buildScanReport(scan, { ...result, results: { findings: [proven, plain, unvalidated] } }, null);
    expect(report.findings[0].proof_of_exploit).toEqual({ confirmed: true, evidence: "e", validated_at: "2026-10-05T00:00:00Z" });
    expect(report.findings[1].proof_of_exploit).toBeUndefined();
    expect(report.findings[2].proof_of_exploit?.validated_at).toBeNull();
  });
});
