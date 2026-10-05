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
