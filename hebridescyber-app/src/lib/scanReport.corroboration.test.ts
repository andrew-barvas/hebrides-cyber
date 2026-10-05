import { describe, it, expect } from "vitest";
import { buildScanReport } from "./scanReport";
import type { Finding } from "./scanners";

const scan = { id: "s1", owner: "o1", target_url: "https://shop.example/", status: "completed", created_at: "2026-10-01T00:00:00Z" };
const wrap = (findings: Finding[]) => ({ results: { findings }, summary: null, score: 80, created_at: "2026-10-01T00:05:00Z" });

describe("buildScanReport corroboration", () => {
  it("exposes corroborated_by in snake case, and omits it when nothing corroborated", () => {
    const report = buildScanReport(
      scan,
      wrap([
        { severity: "medium", title: "HSTS", detail: "d", checkId: "tls.hsts-missing", corroboratedBy: [{ tool: "ZAP", checkId: "zap.alert:HSTS", title: "[ZAP] HSTS" }] },
        { severity: "low", title: "Other", detail: "d", checkId: "dns.dmarc-missing" },
        { severity: "low", title: "Empty", detail: "d", checkId: "dns.spf-missing", corroboratedBy: [] },
      ]),
      null
    );
    expect(report.findings[0].corroborated_by).toEqual([{ tool: "ZAP", check_id: "zap.alert:HSTS", title: "[ZAP] HSTS" }]);
    expect(report.findings[1].corroborated_by).toBeUndefined();
    expect(report.findings[2].corroborated_by).toBeUndefined();
  });

  it("does not report a previous duplicate as fixed when the canonical now carries it", () => {
    const previous = [
      { severity: "medium", title: "HSTS", detail: "d", checkId: "tls.hsts-missing" },
      { severity: "low", title: "ZAP HSTS", detail: "d", checkId: "zap.alert:HSTS" },
    ] as Finding[];
    const current: Finding[] = [
      { severity: "medium", title: "HSTS", detail: "d", checkId: "tls.hsts-missing", corroboratedBy: [{ tool: "ZAP", checkId: "zap.alert:HSTS", title: "z" }] },
    ];
    const report = buildScanReport(scan, wrap(current), previous);
    expect(report.fixed_finding_count).toBe(0);
    expect(report.new_finding_count).toBe(0);
  });
});
