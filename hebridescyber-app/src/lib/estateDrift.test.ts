import { describe, it, expect } from "vitest";
import { buildEstateDrift, parseDriftWindow, type DriftLifecycleRow } from "./estateDrift";
import { buildTriageIndex, EMPTY_TRIAGE_INDEX } from "./findingTriage";

const NOW = new Date("2026-11-14T12:00:00Z");
const SINCE = new Date("2026-10-15T12:00:00Z");
const row = (o: Partial<DriftLifecycleRow>): DriftLifecycleRow => ({
  target_host: "a.example.com",
  check_id: "headers.hsts-missing",
  severity: "medium",
  title: "HSTS missing",
  first_seen_at: "2026-11-01T00:00:00Z",
  resolved_at: null,
  ...o,
});

describe("buildEstateDrift", () => {
  it("counts opened, fixed and open-now by severity across the estate", () => {
    const drift = buildEstateDrift({
      lifecycle: [
        row({}),
        row({ target_host: "b.example.com", severity: "critical", check_id: "network.service-cve:22/tcp", title: "OpenSSH CVE" }),
        row({ check_id: "tls.weak", severity: "high", first_seen_at: "2026-09-01T00:00:00Z", resolved_at: "2026-11-10T00:00:00Z" }),
        row({ check_id: "old.open", severity: "low", first_seen_at: "2026-01-01T00:00:00Z" }),
        row({ check_id: "info.only", severity: "info" }),
      ],
      assets: [
        { hostname: "New.example.com", first_seen_at: "2026-11-02T00:00:00Z" },
        { hostname: "old.example.com", first_seen_at: "2026-01-02T00:00:00Z" },
      ],
      triage: EMPTY_TRIAGE_INDEX,
      since: SINCE,
      until: NOW,
    });
    expect(drift.opened).toEqual({ critical: 1, high: 0, medium: 1, low: 0, total: 2 });
    expect(drift.fixed).toEqual({ critical: 0, high: 1, medium: 0, low: 0, total: 1 });
    expect(drift.openNow).toEqual({ critical: 1, high: 0, medium: 1, low: 1, total: 3 });
    expect(drift.newHosts).toEqual(["new.example.com"]);
    expect(drift.hosts).toEqual([
      { host: "a.example.com", opened: 1, fixed: 1 },
      { host: "b.example.com", opened: 1, fixed: 0 },
    ]);
    expect(drift.notableOpened.map((n) => n.checkId)).toEqual(["network.service-cve:22/tcp"]);
  });

  it("de-duplicates a finding returned by both the open and resolved queries", () => {
    const r = row({});
    expect(buildEstateDrift({ lifecycle: [r, r], assets: [], triage: EMPTY_TRIAGE_INDEX, since: SINCE, until: NOW }).opened.total).toBe(1);
  });

  it("leaves active false positives out, but still counts accepted risk", () => {
    const triage = buildTriageIndex(
      [
        { target_host: "a.example.com", check_id: "headers.hsts-missing", state: "false_positive", reason: "", expires_at: null, updated_at: "2026-11-02T00:00:00Z" },
        { target_host: "a.example.com", check_id: "dns.dmarc", state: "accepted_risk", reason: "", expires_at: null, updated_at: "2026-11-02T00:00:00Z" },
      ] as never,
      NOW
    );
    const drift = buildEstateDrift({ lifecycle: [row({}), row({ check_id: "dns.dmarc" })], assets: [], triage, since: SINCE, until: NOW });
    expect(drift.opened.total).toBe(1);
    expect(drift.openNow.total).toBe(1);
  });
});

describe("parseDriftWindow", () => {
  it("accepts 7, 30 and 90 days and defaults to 30", () => {
    expect(parseDriftWindow("7")).toBe(7);
    expect(parseDriftWindow(["90"])).toBe(90);
    expect(parseDriftWindow("365")).toBe(30);
    expect(parseDriftWindow(undefined)).toBe(30);
  });
});
