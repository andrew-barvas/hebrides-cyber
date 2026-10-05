import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { ScanReport } from "./scanReport";

const { sendEmailMock } = vi.hoisted(() => ({ sendEmailMock: vi.fn() }));
vi.mock("./email", async (orig) => ({ ...(await orig<typeof import("./email")>()), sendEmail: sendEmailMock }));

import { sendCriticalAlertEmail } from "./scanAlerts";

function makeSupabase(): SupabaseClient {
  return {
    from: (table: string) => {
      const b: Record<string, unknown> = {};
      for (const m of ["select", "eq"]) b[m] = () => b;
      b.maybeSingle = () =>
        Promise.resolve({ data: table === "subscriptions" ? { status: "active" } : { email: "owner@shop.example" }, error: null });
      return b;
    },
  } as unknown as SupabaseClient;
}

type ReportFinding = ScanReport["findings"][number];
const finding = (overrides: Partial<ReportFinding> = {}): ReportFinding => ({
  check_id: "webapp.cors-reflected", severity: "critical", title: "Reflected CORS origin", detail: "d", remediation: null, status: "new",
  ...overrides,
});

function report(findings: ReportFinding[]): ScanReport {
  return {
    scan_id: "scan-1", target_url: "https://shop.example", status: "completed", created_at: "2026-09-27T00:00:00Z",
    score: 60, new_finding_count: findings.length, findings, fixed_findings: [], critical_paths: [],
  };
}

describe("sendCriticalAlertEmail", () => {
  beforeEach(() => {
    sendEmailMock.mockReset().mockResolvedValue({ ok: true });
  });

  it("emails about a new critical finding", async () => {
    await sendCriticalAlertEmail(makeSupabase(), "o1", report([finding()]));
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    expect(sendEmailMock.mock.calls[0][0].subject).toBe("New critical finding on shop.example");
  });

  // A finding that flapped back reports as "new", but the owner already
  // decided about it — e.g. marked it a false positive.
  it("stays quiet when every new critical/high finding is triaged", async () => {
    const triage = { state: "false_positive" as const, reason: "WAF block page, not the app", expires_at: null, triaged_at: "2026-09-20T00:00:00Z" };
    await sendCriticalAlertEmail(makeSupabase(), "o1", report([finding({ triage }), finding({ check_id: "x.y", severity: "high", triage })]));
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("counts only the untriaged findings", async () => {
    const triage = { state: "snoozed" as const, reason: "Fix scheduled for next sprint", expires_at: "2026-10-30T00:00:00Z", triaged_at: "2026-09-20T00:00:00Z" };
    await sendCriticalAlertEmail(
      makeSupabase(),
      "o1",
      report([finding({ triage }), finding({ check_id: "tls.expired", severity: "high", title: "Certificate expired", triage: null })])
    );
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    const { subject, html } = sendEmailMock.mock.calls[0][0];
    expect(subject).toBe("New high-severity finding on shop.example");
    expect(html).toContain("Certificate expired");
    expect(html).not.toContain("Reflected CORS origin");
  });
});
